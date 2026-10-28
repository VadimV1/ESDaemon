#!/bin/bash
# jqcheck-tests.sh — bin/jqcheck.sh, the check install.sh and reload.sh make before they change anything: can this Mac's
# jq run the filter, src/scope.jq, with the config the daemon will run? The jq is a parameter. The tests' own jq (on CI's
# Macs, Apple's /usr/bin/jq) must pass, in every format and with rules that drop every sample event. A jq that rejects
# the program, one that prints nothing, a missing one, one that reads its input even for --version, and a run on which
# records cannot be built or rules cannot be evaluated must stop it, on stderr, naming the jq and its version. Last,
# install.sh and reload.sh run from copies on /usr/bin/jq, as far as their first change: they stop at the check when it
# fails (install.sh naming a migrated cfg's draft), and get past it when it passes; reload.sh checks the installed
# scope.jq, the one the filter runs.
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
# shellcheck source=bin/jqcheck.sh
. "$ROOT/bin/jqcheck.sh"
JQ="$(command -v jq)"
DEF="$(bash "$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json)"
J(){ printf '%b' "$1" > "$T/c.cfg"; bash "$ROOT/bin/cfg.sh" "$T/c.cfg" json; }   # cfg.sh's output for this cfg text
chk(){ out="$(esd_jq_check "$ROOT/src/scope.jq" "$1" install.sh "${2:-$JQ}" 2>&1)"; rc=$?; }
has(){ grep -qF -- "$1" <<< "$out"; }

echo "-- the sample: with the default config every event becomes a record, the second one from the pid cache"
REC="$(_esd_jq_sample | jq -n -cR --argjson cfg "$DEF" -f "$ROOT/src/scope.jq")"
ok "3 records and the drop marker"                         '[ "$(grep -vc eslogger_scoped_gap <<< "$REC")" = 3 ] && [ "$(grep -c "\"eslogger_scoped_gap\":1" <<< "$REC")" = 1 ]'
ok "the program the shell starts gets the shell's command line" '[ "$(jq -r "select(.Image == \"/usr/bin/true\") | .ParentCommandLine" <<< "$REC")" = -zsh ]'

echo "-- a jq that runs the filter: passes, prints nothing"
chk "$DEF"
ok "the default config"                                    '[ $rc = 0 ] && [ -z "$out" ]'
for f in sysmon sysmon+extras slim raw; do chk "$(J "[settings]\nformat = $f\n")"
  ok "format = $f"                                         '[ $rc = 0 ] && [ -z "$out" ]'
done
chk "$(J "[include]\nImage is /nowhere\n")"
ok "rules that drop every sample event: the drop marker is enough" '[ $rc = 0 ] && [ -z "$out" ]'

echo "-- a jq that cannot run it: stops (1), on stderr, naming the jq, its version and the macOS it supports"
cat > "$T/jq-old" <<'S'
#!/bin/bash
# what an older jq prints for a builtin it does not have
[ "${1:-}" = --version ] && { echo jq-1.6; exit 0; }
echo 'jq: error: pick/1 is not defined at <top-level>, line 12:' >&2; echo 'jq: 1 compile error' >&2; exit 3
S
printf '#!/bin/bash\n[ "${1:-}" = --version ] && { echo jq-1.7.1; exit 0; }\ncat > /dev/null\n' > "$T/jq-mute"
chmod +x "$T/jq-old" "$T/jq-mute"
chk "$DEF" "$T/jq-old"
ok "rejects the program: stops"                            '[ $rc = 1 ] && [ -z "$(esd_jq_check "$ROOT/src/scope.jq" "$DEF" install.sh "$T/jq-old" 2>/dev/null)" ]'
ok "says it stopped and changed nothing"                   'has "install.sh: stopped, nothing was changed."'
ok "names the jq and its version, and the program"         'has "$T/jq-old (jq-1.6) cannot run ESDaemon" && has "filter, $ROOT/src/scope.jq, with this config:"'
ok "shows what jq said"                                    'has "  jq: error: pick/1 is not defined at <top-level>, line 12:" && has "  jq: 1 compile error"'
ok "names the macOS it supports"                           'has "ESDaemon supports macOS 15.0 or later, with the /usr/bin/jq that comes with it"'
chk "$DEF" "$T/jq-mute"
ok "prints nothing, exit 0: stops, says so"                '[ $rc = 1 ] && has "$T/jq-mute (jq-1.7.1) cannot run" && has "  (jq printed nothing)"'
chk "$DEF" "$T/none/jq"
ok "no jq there: stops, version unknown"                   '[ $rc = 1 ] && has "$T/none/jq (version unknown) cannot run"'
printf '#!/bin/bash\necho "jq-$(cat)"\n' > "$T/jq-stdin"; chmod +x "$T/jq-stdin"   # a wrapper that reads its input, --version too
chk "$DEF" "$T/jq-stdin" <<< "the caller's input"
ok "asks for the version with nothing on stdin: a jq that reads it cannot hang the check" '[ $rc = 1 ] && has "$T/jq-stdin (jq-) cannot run" && ! has "the caller"'
cat > "$T/jq-rule" <<'S'
#!/bin/bash
# a jq on which the rules fail: every event is still logged, marked esd_rule_error
[ "${1:-}" = --version ] && { echo jq-1.7.1; exit 0; }
cat > /dev/null
echo '{"eslogger_scoped_gap":1,"time":"t","after_global_seq_num":1}'
echo '{"Image":"/bin/zsh","esd_rule_error":"( (at offset 1) is not a valid regex in [exclude]: Image regex ("}'
S
chmod +x "$T/jq-rule"
chk "$DEF" "$T/jq-rule"
ok "a rule fails on an event (esd_rule_error): stops, shows it" '[ $rc = 1 ] && has "\"esd_rule_error\":"'
# cfgs cfg.sh never writes, run by the real jq to the end: users not an object, so no record can be built; a regex that
# does not compile, so the rule cannot be evaluated (a marker of either kind, depending on the version of scope.jq)
chk "$(jq -c ".users = []" <<< "$DEF")"
ok "every event hits a filter error: stops, shows it"      '[ $rc = 1 ] && has "\"esd_filter_error\":"'
chk "$(jq -c ".exclude = [[{field: \"Image\", op: \"regex\", value: \"(\"}]]" <<< "$DEF")"
ok "a rule fails on every event: stops, shows it"          '[ $rc = 1 ] && grep -qE "\"esd_(rule|filter)_error\":" <<< "$out"'

echo "-- it runs scope.jq as filter.sh does"
# jq's options, as written before --argjson cfg in each
FOPT="$(sed -n 's|.*/usr/bin/jq \(-.*\) --argjson cfg "$CFG" -f "$BASE/scope.jq".*|\1|p' "$ROOT/bin/filter.sh")"
COPT="$(sed -n 's|.*"$jq" \(-.*\) --argjson cfg "$2" -f "$1".*|\1|p' "$ROOT/bin/jqcheck.sh")"
ok "with filter.sh's options ($FOPT)"                      '[ -n "$FOPT" ] && [ "$FOPT" = "$COPT" ]'

echo "-- install.sh and reload.sh run it on /usr/bin/jq before their first change, and stop there when it fails"
if [ ! -x /usr/bin/jq ]; then echo "  skipped: no /usr/bin/jq, which install.sh and reload.sh run"
elif [ "$(id -u)" = 0 ]; then echo "  skip running as root: a script that skipped the check would change things for real"
else
  # install.sh and reload.sh from a copy of the checkout, and reload.sh from a copy laid out as installed. The chain.sh
  # in each lets them through, points them at the installed copy (BASE) and the default cfg, and refuses their first
  # change (install), so none of them changes anything, even one that skipped the check.
  mkdir -p "$T/src" "$T/inst"; cp -R "$ROOT/install.sh" "$ROOT/bin" "$ROOT/configs" "$ROOT/src" "$T/src/"
  cp "$ROOT/bin/reload.sh" "$ROOT/bin/cfg.sh" "$ROOT/bin/jqcheck.sh" "$ROOT/src/scope.jq" "$T/inst/"
  printf 'esd_gate(){ BASE=%q; CFGF=%q; }\ninstall(){ echo "went on to install $*"; return 1; }\n' "$T/inst" "$ROOT/configs/ESDaemon.cfg" > "$T/inst/chain.sh"
  cp "$T/inst/chain.sh" "$T/src/bin/chain.sh"
  run(){ out="$(TMPDIR="$T" bash "$1" 2>&1)"; rc=$?; }   # TMPDIR: a migrated draft install.sh leaves goes with $T
  RESTART="went on to install -d -o root -g wheel -m 700 /usr/local/ESDaemon/run /var/log/ESDaemon"
  run "$T/src/install.sh"
  ok "install.sh: the filter runs, so it goes on to install" '[ $rc = 1 ] && [ "$out" = "went on to install -d -o 0 -g 0 -m 755 $T/inst/bin" ]'
  run "$T/inst/reload.sh"
  ok "reload.sh: the filter runs, so it goes on to restart"  '[ $rc = 1 ] && [ "$(tail -1 <<< "$out")" = "$RESTART" ]'
  run "$T/src/bin/reload.sh"
  ok "reload.sh from a checkout (no scope.jq beside it): checks the installed one, which the filter runs" '[ $rc = 1 ] && [ "$(tail -1 <<< "$out")" = "$RESTART" ]'
  printf 'not a jq program\n' > "$T/src/src/scope.jq"; cp "$T/src/src/scope.jq" "$T/inst/scope.jq"
  run "$T/src/install.sh"
  ok "install.sh: a filter /usr/bin/jq cannot compile: stops (1) at the check" '[ $rc = 1 ] && has "install.sh: stopped, nothing was changed. /usr/bin/jq (" && ! has "went on"'
  run "$T/inst/reload.sh"
  ok "reload.sh: the same, before it restarts anything"      '[ $rc = 1 ] && has "reload.sh: stopped, nothing was changed. /usr/bin/jq (" && ! has "went on"'
  mkdir "$T/inst/configs"; cp "$ROOT/test/fixtures/v1.cfg" "$T/inst/configs/ESDaemon.cfg"; run "$T/src/install.sh"
  ok "install.sh, an older cfg migrated first: stops, naming the migrated draft" '[ $rc = 1 ] && has "install.sh: stopped" && has "(migrated draft: $T/"'
fi

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
