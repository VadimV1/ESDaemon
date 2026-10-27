#!/bin/bash
# lifecycle-tests.sh — what reload.sh ships to launchd and what try.sh reports. A cfg that parses must also produce a
# daemon that starts; the FIFO must survive a reboot; drop markers must not be counted as kept events.
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
cfg(){ printf '[settings]\n%s\n' "$1" > "$T/c.cfg"; "$ROOT/bin/cfg.sh" "$T/c.cfg" json >/dev/null 2>&1; }
mods(){ printf '[modules]\n%b\n' "$1" > "$T/m.cfg"; "$ROOT/bin/cfg.sh" "$T/m.cfg" events 2>/dev/null; }

echo "-- cfg values that end up in the LaunchDaemon plists / the filter are validated"
ok "[modules] -> eslogger events, deduplicated"    '[ "$(mods "process = start, exit\nfile = read, write, create, delete, rename\nprocess = start")" = "exec exit open close create unlink rename" ]'
ok "every module operation maps to eslogger events" '[ -n "$(mods "process = start, exit, inject\nfile = read, write, create, delete, rename, attributes\nuser = login, logout, sudo, account\nsystem = persistence, malware, kernel, mount")" ]'
ok "operations separated by spaces work too"      '[ "$(mods "file = create delete")" = "create unlink" ]'
ok "module with XML/shell chars refused"          '! mods "file = read<x"'
ok "format typo refused"                          '! cfg "format = sysmon-extras"'
ok "third_party typo refused"                     '! cfg "third_party = drop-noisy"'
ok "subsystem path chars refused"                 '! cfg "subsystem = ../../tmp/x"'
ok "custom subsystem accepted"                    'cfg "subsystem = com.corp.esdaemon"'
ok "default cfg still parses"                     '"$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json >/dev/null 2>&1'

echo "-- reload.sh --render"
mkdir -p "$T/ld" "$T/bad"
ok "renders both plists from the default cfg"     '"$ROOT/bin/reload.sh" --render "$T/ld" "$ROOT/configs/ESDaemon.cfg" >/dev/null 2>&1 && [ -f "$T/ld/com.esdaemon.eslogger.plist" ] && [ -f "$T/ld/com.esdaemon.filter.plist" ]'
ok "eslogger args from the default [modules] (process start, user login)" 'grep -q "<string>/usr/bin/eslogger</string><string>exec</string><string>authentication</string>" "$T/ld/com.esdaemon.eslogger.plist"'
FIFO_PLIST="$(sed -n 's:.*<key>StandardOutPath</key><string>\(.*\)</string>.*:\1:p' "$T/ld/com.esdaemon.eslogger.plist")"
FIFO_FILTER="$(bash -c "$(grep -E '^BASE=' "$ROOT/bin/filter.sh")"'; echo "$FIFO"')"
ok "FIFO not under /var/run (wiped at boot)"      '[ -n "$FIFO_PLIST" ] && [ "${FIFO_PLIST#/var/run/}" = "$FIFO_PLIST" ]'
ok "eslogger and filter use the same FIFO"        '[ "$FIFO_PLIST" = "$FIFO_FILTER" ]'
printf '[modules]\nfile = read<x\n' > "$T/bad.cfg"
ok "bad cfg: render refuses, writes nothing"      '! "$ROOT/bin/reload.sh" --render "$T/bad" "$T/bad.cfg" >/dev/null 2>&1 && [ -z "$(ls "$T/bad")" ]'
ok "filter runs the cfg reload.sh validated"      'grep -q "CFGF=\"\$RUN/active.cfg\"" "$ROOT/bin/filter.sh" && grep -q "\$RUN/active.cfg\"" "$ROOT/bin/reload.sh"'

echo "-- try.sh does not count eslogger_scoped_gap markers as kept events"
ev(){ jq -cn --arg tp "$1" --argjson g "$2" --argjson args "$3" '
  def proc($p): {executable:{path:$p}, audit_token:{pid:(4000+$g), euid:501, ruid:501}, ppid:1, original_ppid:1,
     is_platform_binary:true, team_id:null, signing_id:"x", cdhash:"ab", codesigning_flags:570522385};
  {schema_version:1, time:"2026-09-28T10:00:00Z", seq_num:$g, global_seq_num:$g, process:proc("/bin/zsh"),
   event:{exec:{target:proc($tp), args:$args, cwd:{path:"/"}, env:[], fds:[]}}}'; }
{ ev /usr/bin/true 1 '["true"]'; ev /usr/bin/curl 2 '["curl","-o","/tmp/a","https://x/y"]'; ev /usr/bin/true 10 '["true"]'; } > "$T/cap.ndjson"
OUT="$("$ROOT/bin/try.sh" "$T/cap.ndjson" "$ROOT/configs/ESDaemon.cfg" 2>&1)"
ok "kept = 3 real events (log all), gap marker not counted" 'grep -Eq "^kept +3 events" <<< "$OUT"'
ok "reports the 7 events ES dropped"              'grep -q "dropped 7 events" <<< "$OUT"'
ok "no null in top kept images"                   '! grep -q " null$" <<< "$OUT"'
rm -f "$(sed -n 's/^kept events: //p' <<< "$OUT")"

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
