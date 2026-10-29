#!/bin/bash
# stderr-rotation-tests.sh — issue #9: the daemons' stderr logs must stay bounded. launchd appends
# /var/log/ESDaemon/{eslogger,filter}.stderr forever, so a crash-looping daemon can fill the disk.
# reload.sh now installs a newsyslog config that rotates them by size while keeping recent archives, and
# both uninstall paths remove it.
#   - the rendered config is checked statically (runs anywhere jq is on PATH: CI, macOS);
#   - its field layout is validated with newsyslog when present (macOS only);
#   - removal is checked by running `esdaemon uninstall` against a throwaway tree, and by a static check of
#     uninstall.sh (which removes in place and is never executed here, as control-tests.sh documents).
# shellcheck disable=SC2034  # vars read only inside the single-quoted strings ok() evals look unused to shellcheck
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/.."; ESD="$ROOT/bin/esdaemon"
TD="$(mktemp -d)"; trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }

echo "-- reload.sh --render emits a newsyslog rotation config alongside the plists"
mkdir -p "$TD/ld"
ESLP="$TD/ld/com.esdaemon.eslogger.plist"; FLTP="$TD/ld/com.esdaemon.filter.plist"; CONF="$TD/ld/com.esdaemon.conf"
"$ROOT/bin/reload.sh" --render "$TD/ld" "$ROOT/configs/ESDaemon.cfg" >/dev/null 2>&1 || true
if [ -f "$ESLP" ]; then
  ok "render writes the rotation config next to the plists" '[ -f "$CONF" ]'
  ok "config bounds eslogger.stderr"                        'grep -q "/var/log/ESDaemon/eslogger.stderr" "$CONF"'
  ok "config bounds filter.stderr"                          'grep -q "/var/log/ESDaemon/filter.stderr" "$CONF"'
  # the stderr paths the plists write to are exactly the ones the config rotates — no drift between the two
  ok "eslogger plist stderr path matches the config"        'grep -q "<string>/var/log/ESDaemon/eslogger.stderr</string>" "$ESLP"'
  ok "filter plist stderr path matches the config"          'grep -q "<string>/var/log/ESDaemon/filter.stderr</string>" "$FLTP"'

  # the fields of the eslogger entry (comments start their first field with '#', so they are skipped):
  #   logfile  owner:group  mode  count  size(KB)  when  flags
  read -r _ og mode count size when flags <<EOF
$(awk '$1 !~ /^#/ && /eslogger\.stderr/ {print; exit}' "$CONF")
EOF
  # bounded means: rotate on SIZE (a positive KB threshold, when = '*' so time is not the only trigger) and keep
  # a FINITE number of archives — so the files cannot grow without bound, while the current file holds the tail.
  ok "rotates at a positive size threshold in KB"  'case "$size"  in ""|*[!0-9]*) false;; *) [ "$size"  -gt 0 ];; esac'
  ok "keeps a finite, positive archive count"      'case "$count" in ""|*[!0-9]*) false;; *) [ "$count" -gt 0 ];; esac'
  ok "size is the rotation trigger (when = '*')"   '[ "$when" = "*" ]'
  ok "marks no process needs signalling (flag N)"  'case "$flags" in *N*) true;; *) false;; esac'

  echo "-- this Mac's newsyslog accepts the generated config's field layout (macOS only, needs root)"
  # newsyslog needs root even for -n (a dry run): a non-root run exits "must have root privs" regardless of the
  # config. So validate only where passwordless sudo is available (the CI macOS runners and the Mac lab); elsewhere
  # skip — the static field assertions above already encode the bound properties without newsyslog.
  if command -v newsyslog >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    # Validate the exact owner/mode/count/size/when/flags tuple over a log file that exists, so the check turns
    # on field validity rather than on the real /var/log path being present or on newsyslog's exact wording.
    probe="$TD/probe.conf"; plog="$TD/probe.stderr"; : > "$plog"
    printf '%s %s %s %s %s %s %s\n' "$plog" "$og" "$mode" "$count" "$size" "$when" "$flags" > "$probe"
    sudo -n newsyslog -n -f "$probe" >/dev/null 2>&1; rc=$?
    ok "newsyslog -n accepts the field layout (exit 0)" '[ "$rc" -eq 0 ]'
  else
    echo "  skipped: newsyslog absent or no passwordless sudo (the Mac lab validates it as root)"
  fi
else
  echo "  skipped: reload.sh --render produced no plists here (cfg.sh needs /usr/bin/jq; CI/macOS cover it)"
fi

echo "-- esdaemon uninstall removes the rotation config (it is our artifact, like the plists — not user data)"
mk_tree(){ # $1 = tree dir
  mkdir -p "$1/base/configs" "$1/ld" "$1/logs" "$1/bin"
  printf '0.1.0\n' > "$1/base/VERSION"
  printf 'process = start\n' > "$1/base/configs/ESDaemon.cfg"
  : > "$1/ld/com.esdaemon.filter.plist"; : > "$1/ld/com.esdaemon.eslogger.plist"
  cp "$ESD" "$1/bin/esdaemon"; chmod +x "$1/bin/esdaemon"
  printf '#!/bin/bash\ntrue\n' > "$1/lc"; chmod +x "$1/lc"
  : > "$1/conf"   # stands in for the installed /etc/newsyslog.d/com.esdaemon.conf
}
unrun(){ local d="$1"; shift
  ESDAEMON_BASE="$d/base" ESDAEMON_LD="$d/ld" ESDAEMON_LOGS="$d/logs" ESDAEMON_SELF="$d/bin/esdaemon" \
  ESDAEMON_LAUNCHCTL="$d/lc" ESDAEMON_LOG=/bin/true ESDAEMON_NEWSYSLOG="$d/conf" ESDAEMON_PKGUTIL=/bin/true bash "$d/bin/esdaemon" "$@"; }

U="$TD/u1"; mk_tree "$U"; unrun "$U" uninstall >/dev/null 2>&1
ok "removed the rotation config (no --purge)" '[ ! -e "$U/conf" ]'
ok "kept the logs dir (no --purge)"           '[ -d "$U/logs" ]'

U="$TD/u2"; mk_tree "$U"; unrun "$U" uninstall --purge >/dev/null 2>&1
ok "removed the rotation config (--purge)"    '[ ! -e "$U/conf" ]'
ok "removed the logs dir (--purge)"           '[ ! -e "$U/logs" ]'

echo "-- uninstall.sh removes the rotation config in place (static: it is never executed here)"
ok "uninstall.sh rm's /etc/newsyslog.d/com.esdaemon.conf" \
   'grep -vE "^[[:space:]]*#" "$ROOT/uninstall.sh" | grep -Eq "rm([[:space:]]|[[:space:]]-[a-z]+[[:space:]])+/etc/newsyslog\.d/com\.esdaemon\.conf"'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
