#!/bin/bash
# control-tests.sh — the esdaemon control command: usage/exit codes, and the uninstall removal path.
# Uninstall is exercised against a throwaway tree (ESDAEMON_BASE/LD/LOGS/SELF overridden) with launchctl
# stubbed, so it runs on Linux or macOS without root and never touches a real install.
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/.."; ESD="$ROOT/bin/esdaemon"
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }

# a throwaway install tree + a launchctl stub that records what it was asked to bootout
new_tree(){
  T="$(mktemp -d)"
  mkdir -p "$T/base/configs" "$T/ld" "$T/logs" "$T/bin"
  printf '0.1.0\n' > "$T/base/VERSION"
  printf 'process = start\n' > "$T/base/configs/ESDaemon.cfg"
  cp "$ROOT/bin/chain.sh" "$T/base/"   # installed next to reload.sh; status runs it
  : > "$T/ld/com.esdaemon.filter.plist"; : > "$T/ld/com.esdaemon.eslogger.plist"
  cp "$ESD" "$T/bin/esdaemon"; chmod +x "$T/bin/esdaemon"
  printf '#!/bin/bash\necho "$@" >> "%s/launchctl.log"\n' "$T" > "$T/lc"; chmod +x "$T/lc"
}
run(){ ESDAEMON_BASE="$T/base" ESDAEMON_LD="$T/ld" ESDAEMON_LOGS="$T/logs" \
       ESDAEMON_SELF="${SELF:-$T/bin/esdaemon}" ESDAEMON_LAUNCHCTL="$T/lc" ESDAEMON_LOG=/bin/true \
       ESDAEMON_NEWSYSLOG="$T/newsyslog.conf" \
       bash "$T/bin/esdaemon" "$@"; }

echo "-- usage and exit codes"
new_tree
ok "help exits 0"                 'run help >/dev/null 2>&1'
ok "unknown command exits 2"      'run frobnicate >/dev/null 2>&1; rc=$?; [ $rc -eq 2 ]'
ok "version prints installed ver" '[ "$(run version 2>/dev/null)" = 0.1.0 ]'
ok "config prints cfg path"       '[ "$(run config)" = "$T/base/configs/ESDaemon.cfg" ]'
ok "status names both daemons"    's="$(run status 2>/dev/null)"; [[ "$s" == *com.esdaemon.eslogger* && "$s" == *com.esdaemon.filter* ]]'
ok "help prints the usage, no code" 'h="$(run help)"; grep -q "esdaemon uninstall" <<< "$h" && ! grep -q pipefail <<< "$h"'

echo "-- status: can anyone but root change the install tree or a directory above it (chain.sh)? exit 1 if so"
# a throwaway tree is the test user's, and above it is a temp dir: another user can change it, which is the point
new_tree
s="$(run status 2>/dev/null)"; rc=$?
ok "a tree others can change: UNSAFE, exit 1"      '[ $rc = 1 ] && grep -q "^permissions  *UNSAFE" <<< "$s"'
ok "names the path, with the fix"                  '[ "$(id -u)" = 0 ] || grep -qF "  $T/base is owned by uid $(id -u), not root; fix: sudo chown root:wheel $T/base" <<< "$s"'
ok "a command on PATH others can replace: UNSAFE"  'grep -qF "command          UNSAFE: users other than root can replace $T/bin/esdaemon" <<< "$s"'
ok "...with the fix: the copy in the install tree" 'grep -qF "fix: sudo rm $T/bin/esdaemon, and run sudo $T/base/bin/esdaemon instead" <<< "$s"'
ok "no command on PATH: nothing said about it"     '! grep -q "^command" <<< "$(SELF="$T/none" run status 2>/dev/null)"'
rm -f "$T/base/chain.sh"; s="$(run status 2>/dev/null)"; rc=$?
ok "without chain.sh: says it did not check, exit 0" '[ $rc = 0 ] && grep -q "^permissions  *not checked" <<< "$s"'
rm -rf "${T:?}"

echo "-- uninstall removes the install, keeps a config copy, and self-deletes"
new_tree
run uninstall >/dev/null 2>&1; rc=$?
ok "uninstall exits 0"                 '[ $rc -eq 0 ]'
ok "booted out both daemons"           '[ "$(grep -c "^bootout system/com.esdaemon" "$T/launchctl.log")" = 2 ]'
ok "removed both plists"               '[ ! -e "$T/ld/com.esdaemon.filter.plist" ] && [ ! -e "$T/ld/com.esdaemon.eslogger.plist" ]'
ok "removed the install dir"           '[ ! -e "$T/base" ]'
ok "removed the control command"       '[ ! -e "$T/bin/esdaemon" ]'
ok "saved a config copy (no --purge)"  '[ -f "$T/logs/ESDaemon.cfg.uninstalled" ]'
ok "kept the logs dir (no --purge)"    '[ -d "$T/logs" ]'

echo "-- uninstall --purge also deletes the logs dir"
new_tree
run uninstall --purge >/dev/null 2>&1
ok "removed the install dir"           '[ ! -e "$T/base" ]'
ok "removed the logs dir"              '[ ! -e "$T/logs" ]'
ok "removed the control command"       '[ ! -e "$T/bin/esdaemon" ]'

echo "-- uninstall: the command on PATH only if the install put it there (not where others can write)"
new_tree
out="$(SELF="$T/none" run uninstall 2>&1)"
ok "removes the install, claims nothing about a command that is not there" '[ ! -e "$T/base" ] && ! grep -q "removed $T/none" <<< "$out"'
rm -rf "${T:?}"

echo "-- uninstall.sh removes in place: it never runs the installed command"
ok "no exec, no installed esdaemon run"            '! grep -v "^[[:space:]]*#" "$ROOT/uninstall.sh" | grep -Eq "(^|[^[:alnum:]_])exec[[:space:]]|esdaemon uninstall"'

echo "-- real uninstall refuses to run without root"
ok "uninstall on real BASE needs root" '[ "$(id -u)" = 0 ] || { out=$(ESDAEMON_LAUNCHCTL=/bin/true bash "$ESD" uninstall 2>&1); [ $? -ne 0 ] && echo "$out" | grep -qi "run as root"; }'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
