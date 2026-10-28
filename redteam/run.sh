#!/bin/bash
# run.sh — ESDaemon adversary-emulation runner.
# Runs benign, self-cleaning emulations of macOS attacker techniques and checks whether ESDaemon logged each one,
# producing a technique -> detected table. Run it on the Mac where ESDaemon is installed (it reads the unified log).
#
#   ./run.sh list                       show every scenario (id, tactic, LOOBin, technique)
#   ./run.sh run                        run all, verify each against the unified log, clean up
#   ./run.sh run --tactic persistence   only one tactic
#   ./run.sh run --id launchagent       only scenarios whose function name contains this
#   ./run.sh run --no-verify            just generate the activity (e.g. to watch it arrive in your SIEM)
#   ./run.sh run --destructive          also run the state-changing variants (disable Gatekeeper, add account, ...),
#                                       each still restored afterwards. VM ONLY.
#   ./run.sh run --keep                 do not run the cleanup steps (leave artifacts for inspection)
# Nothing here harms the machine by default: every scenario uses a harmless payload and removes what it creates.
set -uo pipefail
# fixed PATH: this can run as root, and macOS sudo keeps the caller's PATH — so bare tool names resolve to system binaries
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"; . "$HERE/scenarios.sh"
SUBSYS="${ESD_RT_SUBSYS:-com.apple.eslogger}"

cmd="${1:-list}"; shift || true
FILTER_TACTIC=""; FILTER_ID=""; VERIFY=1; CLEAN=1
while [ $# -gt 0 ]; do case "$1" in
  --tactic) FILTER_TACTIC="$2"; shift 2;;
  --id) FILTER_ID="$2"; shift 2;;
  --no-verify) VERIFY=0; shift;;
  --keep) CLEAN=0; shift;;
  --destructive) DESTRUCTIVE=1; export ESD_RT_DESTRUCTIVE=1; shift;;
  --subsys) SUBSYS="$2"; shift 2;;
  *) echo "unknown option: $1" >&2; exit 2;;
esac; done

selected() {
  local fn m tac
  for fn in "${RT[@]}"; do
    m="$($fn meta)"; tac="$(echo "$m" | cut -d'|' -f3)"
    [ -n "$FILTER_TACTIC" ] && [ "$tac" != "$FILTER_TACTIC" ] && continue
    [ -n "$FILTER_ID" ] && [[ "$fn" != *"$FILTER_ID"* ]] && continue
    echo "$fn"
  done
}

if [ "$cmd" = list ]; then
  printf '%-26s %-20s %-16s %-12s %s\n' "SCENARIO" "TACTIC" "LOOBIN" "MITRE" "TECHNIQUE"
  while read -r fn; do [ -z "$fn" ] && continue; m="$($fn meta)"
    printf '%-26s %-20s %-16s %-12s %s\n' "${fn#sc_}" "$(echo "$m"|cut -d'|' -f3)" "$(echo "$m"|cut -d'|' -f4)" "$(echo "$m"|cut -d'|' -f1)" "$(echo "$m"|cut -d'|' -f2)"
  done < <(selected)
  exit 0
fi
[ "$cmd" = run ] || { echo "usage: $0 {list|run} [options]" >&2; exit 2; }

[ -x /usr/bin/jq ] || { echo "needs /usr/bin/jq" >&2; exit 1; }
echo "ESDaemon adversary emulation — nonce $NONCE, workdir $WORK$([ "$DESTRUCTIVE" = 1 ] && echo ', DESTRUCTIVE on')"
echo
pass=0; miss=0; total=0

# look for this scenario's own record in the unified log since $1 (start time)
verified() {
  local start="$1" type="$2" img="$3" neednonce="$4"
  /usr/bin/log show --start "$start" --predicate "subsystem == \"$SUBSYS\"" --style ndjson 2>/dev/null \
   | /usr/bin/jq -e -n --arg type "$type" --arg img "$img" --arg nonce "$NONCE" --argjson neednonce "$neednonce" '
      [ inputs | .eventMessage? | select(.) | fromjson? | select(type=="object")
        | select($type == "any" or .EventType == $type)
        | if ($type|startswith("File")) then select((.TargetFilename//"")|contains($nonce))
          else select((.Image//"") == $img)
               | select($neednonce == 0 or (((.CommandLine//"")+(.TargetFilename//"")+(.ParentCommandLine//""))|contains($nonce))) end
      ] | length > 0' >/dev/null 2>&1
}

while read -r fn; do
  [ -z "$fn" ] && continue
  m="$($fn meta)"; mitre="$(echo "$m"|cut -d'|' -f1)"; name="$(echo "$m"|cut -d'|' -f2)"
  img="$(echo "$m"|cut -d'|' -f5)"; type="$(echo "$m"|cut -d'|' -f6)"; [ -z "$type" ] && type=ProcessStart
  match="$(echo "$m"|cut -d'|' -f7)"; neednonce=1; [ "$match" = "-" ] && neednonce=0
  total=$((total+1))
  printf '[%2d] %-24s %-10s %s\n' "$total" "${fn#sc_}" "$mitre" "$name"
  start="$(date '+%Y-%m-%d %H:%M:%S')"
  ( $fn run ) 2>&1 | sed 's/^/      /'
  if [ "$VERIFY" = 1 ]; then
    sleep 2
    if verified "$start" "$type" "$img" "$neednonce"; then echo "      -> DETECTED by ESDaemon"; pass=$((pass+1))
    else echo "      -> MISS (no matching record)"; miss=$((miss+1)); fi
  fi
  [ "$CLEAN" = 1 ] && ( $fn clean ) >/dev/null 2>&1
done < <(selected)

[ "$CLEAN" = 1 ] && rm -rf "$WORK"
echo
if [ "$VERIFY" = 1 ]; then
  echo "detected $pass / $total techniques$([ "$miss" -gt 0 ] && echo " ($miss missed — investigate the config or a real gap)")"
  [ "$miss" -eq 0 ] && echo "every emulated technique was logged by ESDaemon."
else
  echo "ran $total techniques (verification off)."
fi
