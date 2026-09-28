#!/bin/bash
# drop-tests.sh — [drop] syntax end to end: cfg text -> cfg.sh -> scope.jq, plus parser error cases.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
# base cfg = default cfg + the [drop] rules below
{ cat "$ROOT/configs/ESDaemon.cfg"; cat <<'R'

[drop]
Image is /usr/bin/curl AND CommandLine begin with "curl -s https://updates.example.com/"
Image image jamf AND CommandLine contains "policy -event recurring"
ParentImage end with /usr/local/bin/jamf AND Image image sh AND CommandLine contains inventory
TeamId is any AAAAAAAAAA;BBBBBBBBBB
Image image python3 AND CommandLine regex ^python3 /opt/corp/[a-z]+\.py$
ParentCommandLine begin with "/usr/local/bin/munki" AND Image image curl
R
} > "$T/d.cfg"
CFG="$("$ROOT/bin/cfg.sh" "$T/d.cfg" json)" || { echo "cfg failed to parse"; exit 1; }
run(){ jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | grep -vc eslogger_scoped_gap; }
# ev <parent path> <target path> <args json> [team_id]
ev(){ jq -cn --arg pp "$1" --arg p "$2" --argjson a "$3" --arg tm "${4:-}" '{process:{executable:{path:$pp},is_platform_binary:true,audit_token:{pid:8}},event:{exec:{target:{executable:{path:$p},is_platform_binary:($tm==""),team_id:(if $tm=="" then null else $tm end),audit_token:{pid:8},ppid:7},args:$a}}}'; }

echo "-- rule 1: Image is + CommandLine begin with"
ok "pinned curl update URL -> dropped"          '[ "$(ev /bin/zsh /usr/bin/curl "[\"curl\",\"-s\",\"https://updates.example.com/a.pkg\"]" | run)" = 0 ]'
ok "same curl, other host -> kept"              '[ "$(ev /bin/zsh /usr/bin/curl "[\"curl\",\"-s\",\"https://evil.com/a\"]" | run)" = 1 ]'
ok "case-insensitive like Sysmon"               '[ "$(ev /bin/zsh /usr/bin/curl "[\"curl\",\"-s\",\"HTTPS://UPDATES.EXAMPLE.COM/a\"]" | run)" = 0 ]'
ok "curl copied elsewhere -> kept (Image is)"   '[ "$(ev /bin/zsh /tmp/curl "[\"curl\",\"-s\",\"https://updates.example.com/a\"]" | run)" = 1 ]'
echo "-- rule 2: Image image (name or path) + contains"
ok "jamf policy recurring -> dropped"           '[ "$(ev /sbin/launchd /usr/local/bin/jamf "[\"jamf\",\"policy\",\"-event\",\"recurring\"]" AAAA000000 | run)" = 0 ]'
ok "jamf other command -> kept"                 '[ "$(ev /sbin/launchd /usr/local/bin/jamf "[\"jamf\",\"removeFramework\"]" AAAA000000 | run)" = 1 ]'
echo "-- rule 3: three clauses, ParentImage end with"
ok "jamf -> sh inventory -> dropped"            '[ "$(ev /usr/local/bin/jamf /bin/sh "[\"sh\",\"-c\",\"curl x; inventory\"]" | run)" = 0 ]'
ok "other parent -> sh inventory -> kept"       '[ "$(ev /tmp/evil /bin/sh "[\"sh\",\"-c\",\"curl x; inventory\"]" | run)" = 1 ]'
echo "-- rule 4: TeamId is any"
ok "vendor B binary -> dropped"                 '[ "$(ev /sbin/launchd /Applications/B.app/Contents/MacOS/B "[\"B\"]" BBBBBBBBBB | run)" = 0 ]'
ok "vendor C binary -> kept"                    '[ "$(ev /sbin/launchd /Applications/C.app/Contents/MacOS/C "[\"C\"]" CCCCCCCCCC | run)" = 1 ]'
echo "-- rule 5: regex"
ok "python3 corp script -> dropped"             '[ "$(ev /bin/zsh /usr/bin/python3 "[\"python3\",\"/opt/corp/sync.py\"]" | run)" = 0 ]'
ok "regex anchored: extra args -> kept"         '[ "$(ev /bin/zsh /usr/bin/python3 "[\"python3\",\"/opt/corp/sync.py\",\"-c\",\"import os\"]" | run)" = 1 ]'
echo "-- rule 6: ParentCommandLine unknown -> never drops"
ok "no cached parent -> kept"                   '[ "$(ev /usr/local/bin/munki /usr/bin/curl "[\"curl\",\"https://x\"]" | run)" = 1 ]'
echo "-- parser errors (reload refuses)"
bad(){ printf '[drop]\n%s\n' "$1" > "$T/b.cfg"; ! "$ROOT/bin/cfg.sh" "$T/b.cfg" json >/dev/null 2>&1; }
ok "unknown field refused"        'bad "Imag is x"'
ok "unknown condition refused"    'bad "Image equals x"'
ok "bad regex refused"            'bad "CommandLine regex ([x"'
ok "free text refused"            'bad "just text"'
ok "dangling AND refused"         'bad "Image is x AND"'
printf '[drop]\nCommandLine contains cut and paste AND Image is /bin/sh\n' > "$T/a.cfg"
ok "lowercase and stays in value"  '[ "$("$ROOT/bin/cfg.sh" "$T/a.cfg" json | jq -r ".drop[0][0].value")" = "cut and paste" ]'
printf '[drop]\nCommandLine contains " AND " AND Image is /bin/sh\n' > "$T/q.cfg"
ok "quoted value may contain AND"  '[ "$("$ROOT/bin/cfg.sh" "$T/q.cfg" json | jq -r ".drop[0][0].value")" = " AND " ]'
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
