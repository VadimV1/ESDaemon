#!/bin/bash
# sysmon-tests.sh — format = sysmon field mapping + format = raw pass-through (synthetic events).
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; pass=0; fail=0
# fixed uid map so User does not depend on the accounts of the machine running the tests
CFG="$("$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json | jq -c '.users = {"501": "alice"}')"
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
EXEC='{"time":"2026-09-28T10:00:00.123456789Z","global_seq_num":1,"process":{"executable":{"path":"/bin/zsh"},"audit_token":{"pid":4242,"euid":501},"start_time":"2026-09-28T09:59:59Z","is_platform_binary":true,"signing_id":"com.apple.zsh"},"event":{"exec":{"target":{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":4242,"euid":501},"ppid":4100,"original_ppid":4100,"session_id":100,"cdhash":"abcd","signing_id":"com.apple.curl","team_id":null,"is_platform_binary":true},"args":["curl","-o","/tmp/a b","https://x/y"],"cwd":{"path":"/Users/a"},"env":["USER=alice","PATH=/usr/bin"]}}}'
S=$(echo "$EXEC" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq"); echo "  $S"
ok "EventID 1 ProcessStart, no Channel" '[ "$(echo "$S" | jq -r "[.EventID,.EventType,has(\"Channel\")]|map(tostring)|join(\",\")")" = "1,ProcessStart,false" ]'
ok "Image / ParentImage"              '[ "$(echo "$S" | jq -r ".Image+\"|\"+.ParentImage")" = "/usr/bin/curl|/bin/zsh" ]'
ok "CommandLine quotes arg w/ space"  '[ "$(echo "$S" | jq -r .CommandLine)" = "curl -o \"/tmp/a b\" https://x/y" ]'
ok "UtcTime Sysmon format (ms)"       '[ "$(echo "$S" | jq -r .UtcTime)" = "2026-09-28 10:00:00.123" ]'
ok "User (uid map), pids, cwd"       '[ "$(echo "$S" | jq -r "[.User,.ProcessId,.ParentProcessId,.CurrentDirectory]|join(\",\")")" = "alice,4242,4100,/Users/a" ]'
ok "CDHash plain hex, signing extras" '[ "$(echo "$S" | jq -r "[.CDHash,.SigningId,(.IsPlatformBinary|tostring)]|join(\",\")")" = "abcd,com.apple.curl,true" ]'
ok "ProcessGuid is GUID-shaped (start time + pid)" '[ "$(echo "$S" | jq -r .ProcessGuid)" = "{6ABA3A9F-0000-0000-0000-000000001092}" ]'
ok "field order: EventID, EventType, UtcTime first; CDHash last; no RuleName" '[ "$(echo "$S" | jq -r "keys_unsorted | (.[0:3] + [last]) | join(\",\")")" = "EventID,EventType,UtcTime,CDHash" ] && [ "$(echo "$S" | jq "has(\"RuleName\")")" = false ]'
ok "field order: User, Image, CommandLine follow the header" '[ "$(echo "$S" | jq -r "keys_unsorted[3:6] | join(\",\")")" = "User,Image,CommandLine" ]'
ok "no null fields emitted"           '[ "$(echo "$S" | jq "[.[]|select(.==null)]|length")" = 0 ]'
F='{"time":"2026-09-28T10:00:01Z","process":{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":7,"euid":0},"is_platform_binary":true},"event":{"create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"/Users/a/Library/LaunchAgents"},"filename":"x.plist"}}}}}'
S2=$(echo "$F" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
ok "create -> EventID 11 TargetFilename" '[ "$(echo "$S2" | jq -r "[.EventID,.EventType,.TargetFilename,.Image]|map(tostring)|join(\",\")")" = "11,FileCreate,/Users/a/Library/LaunchAgents/x.plist,/usr/bin/curl" ]'
# parent chain: zsh exec (logged and cached) then its child curl -> ParentCommandLine filled
PAR='{"time":"2026-09-28T09:59:59Z","global_seq_num":1,"process":{"executable":{"path":"/usr/bin/login"},"audit_token":{"pid":4100},"start_time":"2026-09-28T09:59:58Z","is_platform_binary":true},"event":{"exec":{"target":{"executable":{"path":"/bin/zsh"},"audit_token":{"pid":4100,"euid":501},"ppid":1,"is_platform_binary":true},"args":["-zsh","-l"]}}}'
CH2=$(printf "%s\n%s\n" "$PAR" "$(echo "$EXEC" | jq -c ".global_seq_num=2")" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
ok "parent and child both logged (2 lines)" '[ "$(echo "$CH2" | wc -l | tr -d " ")" = 2 ]'
CH=$(echo "$CH2" | tail -1)
ok "ParentCommandLine from cached parent exec" '[ "$(echo "$CH" | jq -r .ParentCommandLine)" = "-zsh -l" ]'
ok "ParentProcessGuid = parent ProcessGuid"   '[ "$(echo "$CH" | jq -r .ParentProcessGuid)" = "{6ABA3A9E-0000-0000-0000-000000001004}" ]'
ok "no parent seen -> ParentCommandLine absent" '[ "$(echo "$S" | jq "has(\"ParentCommandLine\")")" = false ]'
PURE=$(echo "$CFG" | jq -c '.format="sysmon"')
P=$(echo "$EXEC" | jq -n -cR --argjson cfg "$PURE" -f "$ROOT/src/scope.jq")
ok "format=sysmon has no macOS extras" '[ "$(echo "$P" | jq "has(\"SigningId\") or has(\"Uid\")")" = false ]'
ok "format=sysmon+extras has extras"   '[ "$(echo "$S" | jq "has(\"SigningId\") and (has(\"Uid\") or has(\"Hashes\") or has(\"OriginalParentProcessId\") | not)")" = true ]'
RAWCFG=$(echo "$CFG" | jq -c '.format="raw"')
R=$(echo "$EXEC" | jq -n -cR --argjson cfg "$RAWCFG" -f "$ROOT/src/scope.jq")
ok "format=raw passes eslogger JSON untouched" '[ "$(echo "$R" | jq -S -c .)" = "$(echo "$EXEC" | jq -S -c .)" ]'
D=$(echo '{"process":{"executable":{"path":"/sbin/launchd"},"is_platform_binary":true},"event":{"exec":{"target":{"executable":{"path":"/usr/libexec/xpcproxy"},"is_platform_binary":true},"args":["xpcproxy"]}}}' | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l | tr -d ' ')
ok "xpcproxy from launchd is logged too (log all)" '[ "$D" = 1 ]'
CH='{"process":{"executable":{"path":"/sbin/launchd"},"is_platform_binary":true},"event":{"exec":{"target":{"executable":{"path":"/Applications/Google Chrome.app/Contents/Frameworks/Helper"},"is_platform_binary":false,"team_id":"EQHXZ8M8AV","audit_token":{"pid":9}},"args":["Helper"]}}}'
A=$(echo "$CH" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l | tr -d ' ')
N=$(echo "$CH" | jq -n -cR --argjson cfg "$(echo "$CFG" | jq -c '.exclude=[[{field:"TeamId",op:"is",value:"EQHXZ8M8AV"}]]')" -f "$ROOT/src/scope.jq" | wc -l | tr -d ' ')
ok "vendor-signed exec (Chrome helper) logged by default"   '[ "$A" = 1 ]'
ok "[exclude] TeamId drops it"                              '[ "$N" = 0 ]'
X(){ echo "{\"process\":{\"executable\":{\"path\":\"$1\"},\"is_platform_binary\":true},\"event\":{\"exec\":{\"target\":{\"executable\":{\"path\":\"$2\"},\"is_platform_binary\":$3,\"audit_token\":{\"pid\":11}},\"args\":$4}}}"; }
# ESDaemon must not log its own binary
SELF=$(X /bin/bash /usr/local/ESDaemon/ESDaemon false '["/usr/local/ESDaemon/ESDaemon","com.apple.eslogger","events"]' | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l | tr -d ' ')
ok "ESDaemon self (ESDaemon) dropped"   '[ "$SELF" = 0 ]'
SLIM=$(echo "$EXEC" | jq -n -cR --argjson cfg "$(echo "$CFG" | jq -c '.format="slim"')" -f "$ROOT/src/scope.jq" | jq -c "has(\"rule\"), .exec.target.path")
ok "format=slim has no rule field"        '[ "$(echo $SLIM)" = "false \"/usr/bin/curl\"" ]'
# ParentCommandLine cap (parent_cmdline_max, default 1024): long parent is cut on output, short one untouched,
# 0 disables it, and [drop] rules still match the full parent command line
LONG=$(printf 'x%.0s' $(seq 1 1500))
LPAR=$(echo "$PAR" | jq -c --arg a "$LONG" '.event.exec.args=["zsh","-c",$a]')
LCH=$(printf "%s\n%s\n" "$LPAR" "$(echo "$EXEC" | jq -c ".global_seq_num=2")" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | tail -1)
ok "long ParentCommandLine capped (256 + marker)" '[ "$(echo "$LCH" | jq -r ".ParentCommandLine|length")" -lt 290 ] && echo "$LCH" | jq -r .ParentCommandLine | grep -q "…\[+"'
ok "CommandLine never capped"               '[ "$(echo "$LCH" | jq -r .CommandLine)" = "curl -o \"/tmp/a b\" https://x/y" ]'
SHORT=$(printf "%s\n%s\n" "$PAR" "$(echo "$EXEC" | jq -c ".global_seq_num=2")" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | tail -1 | jq -r .ParentCommandLine)
ok "short ParentCommandLine untouched"      '[ "$SHORT" = "-zsh -l" ]'
NOCAP=$(printf "%s\n%s\n" "$LPAR" "$(echo "$EXEC" | jq -c ".global_seq_num=2")" | jq -n -cR --argjson cfg "$(echo "$CFG" | jq -c '.parent_cmdline_max=0')" -f "$ROOT/src/scope.jq" | tail -1 | jq -r ".ParentCommandLine|length")
ok "parent_cmdline_max=0 disables cap"      '[ "$NOCAP" -gt 1500 ]'
DCFG=$(echo "$CFG" | jq -c --arg t "${LONG:1400:20}" '.exclude=[[{field:"ParentCommandLine",op:"contains",value:$t}]]')
DROPPED=$(printf "%s\n%s\n" "$LPAR" "$(echo "$EXEC" | jq -c ".global_seq_num=2")" | jq -n -cR --argjson cfg "$DCFG" -f "$ROOT/src/scope.jq" | grep -c /usr/bin/curl)
ok "[exclude] matches full ParentCommandLine past the cap" '[ "$DROPPED" = 0 ]'
BAD=$(mktemp); printf '[settings]\nparent_cmdline_max = lots\n' > "$BAD"
ok "cfg rejects non-numeric parent_cmdline_max" '! "$ROOT/bin/cfg.sh" "$BAD" json >/dev/null 2>&1'; rm -f "$BAD"
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
