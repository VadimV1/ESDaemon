#!/bin/bash
# sysmon-tests.sh — format = sysmon field mapping + format = raw pass-through (synthetic events).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; pass=0; fail=0
CFG="$("$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json)"
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
EXEC='{"time":"2026-09-28T10:00:00.123456789Z","global_seq_num":1,"process":{"executable":{"path":"/bin/zsh"},"audit_token":{"pid":4242,"euid":501},"start_time":"2026-09-28T09:59:59Z","is_platform_binary":true,"signing_id":"com.apple.zsh"},"event":{"exec":{"target":{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":4242,"euid":501},"ppid":4100,"original_ppid":4100,"session_id":100,"cdhash":"abcd","signing_id":"com.apple.curl","team_id":null,"is_platform_binary":true},"args":["curl","-o","/tmp/a b","https://x/y"],"cwd":{"path":"/Users/a"},"env":["USER=alice","PATH=/usr/bin"]}}}'
S=$(echo "$EXEC" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq"); echo "  $S"
ok "EventID 1 ProcessCreate"          '[ "$(echo "$S" | jq -r ".EventID,.EventType" | tr "\n" " ")" = "1 ProcessCreate " ]'
ok "Image / ParentImage"              '[ "$(echo "$S" | jq -r ".Image+\"|\"+.ParentImage")" = "/usr/bin/curl|/bin/zsh" ]'
ok "CommandLine quotes arg w/ space"  '[ "$(echo "$S" | jq -r .CommandLine)" = "curl -o \"/tmp/a b\" https://x/y" ]'
ok "UtcTime Sysmon format (ms)"       '[ "$(echo "$S" | jq -r .UtcTime)" = "2026-09-28 10:00:00.123" ]'
ok "User from env, pids, cwd"         '[ "$(echo "$S" | jq -r "[.User,.ProcessId,.ParentProcessId,.CurrentDirectory]|join(\",\")")" = "alice,4242,4100,/Users/a" ]'
ok "Hashes=CDHASH, signing extras"    '[ "$(echo "$S" | jq -r "[.Hashes,.SigningId,(.IsPlatformBinary|tostring)]|join(\",\")")" = "CDHASH=abcd,com.apple.curl,true" ]'
ok "no null fields emitted"           '[ "$(echo "$S" | jq "[.[]|select(.==null)]|length")" = 0 ]'
F='{"time":"2026-09-28T10:00:01Z","process":{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":7,"euid":0},"is_platform_binary":true},"event":{"create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"/Users/a/Library/LaunchAgents"},"filename":"x.plist"}}}}}'
S2=$(echo "$F" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
ok "create -> EventID 11 TargetFilename" '[ "$(echo "$S2" | jq -r "[.EventID,.TargetFilename,.Image]|map(tostring)|join(\",\")")" = "11,/Users/a/Library/LaunchAgents/x.plist,/usr/bin/curl" ]'
# parent chain: zsh exec (dropped by filter, but cached) then its child curl -> ParentCommandLine filled
PAR='{"time":"2026-09-28T09:59:59Z","global_seq_num":1,"process":{"executable":{"path":"/usr/bin/login"},"audit_token":{"pid":4100},"start_time":"2026-09-28T09:59:58Z","is_platform_binary":true},"event":{"exec":{"target":{"executable":{"path":"/bin/zsh"},"audit_token":{"pid":4100,"euid":501},"ppid":1,"is_platform_binary":true},"args":["-zsh","-l"]}}}'
CH=$(printf "%s\n%s\n" "$PAR" "$(echo "$EXEC" | jq -c ".global_seq_num=2")" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
ok "parent exec dropped, child kept (1 line)" '[ "$(echo "$CH" | wc -l)" = 1 ]'
ok "ParentCommandLine from cached parent exec" '[ "$(echo "$CH" | jq -r .ParentCommandLine)" = "-zsh -l" ]'
ok "ParentProcessGuid = parent ProcessGuid"   '[ "$(echo "$CH" | jq -r .ParentProcessGuid)" = "{4100-2026-09-28T09:59:58Z}" ]'
ok "no parent seen -> ParentCommandLine absent" '[ "$(echo "$S" | jq "has(\"ParentCommandLine\")")" = false ]'
PURE=$(echo "$CFG" | jq -c '.format="sysmon"')
P=$(echo "$EXEC" | jq -n -cR --argjson cfg "$PURE" -f "$ROOT/src/scope.jq")
ok "format=sysmon has no macOS extras" '[ "$(echo "$P" | jq "has(\"SigningId\") or has(\"Uid\")")" = false ]'
ok "format=sysmon+extras has extras"   '[ "$(echo "$S" | jq "has(\"SigningId\") and has(\"Uid\")")" = true ]'
RAWCFG=$(echo "$CFG" | jq -c '.format="raw"')
R=$(echo "$EXEC" | jq -n -cR --argjson cfg "$RAWCFG" -f "$ROOT/src/scope.jq")
ok "format=raw passes eslogger JSON untouched" '[ "$(echo "$R" | jq -S -c .)" = "$(echo "$EXEC" | jq -S -c .)" ]'
D=$(echo '{"process":{"executable":{"path":"/sbin/launchd"},"is_platform_binary":true},"event":{"exec":{"target":{"executable":{"path":"/usr/libexec/xpcproxy"},"is_platform_binary":true},"args":["xpcproxy"]}}}' | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l)
ok "filtering still applies in sysmon mode" '[ "$D" = 0 ]'
CH='{"process":{"executable":{"path":"/sbin/launchd"},"is_platform_binary":true},"event":{"exec":{"target":{"executable":{"path":"/Applications/Google Chrome.app/Contents/Frameworks/Helper"},"is_platform_binary":false,"team_id":"EQHXZ8M8AV","audit_token":{"pid":9}},"args":["Helper"]}}}'
A=$(echo "$CH" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l)
N=$(echo "$CH" | jq -n -cR --argjson cfg "$(echo "$CFG" | jq -c '.third_party="drop_noisy"')" -f "$ROOT/src/scope.jq" | wc -l)
ok "third_party=all keeps vendor-signed exec (Chrome helper)" '[ "$A" = 1 ]'
ok "third_party=drop_noisy drops it"                         '[ "$N" = 0 ]'
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
