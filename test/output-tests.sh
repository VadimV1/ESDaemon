#!/bin/bash
# output-tests.sh — output correctness on eslogger shapes seen on macOS 26 (key order, pidversion, exec chains) and
# hostile input (quoting, huge argv, regex blow-up, odd events). Synthetic, modelled on real captures.
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; pass=0; fail=0
CFG="$("$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json | jq -c '.users = {"501": "alice"}')"
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
run(){ jq -n -cR --argjson cfg "${2:-$CFG}" -f "$ROOT/src/scope.jq" <<< "$1"; }
fmt(){ echo "$CFG" | jq -c --arg f "$1" '.format = $f'; }
P='{"executable":{"path":"/bin/rm"},"audit_token":{"pid":7,"euid":501},"start_time":"2026-09-28T09:00:00.000001Z","is_platform_binary":true}'

echo "-- FileDelete names the deleted file whatever the key order (real unlink = {target, parent_dir})"
U1="{\"time\":\"2026-09-28T10:00:00.5Z\",\"process\":$P,\"event\":{\"unlink\":{\"target\":{\"path\":\"/private/tmp/qa/x.plist\"},\"parent_dir\":{\"path\":\"/private/tmp/qa\"}}}}"
U2="{\"time\":\"2026-09-28T10:00:00.5Z\",\"process\":$P,\"event\":{\"unlink\":{\"parent_dir\":{\"path\":\"/private/tmp/qa\"},\"target\":{\"path\":\"/private/tmp/qa/x.plist\"}}}}"
ok "unlink target first -> TargetFilename = file"   '[ "$(run "$U1" | jq -r .TargetFilename)" = /private/tmp/qa/x.plist ]'
ok "unlink parent_dir first -> TargetFilename = file" '[ "$(run "$U2" | jq -r .TargetFilename)" = /private/tmp/qa/x.plist ]'
R1="{\"time\":\"t\",\"process\":$P,\"event\":{\"rename\":{\"destination\":{\"existing_file\":{\"path\":\"/Library/LaunchDaemons/a.plist\"}},\"destination_type\":0,\"source\":{\"path\":\"/private/tmp/a\"}}}}"
ok "rename onto existing file, destination first" '[ "$(run "$R1" | jq -r "[.TargetFilename,.SourceFilename]|join(\",\")")" = "/Library/LaunchDaemons/a.plist,/private/tmp/a" ]'
# live repro (marker kaifile1790637497): mv com.X.plist com.X.renamed.plist in LaunchAgents gave SourceFilename = the directory
R2="{\"time\":\"t\",\"process\":$P,\"event\":{\"rename\":{\"destination_type\":1,\"destination\":{\"new_path\":{\"dir\":{\"path\":\"/Users/a/Library/LaunchAgents\"},\"filename\":\"com.x.renamed.plist\"}},\"source\":{\"path\":\"/Users/a/Library/LaunchAgents/com.x.plist\"}}}}"
ok "rename to new_path, destination first -> Source = old file, not its dir" '[ "$(run "$R2" | jq -r "[.TargetFilename,.SourceFilename]|join(\",\")")" = "/Users/a/Library/LaunchAgents/com.x.renamed.plist,/Users/a/Library/LaunchAgents/com.x.plist" ]'
R3=$(echo "$R2" | jq -c '.event.rename = {source: .event.rename.source, destination_type: 1, destination: .event.rename.destination}')
ok "rename to new_path, source first -> same result" '[ "$(run "$R3" | jq -r "[.TargetFilename,.SourceFilename]|join(\",\")")" = "/Users/a/Library/LaunchAgents/com.x.renamed.plist,/Users/a/Library/LaunchAgents/com.x.plist" ]'
# real macOS 26.7 create/rename/unlink events (stat blocks removed), key orders as eslogger emitted them:
# every kept record must name exactly the ES target/destination and rename source, by field. The raw-format run of the
# same input keeps the same events in the same order, so its lines give the expected values for the sysmon lines.
FX="$ROOT/test/fixtures/file-events-macos26.ndjson"
REAL=$(jq -c -n --slurpfile out <(jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" < "$FX") \
  --slurpfile raw <(jq -n -cR --argjson cfg "$(fmt raw)" -f "$ROOT/src/scope.jq" < "$FX") '
  ($raw | map(select(.event))) as $raw | ($out | map(select(.EventID == 11 or .EventID == 23 or .EventID == 103))) as $out   # skip gap markers
  | [$raw[] | (.event | keys[0]) as $ev | .event[$ev] as $e
    | {t: (if $ev == "unlink" then $e.target.path else ($e.destination | if .existing_file then .existing_file.path
           else (.new_path.dir.path | rtrimstr("/")) + "/" + .new_path.filename end) end),
       s: (if $ev == "rename" then $e.source.path else null end)}] as $want
  | {n: ($out | length), same: (($raw | length) == ($out | length)),
     bad: [range(0; $out | length) as $i | select($out[$i].TargetFilename != $want[$i].t or $out[$i].SourceFilename != $want[$i].s)] | length}')
ok "real macOS 26 file events, mixed key orders: every Target/Source exact" '[ "$(echo "$REAL" | jq -c "[.n >= 20, .same, .bad]")" = "[true,true,0]" ]'
C1="{\"time\":\"t\",\"process\":$P,\"event\":{\"create\":{\"destination\":{\"new_path\":{\"filename\":\"evil.plist\",\"dir\":{\"path\":\"/Users/a/Library/LaunchAgents\"}}},\"destination_type\":1,\"acl\":null}}}"
ok "create new_path, filename before dir"      '[ "$(run "$C1" | jq -r .TargetFilename)" = /Users/a/Library/LaunchAgents/evil.plist ]'

echo "-- User is the account of the euid, never the USER env var (attacker-set)"
X(){ jq -cn --arg u "$1" '{time:"2026-09-28T10:00:00.1Z",process:{executable:{path:"/bin/zsh"},audit_token:{pid:50,euid:501},start_time:"s",is_platform_binary:true},
  event:{exec:{target:{executable:{path:"/usr/bin/curl"},audit_token:{pid:50,euid:501},ppid:1,is_platform_binary:true},args:["curl","-V"],env:["USER=\($u)"]}}}'; }
ok "env USER=svc_fake does not become User"     '[ "$(run "$(X svc_fake)" | jq -r .User)" = alice ]'
ok "unknown uid -> uid:N"                       '[ "$(run "$(X svc_fake)" "$(echo "$CFG" | jq -c ".users={}")" | jq -r .User)" = uid:501 ]'
DU=$(echo "$CFG" | jq -c '.exclude=[[{field:"User",op:"is",value:"svc_fake"},{field:"Image",op:"image",value:"curl"}]]')
ok "[drop] User rule cannot be triggered via env" '[ "$(run "$(X svc_fake)" "$DU" | wc -l | tr -d " ")" = 1 ]'

echo "-- ParentImage is the parent process, not the previous image of the same pid (exec chains)"
# bash(100) forks+execs sh(200) which then execs curl in place (sh -c 'exec curl'), as captured on macOS 26
E(){ jq -cn --argjson pid $1 --argjson pv $2 --arg pimg "$3" --arg timg "$4" --argjson ppid $5 --argjson ppv $6 --argjson args "$7" \
  '{time:"2026-09-28T10:00:00.2Z",process:{executable:{path:$pimg},audit_token:{pid:$pid,euid:501,pidversion:($pv-1)},start_time:"2026-09-28T09:00:00.\($pid)Z",is_platform_binary:true,signing_id:"p"},
    event:{exec:{target:{executable:{path:$timg},audit_token:{pid:$pid,euid:501,pidversion:$pv},parent_audit_token:{pid:$ppid,pidversion:$ppv},ppid:$ppid,is_platform_binary:true,signing_id:"t"},args:$args}}}'; }
BASH=$(E 100 10 /usr/bin/login /bin/bash 1 1 '["bash","./run.sh"]')
SH=$(E 200 20 /bin/bash /bin/sh 100 10 '["sh","-c","exec curl -V"]')
CURL=$(E 200 21 /bin/sh /usr/bin/curl 100 10 '["curl","-V"]')
O=$(printf '%s\n%s\n%s\n' "$BASH" "$SH" "$CURL" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | jq -c 'select(.Image == "/usr/bin/curl")')
ok "exec chain: ParentImage from parent's own exec" '[ "$(echo "$O" | jq -r .ParentImage)" = /bin/bash ]'
ok "exec chain: Parent fields describe one process"  '[ "$(echo "$O" | jq -r "[.ParentProcessId,.ParentCommandLine,.ParentProcessGuid]|map(tostring)|join(\",\")")" = "100,bash ./run.sh,{6ABA2C90-0001-86A0-0000-000000000064}" ]'
O2=$(printf '%s\n%s\n' "$SH" "$CURL" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | jq -c 'select(.Image == "/usr/bin/curl")')
ok "exec chain, parent unseen: ParentImage left out (not the old image /bin/sh)" '[ "$(echo "$O2" | jq "has(\"ParentImage\")")" = false ]'
FORK=$(E 300 30 /bin/bash /usr/bin/curl 100 10 '["curl","-V"]')
O3=$(printf '%s\n' "$FORK" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
ok "plain fork+exec, parent unseen: ParentImage from .process" '[ "$(echo "$O3" | jq -r .ParentImage)" = /bin/bash ]'

echo "-- a reused pid does not lend its old command line to a new child (pidversion)"
JAMF=$(E 100 10 /usr/bin/login /usr/libexec/jamfagent 1 1 '["jamf","policy"]')
CHILD=$(E 400 40 /bin/zsh /usr/bin/curl 100 77 '["curl","-V"]')
O4=$(printf '%s\n%s\n' "$JAMF" "$CHILD" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | tail -1)
ok "pidversion mismatch -> no ParentCommandLine / ParentProcessGuid" '[ "$(echo "$O4" | jq "has(\"ParentCommandLine\") or has(\"ParentProcessGuid\")")" = false ]'
DJ=$(echo "$CFG" | jq -c '.exclude=[[{field:"ParentCommandLine",op:"is",value:"jamf policy"}]]')
ok "stale parent cannot trigger an [exclude] rule"  '[ "$(printf "%s\n%s\n" "$JAMF" "$CHILD" | jq -n -cR --argjson cfg "$DJ" -f "$ROOT/src/scope.jq" | grep -c /usr/bin/curl)" = 1 ]'

echo "-- CommandLine: CommandLineToArgvW quoting, one string per argv"
cl(){ jq -cn --argjson a "$1" '{time:"t",process:{executable:{path:"/bin/zsh"},audit_token:{pid:9}},event:{exec:{target:{executable:{path:"/usr/bin/curl"},audit_token:{pid:9},is_platform_binary:true},args:$a}}}' \
  | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | jq -r .CommandLine; }
ok 'empty arg kept as ""'                  '[ "$(cl "[\"curl\",\"\",\"x\"]")" = "curl \"\" x" ]'
ok 'backslash before quote doubled'        '[ "$(cl "[\"curl\",\"q\\\\\\\"x\"]")" = "curl \"q\\\\\\\"x\"" ]'
ok 'trailing backslash in quoted arg doubled' '[ "$(cl "[\"curl\",\"a b\\\\\"]")" = "curl \"a b\\\\\"" ]'
ok 'lone backslash unquoted stays literal' '[ "$(cl "[\"curl\",\"c\\\\d\"]")" = "curl c\\d" ]'
ok 'backslash before a newline not doubled' '[ "$(cl "[\"curl\",\"a b\\\\\\n\"]" | head -1)" = "curl \"a b\\" ]'
ok 'newline arg is quoted'                '[ "$(cl "[\"curl\",\"a\\nb\"]" | head -1)" = "curl \"a" ]'
# ca <arg>...: the CommandLine of curl run with these arguments; b <n>: n backslashes
ca(){ cl "$(jq -cn '["curl"] + $ARGS.positional' --args "$@")"; }
b(){ printf '%*s' "$1" '' | tr ' ' '\\'; }
ok 'n backslashes before a quote: 2n+1, then the quote' '[ "$(ca "a$(b 2)\"b c")" = "curl \"a$(b 5)\"b c\"" ]'
ok 'trailing backslashes of a quoted arg doubled'    '[ "$(ca "a b$(b 3)")" = "curl \"a b$(b 6)\"" ]'
ok 'backslashes before a space untouched'            '[ "$(ca "a$(b 2) b")" = "curl \"a$(b 2) b\"" ]'
ok 'only the run before each quote doubled'          '[ "$(ca "x$(b 2)y$(b 3)\"z w$(b 1)")" = "curl \"x$(b 2)y$(b 7)\"z w$(b 2)\"" ]'
ok 'run at the start, before a quote'                '[ "$(ca "$(b 3)\"x y")" = "curl \"$(b 7)\"x y\"" ]'
ok 'nothing but backslashes between two quotes'      '[ "$(ca "\"$(b 4)\"")" = "curl \"$(b 1)\"$(b 9)\"\"" ]'
ok 'adjacent quotes, one backslash between quotes'   '[ "$(ca "a\"\"$(b 1)\"b")" = "curl \"a$(b 1)\"$(b 1)\"$(b 3)\"b\"" ]'
ok 'long runs: 37 trailing, 100 before a quote'      '[ "$(ca "a b$(b 37)" "x$(b 100)\"y")" = "curl \"a b$(b 74)\" \"x$(b 201)\"y\"" ]'
ok 'non-ASCII before a trailing run'                 '[ "$(ca "é 中$(b 3)")" = "curl \"é 中$(b 6)\"" ]'
ok 'empty, quote-only and plain args side by side'   '[ "$(ca "" "\"" "a b" c)" = "curl \"\" \"$(b 1)\"\" \"a b\" c" ]'

echo "-- records fit the unified log (32759-byte message limit) and stay valid JSON"
BIG=$(jq -cn '{time:"2026-09-28T10:00:00.3Z",process:{executable:{path:"/bin/zsh"},audit_token:{pid:9,euid:501},is_platform_binary:true},
  event:{exec:{target:{executable:{path:"/usr/bin/curl"},audit_token:{pid:9,euid:501},is_platform_binary:true},args:["curl","-V",("A" * 100000),"http://evil.example/x"],env:["USER=x"]}}}')
for f in sysmon sysmon+extras slim raw; do
  B=$(run "$BIG" "$(fmt $f)")
  ok "100 KB argv, format=$f: <= 32000 bytes, valid JSON" '[ "$(printf %s "$B" | wc -c | tr -d " ")" -le 32000 ] && echo "$B" | jq -e . >/dev/null'
done
B=$(run "$BIG")
ok "cut keeps head and tail of CommandLine, marks the cut" 'echo "$B" | jq -e ".CommandLine | startswith(\"curl -V AAA\") and endswith(\"http://evil.example/x\") and test(\"…\\\\[\\\\+[0-9]+ chars\\\\]…\")" >/dev/null'
ok "cut record keeps Image and EventID"    '[ "$(echo "$B" | jq -r "[.Image,.EventID]|map(tostring)|join(\",\")")" = "/usr/bin/curl,1" ]'
MANY=$(echo "$BIG" | jq -c '.event.exec.args = ["curl"] + [range(0; 20000) | "ab\u0001"]')
ok "20000 small args (control chars): fits, valid JSON" 'M=$(run "$MANY" "$(fmt slim)"); [ "$(printf %s "$M" | wc -c | tr -d " ")" -le 32000 ] && echo "$M" | jq -e .exec.args >/dev/null'
SMALL=$(echo "$BIG" | jq -c '.event.exec.args = ["curl","-V"]')
ok "small record untouched by the size limit" '[ "$(run "$SMALL" | jq -r .CommandLine)" = "curl -V" ]'

echo "-- hostile argv cannot stall the filter (regex blow-up)"
PY=$(jq -cn '{time:"t",process:{executable:{path:"/bin/zsh"},audit_token:{pid:9},is_platform_binary:true},
  event:{exec:{target:{executable:{path:"/bin/sh"},audit_token:{pid:9},is_platform_binary:true},args:["sh","-c",("python " * 100000)]}}}')
t0=$SECONDS; n=$(run "$PY" | wc -l | tr -d ' '); dt=$((SECONDS - t0))
ok "700 KB 'python python ...' argv processed in < 10 s, logged" '[ $dt -lt 10 ] && [ "$n" = 1 ]'
# quoting an argument takes time linear in its length, whatever it holds (it grew with the square of the length)
BS=$(echo "$PY" | jq -c '.event.exec.args = ["sh", "-c", "\\" * 65536 + "\"x", "\\" * 131072 + " x"]')
t0=$SECONDS; R=$(run "$BS"); dt=$((SECONDS - t0))
ok "backslash runs of 64 and 128 KB quoted in < 10 s, logged" '[ $dt -lt 10 ] && [ "$(echo "$R" | jq -r .EventType)" = ProcessStart ]'
QS=$(echo "$PY" | jq -c '.event.exec.args = ["sh", "-c", "\"" * 131072, "x\\\\\\\"" * 65536]')
t0=$SECONDS; R=$(run "$QS"); dt=$((SECONDS - t0))
ok "128k quotes, and 64k backslash runs before quotes, quoted in < 10 s, logged" '[ $dt -lt 10 ] && [ "$(echo "$R" | jq -r .EventType)" = ProcessStart ]'
# argv element count is capped (args_max) so a huge count can't stall the serial filter; the record is marked
# 5000 args renders under record_max so the cap, not the size-cut, is what we are testing
MANYARGS=$(jq -cn '{time:"t",process:{executable:{path:"/bin/zsh"},audit_token:{pid:9},is_platform_binary:true},
  event:{exec:{target:{executable:{path:"/usr/bin/curl"},audit_token:{pid:9},is_platform_binary:true,ppid:9,original_ppid:9},args:(["curl"]+[range(0;5000)|tostring])}}}')
ok "argv count capped at args_max with a marker" '[ "$(run "$MANYARGS" "$(echo "$CFG"|jq -c ".args_max=4096")" | jq -r ".CommandLine | (test(\"…\\\\[\\\\+905 args\\\\]\") and ((split(\" \")|length) <= 4100) and ((split(\" \")|length) >= 4096))")" = true ]'
ok "args_max=0 disables the cap (full argv rendered)" '[ "$(run "$MANYARGS" "$(echo "$CFG"|jq -c ".args_max=0")" | jq -r ".CommandLine | (split(\" \")|length)")" = 5001 ]'
# a malformed (regex-valid but impossible) start_time must not crash the stream: the event after it still emits
BADTS=$(jq -cn '{time:"t",global_seq_num:1,process:{executable:{path:"/bin/zsh"},audit_token:{pid:9},is_platform_binary:true},event:{exec:{target:{executable:{path:"/usr/bin/curl"},audit_token:{pid:9},ppid:9,original_ppid:9,start_time:"2026-13-45T99:99:99Z"},args:["curl","bad"]}}}')
NEXT=$(jq -cn '{time:"t",global_seq_num:2,process:{executable:{path:"/bin/zsh"},audit_token:{pid:9},is_platform_binary:true},event:{exec:{target:{executable:{path:"/usr/bin/curl"},audit_token:{pid:9},ppid:9,original_ppid:9},args:["curl","after"]}}}')
ok "malformed start_time does not abort the stream (both events emit)" '[ "$(printf "%s\n%s\n" "$BADTS" "$NEXT" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | jq -rc .CommandLine | tr "\n" ",")" = "curl bad,curl after," ]'

echo "-- schema consistency"
g(){ jq -cn --argjson s $1 '{time:"2026-09-28T10:00:0\($s).000000009Z",global_seq_num:$s,process:{executable:{path:"/sbin/launchd"},is_platform_binary:true},
  event:{exec:{target:{executable:{path:"/usr/libexec/xpcproxy"},is_platform_binary:true},args:["xpcproxy"]}}}'; }
GAP=$( (g 1; g 5) | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | grep eslogger_scoped_gap)
ok "gap marker in sysmon format has Sysmon envelope" '[ "$(echo "$GAP" | jq -r "[.EventID,.EventType,.UtcTime,.eslogger_scoped_gap]|map(tostring)|join(\",\")")" = "255,eslogger_scoped_gap,2026-09-28 10:00:05.000,3" ] && [ "$(echo "$GAP" | jq -r "[.EventType,has(\"Channel\")]|map(tostring)|join(\",\")")" = "eslogger_scoped_gap,false" ]'
ok "UtcTime without fraction still has .mmm" '[ "$(run "$(echo "$SMALL" | jq -c ".time=\"2026-09-28T10:00:00Z\"")" | jq -r .UtcTime)" = "2026-09-28 10:00:00.000" ]'
ok "UtcTime with 1 fractional digit padded"  '[ "$(run "$(echo "$SMALL" | jq -c ".time=\"2026-09-28T10:00:00.5Z\"")" | jq -r .UtcTime)" = "2026-09-28 10:00:00.500" ]'
ok "format=slim emits no null in exec block" '[ "$(run "$SMALL" "$(fmt slim)" | jq "[.exec | paths(. == null)] | length")" = 0 ]'
ok "no OriginalFileName invented from the (renamable) path" '[ "$(run "$SMALL" | jq "has(\"OriginalFileName\")")" = false ]'
ODD=$(printf '%s\n%s\n' '{"time":"t","event":{}}' "$SMALL" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
ok "an event the filter chokes on is reported, the next one still processed" '[ "$(echo "$ODD" | head -1 | jq -r "has(\"esd_filter_error\")")" = true ] && [ "$(echo "$ODD" | tail -1 | jq -r .Image)" = /usr/bin/curl ]'
# a record that cannot be built (forced: cwd is a string, not {path}) leaves a marker that still names the event, shaped
# for the format; raw, which never reads cwd, logs the event itself, saying the rules could not read it
NOREC=$(jq -cn '{time:"2026-09-28T10:00:01Z",process:{executable:{path:"/bin/zsh"},audit_token:{pid:51,euid:501}},
  event:{exec:{target:{executable:{path:"/usr/bin/curl"},audit_token:{pid:51,euid:501},ppid:100},args:["curl","-V"],cwd:"/tmp"}}}')
ok "record that cannot be built: marker names the event, with the Sysmon envelope" '[ "$(run "$NOREC" | jq -c "[.EventID,.EventType,.UtcTime,.EventKind,.User,.Image,.ProcessId,(.esd_filter_error | length > 0)]")" = "[255,\"esd_filter_error\",\"2026-09-28 10:00:01.000\",\"exec\",\"alice\",\"/usr/bin/curl\",51,true]" ]'
ok "same in slim: the marker without an envelope"  '[ "$(run "$NOREC" "$(fmt slim)" | jq -c "[has(\"EventID\"),.EventKind,.User,.Image,.ProcessId]")" = "[false,\"exec\",\"alice\",\"/usr/bin/curl\",51]" ]'
ok "same in raw: the event itself, with the error" '[ "$(run "$NOREC" "$(fmt raw)" | jq -c "[.event.exec.target.executable.path, (.esd_rule_error | length > 0)]")" = "[\"/usr/bin/curl\",true]" ]'
AROUND=$(printf '%s\n%s\n%s\n' "$BASH" "$NOREC" "$CURL" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | jq -r '[.EventType, .Image, .ParentCommandLine] | join(",")' | tr "\n" ";")
ok "events around it unaffected, the parent cache too" '[ "$AROUND" = "ProcessStart,/bin/bash,;esd_filter_error,/usr/bin/curl,;ProcessStart,/usr/bin/curl,bash ./run.sh;" ]'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
