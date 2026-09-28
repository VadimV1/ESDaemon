#!/bin/bash
# file-tests.sh — keep/drop for create/rename events (synthetic, ES create/rename shape). Also checks pass-through events.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/.."; CFG="$("$ROOT/bin/cfg.sh" "$ROOT/test/fixtures/slim.cfg" json)"; pass=0; fail=0
P='{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":1},"is_platform_binary":true}'
newp() { echo "{\"time\":\"t\",\"process\":$P,\"event\":{\"create\":{\"destination_type\":1,\"destination\":{\"new_path\":{\"dir\":{\"path\":\"$1\"},\"filename\":\"$2\",\"mode\":420}}}}}"; }
exist() { echo "{\"time\":\"t\",\"process\":$P,\"event\":{\"create\":{\"destination_type\":0,\"destination\":{\"existing_file\":{\"path\":\"$1\",\"stat\":{}}}}}}"; }
ren() { echo "{\"time\":\"t\",\"process\":$P,\"event\":{\"rename\":{\"source\":{\"path\":\"$1\"},\"destination_type\":1,\"destination\":{\"new_path\":{\"dir\":{\"path\":\"$2\"},\"filename\":\"$3\"}}}}}"; }
t() { local want=$1 name=$2 line=$3; local g=$([ "$(echo "$line" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l | tr -d ' ')" = 1 ] && echo KEEP || echo DROP)
  [ "$g" = "$want" ] && { pass=$((pass+1)); printf "  ok   %-4s %s\n" $g "$name"; } || { fail=$((fail+1)); printf "  FAIL want %s got %s %s\n" $want $g "$name"; }; }
t KEEP "LaunchAgent plist created"     "$(newp /Users/a/Library/LaunchAgents com.evil.plist)"
t KEEP "ccache in /tmp"                "$(newp /tmp krb5cc_501.ccache)"
t KEEP "keychain copied to tmp"        "$(newp /private/tmp login.keychain-db)"
t KEEP "loginwindow.plist written"     "$(exist /Library/Preferences/com.apple.loginwindow.plist)"
t KEEP "litellm .pth persistence"      "$(newp /usr/lib/python3.12/site-packages litellm_init.pth)"
t KEEP "rename into LaunchDaemons"     "$(ren /tmp/x /Library/LaunchDaemons com.x.plist)"
t KEEP "hidden App Support drop"       "$(newp "/Users/a/Library/Application Support/.hidden" agent)"
t DROP "document saved"                "$(newp /Users/a/Documents report.docx)"
t DROP "app cache write"               "$(newp /Users/a/Library/Caches/com.spotify.client cache.db)"
t DROP "var/folders temp"              "$(newp /private/var/folders/xy/T tmp123)"
t KEEP "btm_launch_item_add passthrough" "{\"time\":\"t\",\"process\":$P,\"event\":{\"btm_launch_item_add\":{\"item\":{\"item_url\":\"x\"}}}}"
t KEEP "xp_malware_detected passthrough" "{\"time\":\"t\",\"process\":$P,\"event\":{\"xp_malware_detected\":{\"malware_identifier\":\"x\"}}}"
mk(){ echo "{\"time\":\"t$1\",\"global_seq_num\":$1,\"process\":{\"executable\":{\"path\":\"/sbin/launchd\"},\"is_platform_binary\":true},\"event\":{\"exec\":{\"target\":{\"executable\":{\"path\":\"/usr/libexec/xpcproxy\"},\"is_platform_binary\":true},\"args\":[\"xpcproxy\"]}}}"; }
g=$( (mk 1; mk 2; mk 5) | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
[ "$g" = '{"eslogger_scoped_gap":2,"time":"t5","after_global_seq_num":5}' ] && { pass=$((pass+1)); echo "  ok   ES drop (seq 2->5) emits gap marker, dropped events stay dropped"; } || { fail=$((fail+1)); echo "  FAIL gap: $g"; }
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
