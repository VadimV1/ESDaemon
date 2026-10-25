#!/bin/bash
# drop-tests.sh — [drop] (= [exclude]) syntax end to end: cfg text -> cfg.sh -> scope.jq, plus parser error cases.
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
ok "empty quoted value refused"   'bad "CommandLine contains \"\""'
ok "empty begin with refused"     'bad "Image begin with \"\" AND User is x"'
ok "empty regex refused"          'bad "CommandLine regex \"\""'
ok "empty ;-list refused"         'bad "CommandLine excludes all ;"'
ok "empty ;-list refused (quoted)" 'bad "Image is any \";;\""'
printf '[drop]\nImage is any ;/bin/sh;\n' > "$T/e.cfg"
ok "stray ; in a list still ok"   '"$ROOT/bin/cfg.sh" "$T/e.cfg" json >/dev/null'
printf '[drop]\nCommandLine contains cut and paste AND Image is /bin/sh\n' > "$T/a.cfg"
ok "lowercase and stays in value"  '[ "$("$ROOT/bin/cfg.sh" "$T/a.cfg" json | jq -r ".exclude[0][0].value")" = "cut and paste" ]'
printf '[drop]\nCommandLine contains " AND " AND Image is /bin/sh\n' > "$T/q.cfg"
ok "quoted value may contain AND"  '[ "$("$ROOT/bin/cfg.sh" "$T/q.cfg" json | jq -r ".exclude[0][0].value")" = " AND " ]'
echo "-- every condition x field, one rule per case (event is kept unless the rule drops it)"
# Foo is third-party, so it is kept by rule 6 unless the [drop] rule matches. CommandLine renders as: Foo --sync a;b it's C:\x
BS='C:\x'; SQ="it's"
FOO="$(jq -cn --arg bs "$BS" --arg sq "$SQ" '{process:{executable:{path:"/sbin/launchd"},is_platform_binary:true,audit_token:{pid:1}},event:{exec:{target:{executable:{path:"/Applications/Foo.app/Contents/MacOS/Foo"},is_platform_binary:false,team_id:"ABCDE12345",signing_id:"com.foo.agent",audit_token:{pid:9,euid:501},ppid:1},args:["Foo","--sync","a;b",$sq,$bs],env:["USER=alice"]}}}')"
BARE="$(jq -cn '{process:{executable:{path:"/sbin/launchd"},is_platform_binary:true,audit_token:{pid:1}},event:{exec:{target:{executable:{path:"/Applications/Foo.app/Contents/MacOS/Foo"},is_platform_binary:false,audit_token:{pid:9,euid:501},ppid:1},args:["Foo"],env:[]}}}')"
# c <DROP|KEEP> <rule> [event]
c(){ printf '[drop]\n%s\n' "$2" > "$T/c.cfg"; local cfg n got
  cfg="$("$ROOT/bin/cfg.sh" "$T/c.cfg" json 2>/dev/null | jq -c ".users={\"501\":\"alice\"}")" || { fail=$((fail+1)); echo "  FAIL refused: $2"; return; }
  n=$(printf '%s\n' "${3:-$FOO}" | jq -n -cR --argjson cfg "$cfg" -f "$ROOT/src/scope.jq" | grep -vc eslogger_scoped_gap)
  got=$([ "$n" = 0 ] && echo DROP || echo KEEP)
  if [ "$got" = "$1" ]; then pass=$((pass+1)); echo "  ok   $got $2"; else fail=$((fail+1)); echo "  FAIL want $1 got $got: $2"; fi; }
c KEEP 'User is nobody'
c DROP 'image is /APPLICATIONS/foo.app/contents/macos/FOO'
c KEEP 'Image is /Applications/Foo.app/Contents/MacOS'
c DROP 'Image is not /bin/sh';                    c KEEP 'Image is not /Applications/Foo.app/Contents/MacOS/Foo'
c DROP 'Image is any /bin/sh;/Applications/Foo.app/Contents/MacOS/Foo'; c KEEP 'Image is any /bin/sh;/bin/zsh'
c DROP 'CommandLine contains --SYNC';             c KEEP 'CommandLine contains --push'
c DROP 'CommandLine contains any nope;--sync';    c KEEP 'CommandLine contains any nope;nada'
c DROP 'CommandLine contains all foo;--sync';     c KEEP 'CommandLine contains all foo;nope'
c DROP 'CommandLine excludes nope';               c KEEP 'CommandLine excludes --sync'
c DROP 'CommandLine excludes any --sync;nope';    c KEEP 'CommandLine excludes any --sync;foo'
c DROP 'CommandLine excludes all x1;x2';          c KEEP 'CommandLine excludes all x1;--sync'
c DROP 'Image begin with /applications/foo.app/'; c KEEP 'Image begin with /usr/'
c DROP 'Image not begin with /usr/';              c KEEP 'Image not begin with /Applications/'
c DROP 'Image end with /MacOS/foo';               c KEEP 'Image end with /MacOS/Bar'
c DROP 'Image not end with /Bar';                 c KEEP 'Image not end with /foo'
c DROP 'Image image FOO';                         c KEEP 'Image image Foo.app'
c DROP 'Image image /Applications/Foo.app/Contents/MacOS/Foo'
c DROP 'CommandLine regex ^foo --sync';           c KEEP 'CommandLine regex ^--sync'
c DROP 'ParentImage image launchd';               c DROP 'ParentImage is /SBIN/launchd'
c DROP 'User is ALICE';                           c KEEP 'User is bob'
c DROP 'TeamId is abcde12345';                    c DROP 'SigningId begin with COM.foo.'
c DROP 'Image image foo AND TeamId is ABCDE12345 AND User is alice'
c KEEP 'Image image foo AND TeamId is ABCDE12345 AND User is bob'
c DROP 'CommandLine contains "a;b"';              c DROP "CommandLine contains $SQ"
c DROP 'CommandLine contains C:\x';               c DROP 'CommandLine end with "C:\x"'
c DROP 'image  IS   /Applications/Foo.app/Contents/MacOS/Foo'
echo "-- missing fields never drop, even with negative conditions"
c KEEP 'ParentCommandLine is not x';              c KEEP 'ParentCommandLine excludes x'
c KEEP 'ParentCommandLine not begin with x';      c KEEP 'TeamId is not x' "$BARE"
c KEEP 'SigningId not end with x' "$BARE";        c KEEP 'TeamId excludes all a;b' "$BARE"
c KEEP 'TeamId regex .' "$BARE"
echo "-- ParentCommandLine from a parent exec seen earlier"
PAR="$(jq -cn '{process:{executable:{path:"/sbin/launchd"},is_platform_binary:true,audit_token:{pid:1}},event:{exec:{target:{executable:{path:"/usr/local/bin/munki"},is_platform_binary:true,audit_token:{pid:9},ppid:1},args:["/usr/local/bin/munki","--auto"]}}}')"
KID="$(jq -cn '{process:{executable:{path:"/usr/local/bin/munki"},is_platform_binary:true,audit_token:{pid:9}},event:{exec:{target:{executable:{path:"/usr/bin/curl"},is_platform_binary:true,audit_token:{pid:10},ppid:9},args:["curl","https://x"]}}}')"
ok "cached parent cmdline -> child dropped (parent logged)" '[ "$(printf "%s\n%s\n" "$PAR" "$KID" | run)" = 1 ]'
echo "-- parser: whitespace, stray and/#, a value that swallowed another clause"
ok "tab/double space in two-word condition parsed as that condition" \
   '[ "$(printf "[drop]\nCommandLine excludes  any a;b\nImage is\tnot /x\n" > "$T/w.cfg"; "$ROOT/bin/cfg.sh" "$T/w.cfg" json | jq -c "[.exclude[][].op]")" = "[\"excludes any\",\"is not\"]" ]'
ok "lowercase and before a clause refused" 'bad "Image is not /bin/sh and User is root"'
ok "mixed-case And before a clause refused" 'bad "CommandLine excludes jamf And Image is /usr/local/bin/jamf"'
ok "trailing # comment refused"           'bad "Image not begin with /usr/ # vendor tools"'
printf '[drop]\nCommandLine contains "run # 1" AND CommandLine contains "a and Image is b"\nCommandLine contains https://x/#frag\n' > "$T/h.cfg"
ok "quoted # / and-clause, and URL #frag still ok" '"$ROOT/bin/cfg.sh" "$T/h.cfg" json >/dev/null'
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
