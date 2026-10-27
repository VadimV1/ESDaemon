#!/bin/bash
# filter-tests.sh — log-all + [include]/[exclude] (Sysmon semantics) + ESDaemon never logging itself.
# Uses the DEFAULT config (cfg text -> cfg.sh -> scope.jq), plus rules added on top.
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
cfg(){ { cat "$ROOT/configs/ESDaemon.cfg"; printf '%b' "$1"; } > "$T/c.cfg"; "$ROOT/bin/cfg.sh" "$T/c.cfg" json; }
DEF="$("$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json)"
# ev <parent path> <target path> <args json> [team_id] [platform true|false]
ev(){ jq -cn --arg pp "$1" --arg p "$2" --argjson a "$3" --arg tm "${4:-}" --argjson pl "${5:-true}" '
  {time:"2026-09-28T10:00:00Z", process:{executable:{path:$pp},is_platform_binary:true,audit_token:{pid:8,euid:501}},
   event:{exec:{target:{executable:{path:$p},is_platform_binary:$pl,team_id:(if $tm=="" then null else $tm end),
     signing_id:"com.apple.x",audit_token:{pid:8,euid:501},ppid:7},args:$a,cwd:{path:"/Users/a"}}}}'; }
n(){ jq -n -cR --argjson cfg "${1:-$DEF}" -f "$ROOT/src/scope.jq" | grep -vc eslogger_scoped_gap; }
# S <image> <ppid> <original_ppid> [platform]: a process start
S(){ jq -cn --arg i "$1" --argjson pp "$2" --argjson op "$3" --argjson pl "${4:-true}" --arg pi "${5:-/usr/libexec/xpcproxy}" '{time:"t",process:{executable:{path:$pi},is_platform_binary:true,audit_token:{pid:70}},event:{exec:{target:{executable:{path:$i},is_platform_binary:$pl,audit_token:{pid:70,euid:0},ppid:$pp,original_ppid:$op},args:["x"]}}}'; }
# D <image> <file> <ppid> <original_ppid> [platform]: a file create by a running process
D(){ jq -cn --arg i "$1" --arg t "$2" --argjson pp "$3" --argjson op "$4" --argjson pl "${5:-true}" '{time:"t",process:{executable:{path:$i},is_platform_binary:$pl,audit_token:{pid:71,euid:501},ppid:$pp,original_ppid:$op},event:{create:{destination_type:0,destination:{existing_file:{path:$t}}}}}'; }

echo "-- default config logs every launch (no keep rules, no RuleName)"
ok "benign ls from zsh logged"           '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | n)" = 1 ]'
ok "third-party xpcproxy from launchd logged" '[ "$(ev /sbin/launchd /usr/libexec/xpcproxy "[\"xpcproxy\",\"com.corp.x\"]" | n)" = 1 ]'
ok "defaults write dock autohide logged" '[ "$(ev /bin/zsh /usr/bin/defaults "[\"defaults\",\"write\",\"com.apple.dock\",\"autohide\",\"-bool\",\"true\"]" | n)" = 1 ]'
ok "log show by a user logged"           '[ "$(ev /bin/zsh /usr/bin/log "[\"log\",\"show\",\"--last\",\"1m\"]" | n)" = 1 ]'
ok "third-party app logged"              '[ "$(ev /sbin/launchd /Applications/Foo.app/Contents/MacOS/Foo "[\"Foo\"]" ZZZZ999999 false | n)" = 1 ]'
ok "no RuleName / rule field"            '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | jq -n -cR --argjson cfg "$DEF" -f "$ROOT/src/scope.jq" | jq "has(\"RuleName\") or has(\"rule\")")" = false ]'
ok "Bindplane agent log show excluded by default" '[ "$(ev /opt/observiq-otel-collector/observiq-otel-collector /usr/bin/log "[\"log\",\"show\"]" | n)" = 0 ]'
ok "Bindplane agent itself excluded by default"   '[ "$(ev /sbin/launchd /opt/observiq-otel-collector/observiq-otel-collector "[\"x\"]" X false | n)" = 0 ]'

ok "eslogger itself excluded by default"          '[ "$(ev /bin/bash /usr/bin/eslogger "[\"/usr/bin/eslogger\",\"--list-events\"]" | n)" = 0 ]'
ok "eslogger copied elsewhere still logged"       '[ "$(ev /bin/zsh /tmp/eslogger "[\"/tmp/eslogger\",\"exec\"]" | n)" = 1 ]'

# ls <signing id> <image> <args json>: launched by launchd, Apple platform binary
L(){ jq -cn --arg s "$1" --arg p "$2" --argjson a "$3" '{time:"t",process:{executable:{path:"/sbin/launchd"},is_platform_binary:true,audit_token:{pid:1}},event:{exec:{target:{executable:{path:$p},signing_id:$s,is_platform_binary:true,audit_token:{pid:77,euid:0},ppid:1},args:$a}}}'; }
MDW=/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared
ok "Apple xpcproxy (com.apple.*) excluded by default"          '[ "$(L com.apple.xpc.proxy /usr/libexec/xpcproxy "[\"xpcproxy\",\"com.apple.contactsd\"]" | n)" = 0 ]'
ok "Apple app xpcproxy (application.com.apple.*) excluded"     '[ "$(L com.apple.xpc.proxy /usr/libexec/xpcproxy "[\"xpcproxy\",\"application.com.apple.Terminal.1.2\"]" | n)" = 0 ]'
ok "third-party service xpcproxy still logged"                 '[ "$(L com.apple.xpc.proxy /usr/libexec/xpcproxy "[\"xpcproxy\",\"com.corp.agent\"]" | n)" = 1 ]'
ok "Spotlight worker excluded by default"                      '[ "$(L com.apple.mdworker_shared "$MDW" "[\"mdworker_shared\",\"-s\",\"mdworker\"]" | n)" = 0 ]'
ok "mdworker_shared copied elsewhere still logged"             '[ "$(L com.apple.mdworker_shared /tmp/mdworker_shared "[\"x\"]" | n)" = 1 ]'
ok "non-Apple binary at the mdworker_shared path still logged"   '[ "$(S "$MDW" 1 1 false | n)" = 1 ]'

# the Bindplane agent's `log show` writes a temp file each poll; logging it fed the agent new data, so it polled
# again at once (a loop, ~1 poll/s). File events now carry the acting process's ParentImage for [exclude] rules.
X(){ jq -cn --arg pp "$1" --argjson pid "$2" '{time:"t",process:{executable:{path:$pp},is_platform_binary:true,audit_token:{pid:($pid-1)}},event:{exec:{target:{executable:{path:"/usr/bin/log"},is_platform_binary:true,audit_token:{pid:$pid,euid:0,pidversion:7},ppid:($pid-1)},args:["log","show"]}}}'; }
C(){ jq -cn --argjson pid "$1" '{time:"t",process:{executable:{path:"/usr/bin/log"},is_platform_binary:true,audit_token:{pid:$pid,euid:0,pidversion:7}},event:{create:{destination_type:1,destination:{new_path:{dir:{path:"/private/var/folders/zz/x/T"},filename:"tmp.1"}}}}}'; }
FC="$(cfg '\n[modules]\nprocess = start\nfile = create\n')"
AG=$( { X /opt/observiq-otel-collector/observiq-otel-collector 500; C 500; } | jq -n -cR --argjson cfg "$FC" -f "$ROOT/src/scope.jq" | grep -vc eslogger_scoped)
US=$( { X /bin/zsh 600; C 600; } | jq -n -cR --argjson cfg "$FC" -f "$ROOT/src/scope.jq" | jq -r .EventType | tr "\n" " ")
ok "agent's log show: its launch AND its temp file excluded (ParentImage rule)" '[ "$AG" = 0 ]'
ok "user's log show: launch and temp file both logged"                         '[ "$US" = "ProcessStart FileCreate " ]'

echo "-- default excludes for Apple housekeeping: binary AND its own folder, nothing wider"
FD="$(cfg '\n[modules]\nprocess = start\nfile = create, delete\n')"
# W <process path> <file> [platform true|false]: one FileCreate by that process
W(){ jq -cn --arg i "$1" --arg t "$2" --argjson pl "${3:-true}" '{time:"t",process:{executable:{path:$i},is_platform_binary:$pl,audit_token:{pid:9,euid:0}},event:{create:{destination_type:0,destination:{existing_file:{path:$t}}}}}'; }
TI=/private/var/folders/zz/x/T
ok "cfprefsd temp copy in TemporaryItems dropped"     '[ "$(W /usr/sbin/cfprefsd $TI/TemporaryItems/a.plist.Xy12ab | n "$FD")" = 0 ]'
ok "mobileassetd temp copy dropped"                   '[ "$(W /usr/libexec/mobileassetd $TI/com.apple.mobileassetd/TemporaryItems/NSIRD_m/x | n "$FD")" = 0 ]'
ok "duetexpertd model cache dropped"                  '[ "$(W /usr/libexec/duetexpertd /Users/a/Library/Caches/com.apple.duetexpertd/x/y.e5 | n "$FD")" = 0 ]'
ok "Spotlight index store dropped"                    '[ "$(W /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores /System/Volumes/Data/.Spotlight-V100/Store-V2/x/y | n "$FD")" = 0 ]'
ok "Biome temp file dropped"                          '[ "$(W /System/Library/PrivateFrameworks/BiomeStreams.framework/Support/BiomeAgent /Users/a/Library/Biome/tmp/.tmp.x | n "$FD")" = 0 ]'
ok "curl writing into TemporaryItems still logged"    '[ "$(W /usr/bin/curl $TI/TemporaryItems/payload | n "$FD")" = 1 ]'
ok "cfprefsd writing a LaunchAgent still logged"      '[ "$(W /usr/sbin/cfprefsd /Users/a/Library/LaunchAgents/com.x.plist | n "$FD")" = 1 ]'
ok "mobileassetd writing a LaunchAgent still logged"  '[ "$(W /usr/libexec/mobileassetd /Library/LaunchAgents/com.x.plist | n "$FD")" = 1 ]'
ok "copied cfprefsd (not platform) still logged"      '[ "$(W /usr/sbin/cfprefsd $TI/TemporaryItems/a false | n "$FD")" = 1 ]'
ok "contactsd starting dropped"                       '[ "$(L com.apple.contactsd /System/Library/Frameworks/Contacts.framework/Support/contactsd "[\"contactsd\"]" | n)" = 0 ]'

echo "-- macOS's own daemons: Apple-signed, system folders, started by launchd (ppid 1 and original_ppid 1)"
HK=/System/Library/PrivateFrameworks/HomeKitDaemon.framework/Support/homed
ok "Apple service started by launchd: dropped"                     '[ "$(S $HK 1 1 | n "$FD")" = 0 ]'
ok "launchd service record gets ParentImage /sbin/launchd"         '[ "$(S /usr/local/bin/agent 1 1 false | jq -n -cR --argjson cfg "$FD" -f "$ROOT/src/scope.jq" | jq -r .ParentImage)" = /sbin/launchd ]'
ok "same Apple binary started from a shell: logged"                '[ "$(S $HK 4100 4100 true /bin/zsh | n "$FD")" = 1 ]'
ok "re-parented to pid 1 (double fork): not launchd, logged"       '[ "$(S $HK 1 4100 true /bin/zsh | n "$FD")" = 1 ]'
ok "third-party launchd service (not Apple): logged"               '[ "$(S /Library/Application\ Support/X/agent 1 1 false | n "$FD")" = 1 ]'
ok "Apple binary outside system folders from launchd: logged"      '[ "$(S /Users/a/Library/homed 1 1 | n "$FD")" = 1 ]'
ok "xpcproxy for a third-party service: still logged"              '[ "$(S /usr/libexec/xpcproxy 1 1 | n "$FD")" = 1 ]'
ok "launchd daemon temp file in /private/var/folders: dropped"     '[ "$(D /usr/libexec/swcd /private/var/folders/zz/x/T/a.tmp 1 1 | n "$FD")" = 0 ]'
ok "launchd daemon file in ~/Library/Caches: dropped"              '[ "$(D $HK /Users/a/Library/Caches/com.apple.homed/x 1 1 | n "$FD")" = 0 ]'
ok "launchd daemon writing a LaunchDaemon: logged"                 '[ "$(D /usr/libexec/swcd /Library/LaunchDaemons/com.x.plist 1 1 | n "$FD")" = 1 ]'
ok "launchd daemon writing /Applications: logged"                  '[ "$(D /usr/libexec/swcd /Applications/X.app/Contents/MacOS/X 1 1 | n "$FD")" = 1 ]'
ok "launchd daemon writing a config profile db: logged"            '[ "$(D /usr/libexec/mdmclient /private/var/db/ConfigurationProfiles/Settings/x 1 1 | n "$FD")" = 1 ]'
ok "syspolicyd writing outside its own store: logged"            '[ "$(D /usr/libexec/syspolicyd /Library/LaunchDaemons/com.x.plist 1 1 | n "$FD")" = 1 ]'
ok "kernelmanager_helper re-staging kexts at boot: dropped"      '[ "$(D /usr/libexec/kernelmanager_helper /private/var/db/KernelExtensionManagement/Staging/x 1 1 | n "$FD")" = 0 ]'
ok "syspolicyd rewriting XProtect at boot: dropped"               '[ "$(D /usr/libexec/syspolicyd /private/var/db/SystemPolicyConfiguration/XProtect.app/x 1 1 | n "$FD")" = 0 ]'
ok "another process writing the Gatekeeper/XProtect store: logged" '[ "$(D /bin/cp /private/var/db/SystemPolicyConfiguration/gk.db 4100 4100 | n "$FD")" = 1 ]'
ok "another process writing kext staging: logged"                 '[ "$(D /usr/bin/ditto /private/var/db/KernelExtensionManagement/Staging/evil.kext 4100 4100 | n "$FD")" = 1 ]'
ok "nsurlsessiond background download: logged"                     '[ "$(D /usr/libexec/nsurlsessiond /private/var/folders/zz/x/0/com.apple.nsurlsessiond/d 1 1 | n "$FD")" = 1 ]'
ok "Apple tool run from a shell writing \$TMPDIR: logged"           '[ "$(D /usr/sbin/screencapture /private/var/folders/zz/x/T/s.png 4100 4100 | n "$FD")" = 1 ]'
ok "begin with any / end with any parse and match"                 '[ "$(ev /bin/zsh /usr/bin/curl "[\"curl\"]" | n "$(cfg "\n[exclude]\nImage begin with any /opt/;/usr/bin/\n")")" = 0 ] && [ "$(ev /bin/zsh /usr/bin/curl "[\"curl\"]" | n "$(cfg "\n[exclude]\nImage end with any /wget;/curl\n")")" = 0 ] && [ "$(ev /bin/zsh /usr/bin/curl "[\"curl\"]" | n "$(cfg "\n[exclude]\nImage begin with any /opt/;/sbin/\n")")" = 1 ]'

echo "-- complete pass over a reboot + login: Apple helpers, update volume, Library areas, temp copies, preferences"
# P <image> <parent image>: a process start forked by <parent image> (ppid not 1, parent launch unseen)
P(){ jq -cn --arg i "$1" --arg p "$2" '{time:"t",process:{executable:{path:$p},is_platform_binary:true,audit_token:{pid:80}},event:{exec:{target:{executable:{path:$i},is_platform_binary:true,audit_token:{pid:80,euid:0},ppid:79,original_ppid:79},args:["x"]}}}'; }
ok "diskarbitrationd -> apfs.util (boot disk check): dropped"      '[ "$(P /System/Library/Filesystems/apfs.fs/Contents/Resources/apfs.util /usr/libexec/diskarbitrationd | n "$FD")" = 0 ]'
ok "installd -> /bin/sh (package install script): logged"          '[ "$(P /bin/sh /System/Library/PrivateFrameworks/PackageKit.framework/Resources/installd | n "$FD")" = 1 ]'
ok "Apple daemon -> curl: logged"                                   '[ "$(P /usr/bin/curl /usr/libexec/xpcproxy | n "$FD")" = 1 ]'
ok "launchd -> app extension (.appex): dropped"                    '[ "$(S /System/Applications/Weather.app/Contents/PlugIns/WeatherWidget.appex/Contents/MacOS/WeatherWidget 1 1 | n "$FD")" = 0 ]'
ok "launchd -> Terminal.app (user opened an app): logged"           '[ "$(S /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal 1 1 | n "$FD")" = 1 ]'
ok "launchd -> XProtect run (Apple-managed): dropped"               '[ "$(S /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect 1 1 | n "$FD")" = 0 ]'
ok "daemon file in ~/Library/Application Support/AddressBook: dropped" '[ "$(D /System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookManager.app/Contents/MacOS/AddressBookManager /Users/a/Library/Application\ Support/AddressBook/Metadata/x 1 1 | n "$FD")" = 0 ]'
ok "daemon writing ~/Library/LaunchAgents: logged"                  '[ "$(D /usr/libexec/swcd /Users/a/Library/LaunchAgents/com.x.plist 1 1 | n "$FD")" = 1 ]'
ok "daemon writing the login keychain itself: logged"               '[ "$(D /usr/libexec/sharingd /Users/a/Library/Keychains/login.keychain-db 1 1 | n "$FD")" = 1 ]'
ok "daemon safe-save temp of the keychain (.sb-): dropped"          '[ "$(D /usr/libexec/sharingd /Users/a/Library/Keychains/login.keychain-db.sb-e5dbc161-C7h484 1 1 | n "$FD")" = 0 ]'
ok "same .sb- name written by cp from a shell: logged"              '[ "$(D /bin/cp /Users/a/Library/Keychains/login.keychain-db.sb-e5dbc161-C7h484 4100 4100 | n "$FD")" = 1 ]'
ok "tccd writing the TCC database: logged"                          '[ "$(D /System/Library/PrivateFrameworks/TCC.framework/Support/tccd "/Library/Application Support/com.apple.TCC/TCC.db" 1 1 | n "$FD")" = 1 ]'
ok "launchd daemon runtime file in /private/var/run: dropped"       '[ "$(D /usr/libexec/mdmclient /private/var/run/com.apple.mdmclient.daemon.didRunThisBoot 1 1 | n "$FD")" = 0 ]'
ok "trustd rewriting its protected store at boot: dropped"           '[ "$(D /usr/libexec/trustd /private/var/protected/trustd/update-current 1 1 | n "$FD")" = 0 ]'
ok "a shell-started process writing /private/var/protected: logged"   '[ "$(D /bin/cp /private/var/protected/trustd/evil 4100 4100 | n "$FD")" = 1 ]'
ok "software-update writes on the update volume: dropped"           '[ "$(D /System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated /System/Volumes/Update/restore.log 1 1 | n "$FD")" = 0 ]'
ok "cfprefsd saving Messages/Sharing preferences: dropped"          '[ "$(D /usr/sbin/cfprefsd /Users/a/Library/Preferences/com.apple.Sharing.plist 1 1 | n "$FD")" = 0 ]'
ok "cfprefsd saving loginwindow preferences: logged"                '[ "$(D /usr/sbin/cfprefsd /Users/a/Library/Preferences/com.apple.loginwindow.plist 1 1 | n "$FD")" = 1 ]'
ok "cfprefsd saving LaunchServices preferences: logged"             '[ "$(D /usr/sbin/cfprefsd /Users/a/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist 1 1 | n "$FD")" = 1 ]'
ok "MDM profile write (not the lock file): logged"                  '[ "$(D /usr/libexec/mdmclient /private/var/db/ConfigurationProfiles/Store/x.plist 1 1 | n "$FD")" = 1 ]'
ok "MDM .createStore.lock: dropped"                                 '[ "$(D /usr/libexec/mdmclient /private/var/db/ConfigurationProfiles/Settings/.createStore.lock 1 1 | n "$FD")" = 0 ]'
ok "keybag .writing temp: dropped; other keybag write: logged"      '[ "$(D /usr/libexec/usermanagerd /private/var/db/keybags/persona.kb.writing 1 1 | n "$FD")" = 0 ] && [ "$(D /usr/libexec/usermanagerd /private/var/db/keybags/persona.kb 1 1 | n "$FD")" = 1 ]'

echo "-- [include]: empty = everything; with rules = only matches"
INC="$(cfg '\n[include]\nImage image curl\nIsPlatformBinary is false\n')"
ok "include: curl matches -> logged"     '[ "$(ev /bin/zsh /usr/bin/curl "[\"curl\",\"x\"]" | n "$INC")" = 1 ]'
ok "include: unsigned app matches (second line = OR)" '[ "$(ev /sbin/launchd /tmp/payload "[\"p\"]" "" false | n "$INC")" = 1 ]'
ok "include: ls matches nothing -> not logged" '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | n "$INC")" = 0 ]'
ok "include: [exclude] still wins (Bindplane log show)" '[ "$(cfg "\n[include]\nImage image log\n" > /dev/null; ev /opt/observiq-otel-collector/observiq-otel-collector /usr/bin/log "[\"log\",\"show\"]" | n "$(cfg "\n[include]\nImage image log\n")")" = 0 ]'
EVT="$(cfg '\n[include]\nEventType is FileCreate AND TargetFilename contains any /LaunchAgents/;/LaunchDaemons/\n')"
F(){ jq -cn --arg d "$1" '{time:"t",process:{executable:{path:"/usr/bin/curl"},is_platform_binary:true,audit_token:{pid:1,euid:0}},event:{create:{destination_type:1,destination:{new_path:{dir:{path:$d},filename:"x.plist"}}}}}'; }
ok "include by EventType+TargetFilename: LaunchAgent plist logged" '[ "$(F /Users/a/Library/LaunchAgents | n "$EVT")" = 1 ]'
ok "include by EventType+TargetFilename: other file not logged"    '[ "$(F /Users/a/Documents | n "$EVT")" = 0 ]'
ok "include by EventType: exec not logged"                          '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | n "$EVT")" = 0 ]'

echo "-- [exclude] with exceptions (AND + negated conditions)"
EXC="$(cfg '\n[exclude]\nSigningId begin with com.apple. AND Image not end with /curl\n')"
ok "exclude Apple tools: ls dropped"     '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | n "$EXC")" = 0 ]'
ok "exclude Apple tools except curl: curl logged" '[ "$(ev /bin/zsh /usr/bin/curl "[\"curl\"]" | n "$EXC")" = 1 ]'
RXN="$(cfg '\n[exclude]\nImage image python3 AND CommandLine not regex ^python3 -c\n')"
ok "not regex: python3 script.py dropped" '[ "$(ev /bin/zsh /usr/bin/python3 "[\"python3\",\"s.py\"]" | n "$RXN")" = 0 ]'
ok "not regex: python3 -c kept"           '[ "$(ev /bin/zsh /usr/bin/python3 "[\"python3\",\"-c\",\"x\"]" | n "$RXN")" = 1 ]'
ok "missing field never matches (include)" '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | n "$(cfg "\n[include]\nParentCommandLine is not x\n")")" = 0 ]'
ok "missing field never matches (exclude)" '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | n "$(cfg "\n[exclude]\nParentCommandLine is not x\n")")" = 1 ]'

echo "-- a rule that fails on an event never hides it: no drop in [exclude], a match in [include], the error in the record"
# A regex the regex engine gives up on (backtracking on a long command line the process chose) throws inside the rule.
# Where an engine gives up depends on its version and limits, so these rules hold a regex that does not compile at
# all: the same kind of error, from the same place, on every jq. cfg.sh refuses such a regex, so it goes in as JSON.
BADRX='{"field":"CommandLine","op":"regex","value":"("}'
FX="$(echo "$DEF" | jq -c --argjson b "$BADRX" '.exclude += [[{field:"Image",op:"image",value:"sh"}, $b]]')"
FR="$(ev /bin/zsh /bin/sh '["sh"]' | jq -c '.event.exec.args = ["sh","-c",("A" * 100000),"tail-end"]' | jq -n -cR --argjson cfg "$FX" -f "$ROOT/src/scope.jq")"
ok "failing [exclude] rule, 100 KB argv: logged, CommandLine head and tail kept" '[ "$(echo "$FR" | jq -c "[.Image, (.CommandLine | startswith(\"sh -c AAAA\") and endswith(\" tail-end\"))]")" = "[\"/bin/sh\",true]" ] && [ "$(printf %s "$FR" | wc -c | tr -d " ")" -le 32000 ]'
ok "the record says which rule failed"                  '[ "$(echo "$FR" | jq ".esd_rule_error | endswith(\" in [exclude]: Image image sh AND CommandLine regex (\")")" = true ]'
FXN="$(echo "$FX" | jq -c '.exclude[-1][1].op = "not regex"')"
ok "a failing not regex does not drop it either"         '[ "$(ev /bin/zsh /bin/sh "[\"sh\"]" | jq -n -cR --argjson cfg "$FXN" -f "$ROOT/src/scope.jq" | jq -r .Image)" = /bin/sh ]'
FI="$(echo "$DEF" | jq -c --argjson b "$BADRX" '.include = [[{field:"Image",op:"is",value:"/nope"}], [$b]]')"
ok "failing [include] rule lets the event in, with the error" '[ "$(ev /bin/zsh /bin/ls "[\"ls\"]" | jq -n -cR --argjson cfg "$FI" -f "$ROOT/src/scope.jq" | jq -c "[.Image, (.esd_rule_error | endswith(\" in [include]: CommandLine regex (\"))]")" = "[\"/bin/ls\",true]" ]'
F1="$(echo "$DEF" | jq -c --argjson b "$BADRX" '.exclude += [[$b], [{field:"Image",op:"is",value:"/bin/sh"}]]')"
F2="$(echo "$DEF" | jq -c --argjson b "$BADRX" '.exclude += [[{field:"Image",op:"is",value:"/bin/sh"}], [$b]]')"
ok "a rule that matches cleanly still drops it, before or after the failing one" '[ "$(ev /bin/zsh /bin/sh "[\"sh\"]" | n "$F1")" = 0 ] && [ "$(ev /bin/zsh /bin/sh "[\"sh\"]" | n "$F2")" = 0 ]'
AROUND=$( { ev /bin/zsh /usr/bin/curl '["curl","x"]'; ev /bin/zsh /bin/sh '["sh","-c","y"]'; ev /bin/zsh /bin/ls '["ls"]'; } \
          | jq -n -cR --argjson cfg "$FX" -f "$ROOT/src/scope.jq" | jq -r '"\(.Image):\(has("esd_rule_error"))"' | tr "\n" " ")
ok "events around it unaffected: only the one the rule failed on carries the error" '[ "$AROUND" = "/usr/bin/curl:false /bin/sh:true /bin/ls:false " ]'

echo "-- [modules] operations: what each event is called, and file read / write"
P='{"executable":{"path":"/usr/bin/vim"},"audit_token":{"pid":44,"euid":501},"is_platform_binary":true,"signing_id":"com.apple.vim"}'
# E <eslogger event> <event payload json>  -> one raw eslogger line
E(){ jq -cn --argjson p "$P" --arg ev "$1" --argjson e "$2" '{time:"2026-09-28T10:00:00Z", process:$p, event:{($ev):$e}}'; }
# k: EventID, EventType and the main subject of the record (file, target process, exit status, or the Detail type)
k(){ jq -n -cR --argjson cfg "$DEF" -f "$ROOT/src/scope.jq" | jq -c '[.EventID, .EventType, (.TargetFilename // .TargetImage // .ExitStatus // (.Detail | type))]'; }
t(){ local name="$1" ev="$2" payload="$3" want="$4" got; got="$(E "$ev" "$payload" | k)"
  if [ "$got" = "$want" ]; then pass=$((pass+1)); echo "  ok   $name"; else fail=$((fail+1)); echo "  FAIL $name  (got: $got)"; fi; }
t "open read-only -> FileRead"            open  '{"fflag":1,"file":{"path":"/etc/hosts"}}'        '[101,"FileRead","/etc/hosts"]'
t "open for writing is not a read"        open  '{"fflag":3,"file":{"path":"/tmp/a"}}'            ''
t "open, read-only plus other flags -> FileRead" open '{"fflag":1048577,"file":{"path":"/usr/bin"}}' '[101,"FileRead","/usr/bin"]'
t "close of a changed file -> FileWrite"  close '{"modified":true,"target":{"path":"/Users/a/x.txt"}}'  '[102,"FileWrite","/Users/a/x.txt"]'
t "close without change is not a write"   close '{"modified":false,"target":{"path":"/Users/a/x.txt"}}' ''
t "rename -> FileRename"                  rename '{"source":{"path":"/tmp/a"},"destination_type":0,"destination":{"existing_file":{"path":"/tmp/b"}}}' '[103,"FileRename","/tmp/b"]'
t "exit -> ProcessExit with ExitStatus"   exit  '{"stat":256}'                                    '[5,"ProcessExit",256]'
t "get_task -> ProcessInject with target" get_task '{"target":{"executable":{"path":"/usr/bin/sudo"},"audit_token":{"pid":9}}}' '[10,"ProcessInject","/usr/bin/sudo"]'
t "btm_launch_item_add -> SystemPersistence" btm_launch_item_add '{"item":{"item_url":"x"}}'       '[121,"SystemPersistence","object"]'
t "od_create_user -> UserAccount"         od_create_user '{"user_name":"x"}'                      '[114,"UserAccount","object"]'
t "openssh_login -> UserLogin"            openssh_login '{"success":true}'                        '[111,"UserLogin","object"]'
A=$(E setextattr '{"target":{"path":"/tmp/a.app"},"extattr":"com.apple.quarantine"}' | jq -n -cR --argjson cfg "$DEF" -f "$ROOT/src/scope.jq" | jq -c '[.EventType, .TargetFilename, .Detail.extattr]')
ok "setextattr -> FileAttributes + what changed" '[ "$A" = "[\"FileAttributes\",\"/tmp/a.app\",\"com.apple.quarantine\"]" ]'
SU=$(E sudo '{"success":true,"x":{"stat":{"st_size":1},"path":"/a"}}' | jq -n -cR --argjson cfg "$DEF" -f "$ROOT/src/scope.jq" | jq -c '[.EventType, .Detail.x]')
ok "Detail has no stat blocks"             '[ "$SU" = "[\"UserSudo\",{\"path\":\"/a\"}]" ]'
INCF="$(cfg '\n[include]\nEventType is FileRead AND TargetFilename begin with /Users/\n')"
RE=$(E open '{"fflag":1,"file":{"path":"/etc/hosts"}}'); RU=$(E open '{"fflag":1,"file":{"path":"/Users/a/x"}}')
ok "[include] picks a module by EventType: /etc read not logged" '[ "$(echo "$RE" | n "$INCF")" = 0 ]'
ok "[include] picks a module by EventType: /Users read logged"   '[ "$(echo "$RU" | n "$INCF")" = 1 ]'

echo "-- ESDaemon never logs itself (built in, not a rule)"
# real chain captured on macOS 26.7: launchd -> xpcproxy com.esdaemon.filter (pid 500) -> exec bash filter.sh (same pid)
#   -> children through subshells (ppid = an unseen subshell), all with responsible pid 500
J(){ jq -cn --argjson pid "$1" --argjson ppid "$2" --argjson rp "$3" --arg img "$4" --argjson a "$5" '
  {time:"2026-09-28T10:00:00Z", process:{executable:{path:"/bin/bash"},is_platform_binary:true,audit_token:{pid:$pid}},
   event:{exec:{target:{executable:{path:$img},is_platform_binary:true,audit_token:{pid:$pid,euid:0,pidversion:($pid*10)},ppid:$ppid,
     responsible_audit_token:{pid:$rp,pidversion:($rp*10)}},args:$a}}}'; }
SELF=$( { J 500 1 500 /usr/libexec/xpcproxy '["xpcproxy","com.esdaemon.filter"]'
          J 500 1 500 /bin/bash '["/bin/bash","/usr/local/ESDaemon/filter.sh"]'
          J 501 500 500 /bin/bash '["/bin/bash","/usr/local/ESDaemon/cfg.sh","x","json"]'
          J 503 502 500 /usr/bin/jq '["jq","-R"]'
          J 504 502 500 /usr/bin/awk '["awk","-F\\t"]'
          J 505 500 505 /usr/local/ESDaemon/ESDaemon '["/usr/local/ESDaemon/ESDaemon","com.apple.eslogger","events"]'
          J 600 1 600 /usr/libexec/xpcproxy '["xpcproxy","com.corp.other"]'
          J 601 77 999 /usr/bin/curl '["curl","x"]'; } | jq -n -cR --argjson cfg "$DEF" -f "$ROOT/src/scope.jq")
ok "filter job tree + ESDaemon binary dropped, others logged" '[ "$(echo "$SELF" | jq -r .Image | tr "\n" " ")" = "/usr/libexec/xpcproxy /usr/bin/curl " ]'
SP=$(echo "$DEF" | jq -c '.self_pid = 900')
UNSEEN=$( { J 903 902 900 /usr/bin/awk '["awk","-v","k=subsystem"]'
            J 904 902 900 /usr/bin/jq '["jq","-n","-cR"]'
            J 905 77 999 /usr/bin/curl '["curl","y"]'; } | jq -n -cR --argjson cfg "$SP" -f "$ROOT/src/scope.jq")
ok "job start never seen (eslogger restarting): helpers dropped by self_pid" '[ "$(echo "$UNSEEN" | jq -r .Image | tr "\n" " ")" = "/usr/bin/curl " ]'
ok "user running bash /usr/local/ESDaemon/try.sh is logged (not the launchd job)" \
   '[ "$(J 700 650 640 /bin/bash "[\"/bin/bash\",\"/usr/local/ESDaemon/try.sh\"]" | n)" = 1 ]'
ok "user process cannot claim the job by pid reuse (pidversion differs)" \
   '[ "$( { J 500 1 500 /bin/bash "[\"/bin/bash\",\"/usr/local/ESDaemon/filter.sh\"]"; J 800 799 500 /usr/bin/curl "[\"curl\"]" | jq -c ".event.exec.target.responsible_audit_token.pidversion=1"; } | n)" = 1 ]'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
