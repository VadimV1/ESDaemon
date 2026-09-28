#!/bin/bash
# reload.sh — (re)generate both LaunchDaemons from ESDaemon.cfg and restart them. Run after editing the cfg.
set -euo pipefail
BASE=/usr/local/ESDaemon; CFGF="$BASE/configs/ESDaemon.cfg"; LD=/Library/LaunchDaemons
"$BASE/cfg.sh" "$CFGF" json >/dev/null || { echo "ESDaemon.cfg is invalid, nothing changed"; exit 1; }
EVENTS="$("$BASE/cfg.sh" "$CFGF" get events)"; [ -n "$EVENTS" ] || EVENTS=exec
SUB="$("$BASE/cfg.sh" "$CFGF" get subsystem)"
if [ -n "$SUB" ] && [ "$SUB" != com.apple.eslogger ]; then   # custom subsystem: allow 32 KB messages (default is ~1 KB)
  install -d /Library/Preferences/Logging/Subsystems
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>DEFAULT-OPTIONS</key><dict><key>Enable-Oversize-Messages</key><true/></dict></dict></plist>\n' > "/Library/Preferences/Logging/Subsystems/$SUB.plist"
fi

install -d -o root -g wheel -m 700 /var/run/ESDaemon /var/log/ESDaemon
[ -p /var/run/ESDaemon/raw.fifo ] || mkfifo -m 600 /var/run/ESDaemon/raw.fifo

ARGS=""; for e in $EVENTS; do ARGS+="<string>$e</string>"; done
cat > $LD/com.esdaemon.eslogger.plist <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.esdaemon.eslogger</string>
  <key>ProgramArguments</key><array><string>/usr/bin/eslogger</string>$ARGS</array>
  <key>StandardOutPath</key><string>/var/run/ESDaemon/raw.fifo</string>
  <key>StandardErrorPath</key><string>/var/log/ESDaemon/eslogger.stderr</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
P
cat > $LD/com.esdaemon.filter.plist <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.esdaemon.filter</string>
  <key>ProgramArguments</key><array><string>$BASE/filter.sh</string></array>
  <key>StandardErrorPath</key><string>/var/log/ESDaemon/filter.stderr</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer>
</dict></plist>
P
chown root:wheel $LD/com.esdaemon.*.plist; chmod 644 $LD/com.esdaemon.*.plist
for j in filter eslogger; do launchctl bootout system/com.esdaemon.$j 2>/dev/null || true; done
launchctl bootstrap system $LD/com.esdaemon.filter.plist
launchctl bootstrap system $LD/com.esdaemon.eslogger.plist
echo "ESDaemon running. events: $EVENTS  ->  $SUB"
