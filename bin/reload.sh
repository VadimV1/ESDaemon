#!/bin/bash
# reload.sh — (re)generate both LaunchDaemons from ESDaemon.cfg and restart them. Run after editing the cfg.
#   reload.sh --render <dir> [cfg]   only validate the cfg and write the two plists into <dir> (no root, no launchctl)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; BASE=/usr/local/ESDaemon; RUN="$BASE/run"; FIFO="$RUN/raw.fifo"; LD=/Library/LaunchDaemons
CFGF="$BASE/configs/ESDaemon.cfg"; RENDER=""
if [ "${1:-}" = --render ]; then RENDER="${2:?output dir}"; CFGF="${3:-$CFGF}"; fi
# bash-invoked: a GitHub tarball/ZIP (or a Windows push) may drop the execute bit on cfg.sh
bash "$HERE/cfg.sh" "$CFGF" json >/dev/null || { echo "ESDaemon.cfg is invalid, nothing changed"; exit 1; }
EVENTS="$(bash "$HERE/cfg.sh" "$CFGF" events)"; [ -n "$EVENTS" ] || EVENTS="exec"
SUB="$(bash "$HERE/cfg.sh" "$CFGF" get subsystem)"; CAT="$(bash "$HERE/cfg.sh" "$CFGF" get category)"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
ARGS=""; for e in $EVENTS; do ARGS+="<string>$e</string>"; done
cat > "$T/com.esdaemon.eslogger.plist" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.esdaemon.eslogger</string>
  <key>ProgramArguments</key><array><string>/usr/bin/eslogger</string>$ARGS</array>
  <key>StandardOutPath</key><string>$FIFO</string>
  <key>StandardErrorPath</key><string>/var/log/ESDaemon/eslogger.stderr</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
P
cat > "$T/com.esdaemon.filter.plist" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.esdaemon.filter</string>
  <key>ProgramArguments</key><array><string>$BASE/filter.sh</string></array>
  <key>StandardErrorPath</key><string>/var/log/ESDaemon/filter.stderr</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer>
</dict></plist>
P
if command -v plutil >/dev/null; then plutil -lint -s "$T"/*.plist || { echo "generated plist is invalid, nothing changed"; exit 1; }; fi
if [ -n "$RENDER" ]; then cp "$T"/*.plist "$RENDER/"; exit 0; fi

# Apple's com.apple.eslogger.plist enables 32 KB messages for category "events" only; any other subsystem or
# category gets the ~1 KB default, which cuts almost every record into invalid JSON. Enable it for ours.
if [ -n "$SUB" ] && { [ "$SUB" != com.apple.eslogger ] || [ "${CAT:-events}" != events ]; }; then
  install -d /Library/Preferences/Logging/Subsystems
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>DEFAULT-OPTIONS</key><dict><key>Enable-Oversize-Messages</key><true/></dict></dict></plist>\n' > "/Library/Preferences/Logging/Subsystems/$SUB.plist"
fi

# FIFO lives under $BASE, not /var/run: /var/run is wiped at boot and launchd would recreate the path as a regular file
install -d -o root -g wheel -m 700 "$RUN" /var/log/ESDaemon
[ -p "$FIFO" ] || { rm -f "$FIFO"; mkfifo -m 600 "$FIFO"; }
rm -rf /var/run/ESDaemon   # old location
install -o root -g wheel -m 644 "$CFGF" "$RUN/active.cfg"   # what filter.sh runs with, until the next reload

# Restart eslogger only when its plist changed: killing it discards every event it has buffered (a backlog under
# load can be minutes of events). The filter alone restarts without loss; eslogger holds the FIFO meanwhile.
RESTART_ES=0
cmp -s "$T/com.esdaemon.eslogger.plist" "$LD/com.esdaemon.eslogger.plist" && launchctl print system/com.esdaemon.eslogger >/dev/null 2>&1 || RESTART_ES=1
install -o root -g wheel -m 644 "$T"/com.esdaemon.*.plist "$LD/"
# launchd teardown is asynchronous: bootstrapping a label too soon after booting it out intermittently fails
# ("Operation already in progress"). Boot out, wait until the label is really gone, then bootstrap with retries.
# Never leave a daemon we took down un-restarted — if the filter stops draining the FIFO, events are lost.
restart_job() {   # $1 = label
  launchctl bootout "system/$1" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do launchctl print "system/$1" >/dev/null 2>&1 || break; sleep 0.3; done
  for _ in 1 2 3 4 5; do launchctl bootstrap system "$LD/$1.plist" 2>/dev/null && return 0; sleep 0.5; done
  echo "ESDaemon: could not (re)start $1 — run: sudo launchctl bootstrap system $LD/$1.plist" >&2; return 1
}
rc=0
restart_job com.esdaemon.filter || rc=1
[ $RESTART_ES = 0 ] || restart_job com.esdaemon.eslogger || rc=1
[ $rc = 0 ] || echo "ESDaemon: a daemon did not come back up — see the message above" >&2
echo "ESDaemon running. events: $EVENTS  ->  $SUB$([ $RESTART_ES = 1 ] && echo "  (eslogger restarted)" || true)"
