#!/bin/bash
# uninstall.sh — remove ESDaemon. Works from a checkout or piped from curl.
#   sudo ./uninstall.sh            remove ESDaemon, keep a copy of the config in /var/log/ESDaemon
#   sudo ./uninstall.sh --purge    also delete /var/log/ESDaemon (config copy and the daemons' stderr logs)
#
# Once ESDaemon is installed you do not need this file at all: the installed control command removes
# everything itself, including itself —  sudo esdaemon uninstall [--purge].  This script removes the same
# things in place instead of running the installed command, so it is also the way to remove an install
# another user may have changed (esdaemon status: UNSAFE) without running anything from the install tree.
# Records ESDaemon already wrote stay in the unified log until macOS rotates them out.
set -uo pipefail
# fixed PATH: this can run as root, and macOS sudo keeps the caller's PATH — so bare tool names resolve to system binaries
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
BASE=/usr/local/ESDaemon; LD=/Library/LaunchDaemons; LOGS=/var/log/ESDaemon
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

PURGE=0; [ "${1:-}" = --purge ] && PURGE=1
for j in filter eslogger; do
  launchctl bootout "system/com.esdaemon.$j" 2>/dev/null && echo "stopped com.esdaemon.$j"
  rm -f "$LD/com.esdaemon.$j.plist"
done
rm -f /etc/newsyslog.d/com.esdaemon.conf   # the stderr-rotation config reload.sh installed (issue #9)
if [ $PURGE = 0 ] && [ -f "$BASE/configs/ESDaemon.cfg" ]; then
  [ -d "$LOGS" ] || install -d -m 700 "$LOGS" 2>/dev/null || mkdir -p "$LOGS"
  cp "$BASE/configs/ESDaemon.cfg" "$LOGS/ESDaemon.cfg.uninstalled" \
    && echo "config saved to $LOGS/ESDaemon.cfg.uninstalled"
fi
rm -rf "$BASE" /var/run/ESDaemon /usr/local/bin/esdaemon
[ $PURGE = 1 ] && rm -rf "$LOGS" && echo "removed $LOGS"
echo "ESDaemon removed. Full Disk Access for /usr/bin/eslogger can be revoked in System Settings (or by removing the MDM profile)."
