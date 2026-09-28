#!/bin/bash
# uninstall.sh — remove ESDaemon (keeps /var/log/ESDaemon). Re-enable the old daemon manually if wanted.
LD=/Library/LaunchDaemons
for j in eslogger filter; do launchctl bootout system/com.esdaemon.$j 2>/dev/null; rm -f $LD/com.esdaemon.$j.plist; done
rm -rf /usr/local/ESDaemon /var/run/ESDaemon
echo "ESDaemon removed"
