#!/bin/bash
# install.sh — install/refresh ESDaemon (run as root, macOS 15+). Safe to re-run.
#   com.esdaemon.eslogger : /usr/bin/eslogger <events> -> FIFO   (FDA on /usr/bin/eslogger only)
#   com.esdaemon.filter   : FIFO -> filter -> unified log         (no FDA)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"; BASE=/usr/local/ESDaemon; LD=/Library/LaunchDaemons
[ -x /usr/bin/jq ] || { echo "needs /usr/bin/jq (macOS 15+)"; exit 1; }

# retire the old unfiltered daemon, it would flood the same subsystem
if [ -f $LD/com.endpoint.eslogger.plist ]; then launchctl bootout system $LD/com.endpoint.eslogger.plist 2>/dev/null || true; mv $LD/com.endpoint.eslogger.plist $LD/com.endpoint.eslogger.plist.disabled; fi

install -d -o root -g wheel -m 755 "$BASE" "$BASE/configs"
install -o root -g wheel -m 755 "$SRC"/bin/{cfg.sh,filter.sh,measure.sh,reload.sh,try.sh} "$BASE/"
install -o root -g wheel -m 644 "$SRC"/src/{scope.jq,uls-writer.swift} "$BASE/"
[ -f "$BASE/configs/ESDaemon.cfg" ] || install -o root -g wheel -m 644 "$SRC/configs/ESDaemon.cfg" "$BASE/configs/"   # never overwrite a tuned cfg
"$BASE/cfg.sh" "$BASE/configs/ESDaemon.cfg" json >/dev/null

if   [ -x "$SRC/build/uls-writer" ]; then install -m 755 "$SRC/build/uls-writer" "$BASE/"
elif command -v swiftc >/dev/null; then swiftc -O -o "$BASE/uls-writer" "$SRC/src/uls-writer.swift"
else echo "need prebuilt build/uls-writer (make build) or swiftc (xcode-select --install)"; exit 1; fi
codesign -s - -f "$BASE/uls-writer" 2>/dev/null || true

"$BASE/reload.sh"
echo "ESDaemon installed. Config: $BASE/configs/ESDaemon.cfg   Apply edits: sudo $BASE/reload.sh"
echo "Check: log stream --info --predicate 'subsystem == \"com.apple.eslogger\" AND process == \"uls-writer\"'"
