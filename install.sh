#!/bin/bash
# install.sh — install/refresh ESDaemon (run as root, macOS 15+). Safe to re-run.
#   com.esdaemon.eslogger : /usr/bin/eslogger <events> -> FIFO   (FDA on /usr/bin/eslogger only)
#   com.esdaemon.filter   : FIFO -> filter -> unified log         (no FDA)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"; BASE=/usr/local/ESDaemon; LD=/Library/LaunchDaemons
[ -x /usr/bin/jq ] || { echo "needs /usr/bin/jq (macOS 15+)"; exit 1; }
# check the cfg this version will run (the tuned one if present) with THIS version's parser, before touching anything
CFGF="$BASE/configs/ESDaemon.cfg"; [ -f "$CFGF" ] || CFGF="$SRC/configs/ESDaemon.cfg"
# an older cfg (keep rules, or events = instead of [modules]) is migrated once; the original is kept as ESDaemon.cfg.v1
MIG=""
if [ "$CFGF" = "$BASE/configs/ESDaemon.cfg" ] && grep -Eq '^[[:space:]]*(\[(always|download|conditional|noisy_team_ids|noisy_path_prefixes)\]|(third_party|events)[[:space:]]*=)' "$CFGF"; then
  MIG="$(mktemp)"; bash "$SRC/bin/migrate-cfg.sh" "$CFGF" > "$MIG"
  bash "$SRC/bin/cfg.sh" "$MIG" json >/dev/null || { echo "could not migrate $CFGF (migrated draft: $MIG); fix it and re-run install.sh (nothing changed)"; exit 1; }
  CFGF="$MIG"
fi
# bash-invoked: a GitHub tarball/ZIP (or a Windows push) may drop the execute bit on the source scripts
bash "$SRC/bin/cfg.sh" "$CFGF" json >/dev/null || { echo "$CFGF is invalid for this version: fix it and re-run install.sh (nothing changed)"; exit 1; }

# retire the old unfiltered daemon, it would flood the same subsystem
if [ -f $LD/com.endpoint.eslogger.plist ]; then launchctl bootout system $LD/com.endpoint.eslogger.plist 2>/dev/null || true; mv $LD/com.endpoint.eslogger.plist $LD/com.endpoint.eslogger.plist.disabled; fi

install -d -o root -g wheel -m 755 "$BASE" "$BASE/configs" /usr/local/bin
install -o root -g wheel -m 755 "$SRC"/bin/{cfg.sh,filter.sh,measure.sh,reload.sh,try.sh,update.sh} "$BASE/"
install -o root -g wheel -m 755 "$SRC/bin/esdaemon" /usr/local/bin/esdaemon   # the control command (status/reload/update/uninstall)
install -o root -g wheel -m 644 "$SRC"/VERSION "$SRC"/REPO "$BASE/"   # what update.sh compares against
install -o root -g wheel -m 644 "$SRC"/src/{scope.jq,ESDaemon.swift} "$BASE/"
[ -f "$BASE/configs/ESDaemon.cfg" ] || install -o root -g wheel -m 644 "$SRC/configs/ESDaemon.cfg" "$BASE/configs/"   # never overwrite a tuned cfg
if [ -n "$MIG" ]; then
  OLD="$BASE/configs/ESDaemon.cfg.v1"; [ ! -e "$OLD" ] || OLD="$BASE/configs/ESDaemon.cfg.$(date +%Y%m%d-%H%M%S)"   # never overwrite an earlier backup
  mv "$BASE/configs/ESDaemon.cfg" "$OLD"
  install -o root -g wheel -m 644 "$MIG" "$BASE/configs/ESDaemon.cfg"; rm -f "$MIG"
  echo "migrated $BASE/configs/ESDaemon.cfg to this version ([modules], [include]/[exclude]); old file: $OLD"
fi

if   [ -x "$SRC/build/ESDaemon" ]; then install -m 755 "$SRC/build/ESDaemon" "$BASE/"
elif command -v swiftc >/dev/null; then swiftc -O -o "$BASE/ESDaemon" "$SRC/src/ESDaemon.swift"
else echo "need prebuilt build/ESDaemon (make build) or swiftc (xcode-select --install)"; exit 1; fi
codesign -s - -f "$BASE/ESDaemon" 2>/dev/null || true
rm -f "$BASE/uls-writer" "$BASE/uls-writer.swift"   # pre-rename writer

"$BASE/reload.sh"
echo "ESDaemon $(cat "$BASE/VERSION") installed. Config: $BASE/configs/ESDaemon.cfg"
echo "Control:  esdaemon status | reload | update | logs | uninstall   (apply config edits: sudo esdaemon reload)"
echo "Check:    log stream --info --predicate 'subsystem == \"com.apple.eslogger\" AND process == \"ESDaemon\"'"
echo "Remove:   sudo esdaemon uninstall"
