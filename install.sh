#!/bin/bash
# install.sh — install/refresh ESDaemon (run as root, macOS 15+). Safe to re-run.
#   com.esdaemon.eslogger : /usr/bin/eslogger <events> -> FIFO   (FDA on /usr/bin/eslogger only)
#   com.esdaemon.filter   : FIFO -> filter -> unified log         (no FDA)
set -euo pipefail
# fixed PATH: this can run as root, and macOS sudo keeps the caller's PATH — so bare tool names resolve to system binaries
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
SRC="$(cd "$(dirname "$0")" && pwd)"; BASE=/usr/local/ESDaemon; LD=/Library/LaunchDaemons
# The daemons run as root from $BASE: before anything in it is used or changed, stop unless only root can change it,
# what is in it, and every directory above it (bin/chain.sh).
# shellcheck source=bin/chain.sh
. "$SRC/bin/chain.sh"; esd_gate "$BASE" install.sh || exit 1
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
CFG="$(bash "$SRC/bin/cfg.sh" "$CFGF" json)" || { echo "$CFGF is invalid for this version: fix it and re-run install.sh (nothing changed)"; exit 1; }
# check that this Mac's jq runs THIS version's filter with that cfg too (bin/jqcheck.sh): otherwise the filter daemon
# is the first to compile it, and on a jq that cannot, it restarts every few seconds and collects nothing
# shellcheck source=bin/jqcheck.sh
. "$SRC/bin/jqcheck.sh"
esd_jq_check "$SRC/src/scope.jq" "$CFG" install.sh \
  || { [ -z "$MIG" ] || echo "The config it ran with: $BASE/configs/ESDaemon.cfg, migrated to this version (migrated draft: $MIG)." >&2; exit 1; }

# retire the old unfiltered daemon, it would flood the same subsystem
if [ -f $LD/com.endpoint.eslogger.plist ]; then launchctl bootout system $LD/com.endpoint.eslogger.plist 2>/dev/null || true; mv $LD/com.endpoint.eslogger.plist $LD/com.endpoint.eslogger.plist.disabled; fi

# install_files <src> <base> <bin> [uid] [gid] [top]: lay out <base> from the checkout <src>, owned by <uid>:<gid>
# (default root:wheel). test/chain-tests.sh runs it on a temporary tree, as its own user.
#  - Directories are created only when missing: install -d re-owns an existing one, such as Homebrew's /usr/local/bin.
#  - The control command goes in as <base>/bin/esdaemon: on a case-insensitive APFS, <base>/esdaemon is the ESDaemon
#    writer's own file. It also goes on PATH in <bin>, but only where nobody but <uid> can change <bin> (esd_root_only):
#    there CMD=esdaemon. Otherwise a copy an earlier install left in <bin> is removed, and CMD is the one in the tree.
install_files() {
  local src="$1" base="$2" bin="$3" uid="${4:-0}" gid="${5:-0}" d
  for d in "$base" "$base/bin" "$base/configs"; do [ -d "$d" ] || install -d -o "$uid" -g "$gid" -m 755 "$d"; done
  install -o "$uid" -g "$gid" -m 755 "$src"/bin/{chain.sh,cfg.sh,filter.sh,jqcheck.sh,measure.sh,reload.sh,try.sh,update.sh} "$base/"
  install -o "$uid" -g "$gid" -m 755 "$src/bin/esdaemon" "$base/bin/"   # the control command (status/reload/update/uninstall)
  if BINWHY="$(esd_root_only "$bin" "$uid" "${6:-/}")"; then
    CMD=esdaemon
    [ -d "$bin" ] || install -d -o "$uid" -g "$gid" -m 755 "$bin"
    install -o "$uid" -g "$gid" -m 755 "$src/bin/esdaemon" "$bin/"
  else
    CMD="$base/bin/esdaemon"
    if [ -e "$bin/esdaemon" ] || [ -L "$bin/esdaemon" ]; then   # an earlier install's, now replaceable
      if rm -f "$bin/esdaemon"; then echo "removed $bin/esdaemon: other users can replace files there"
      else echo "could not remove $bin/esdaemon: do not run it, other users can replace it" >&2; fi
    fi
  fi
  install -o "$uid" -g "$gid" -m 644 "$src"/VERSION "$src"/REPO "$base/"   # what update.sh compares against
  install -o "$uid" -g "$gid" -m 644 "$src"/src/{scope.jq,ESDaemon.swift} "$base/"
  [ -f "$base/configs/ESDaemon.cfg" ] || install -o "$uid" -g "$gid" -m 644 "$src/configs/ESDaemon.cfg" "$base/configs/"   # never overwrite a tuned cfg
  [ ! -x "$src/build/ESDaemon" ] || install -o "$uid" -g "$gid" -m 755 "$src/build/ESDaemon" "$base/"   # else swiftc, below
}
install_files "$SRC" "$BASE" /usr/local/bin
if [ -n "$MIG" ]; then
  OLD="$BASE/configs/ESDaemon.cfg.v1"; [ ! -e "$OLD" ] || OLD="$BASE/configs/ESDaemon.cfg.$(date +%Y%m%d-%H%M%S)"   # never overwrite an earlier backup
  mv "$BASE/configs/ESDaemon.cfg" "$OLD"
  install -o root -g wheel -m 644 "$MIG" "$BASE/configs/ESDaemon.cfg"; rm -f "$MIG"
  echo "migrated $BASE/configs/ESDaemon.cfg to this version ([modules], [include]/[exclude]); old file: $OLD"
fi

if   [ -x "$SRC/build/ESDaemon" ]; then :   # installed by install_files
elif command -v swiftc >/dev/null; then swiftc -O -o "$BASE/ESDaemon" "$SRC/src/ESDaemon.swift"
else echo "need prebuilt build/ESDaemon (make build) or swiftc (xcode-select --install)"; exit 1; fi
codesign -s - -f "$BASE/ESDaemon" 2>/dev/null || true
rm -f "$BASE/uls-writer" "$BASE/uls-writer.swift"   # pre-rename writer

"$BASE/reload.sh"
echo "ESDaemon $(cat "$BASE/VERSION") installed. Config: $BASE/configs/ESDaemon.cfg"
echo "Control:  $CMD status | reload | update | logs | uninstall   (apply config edits: sudo $CMD reload)"
if [ "$CMD" != esdaemon ]; then
  echo "          (not in /usr/local/bin: other users can replace files there, and this command runs as root)"
  printf '%s\n' "$BINWHY" | sed 's/; fix: .*//; s/^ */          /'
fi
echo "Check:    log stream --info --predicate 'subsystem == \"com.apple.eslogger\" AND process == \"ESDaemon\"'"
echo "Remove:   sudo $CMD uninstall"
