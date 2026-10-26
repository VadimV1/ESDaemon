#!/bin/bash
# quick-install.sh — install ESDaemon in one step: get the source, get or build the binary, install, check.
#   from a checkout:  sudo ./quick-install.sh
#   without one:      curl -fsSL https://raw.githubusercontent.com/<owner>/ESDaemon/main/quick-install.sh | sudo bash
# Environment (optional):
#   ESDAEMON_REPO   GitHub owner/repo to fetch from (default below)
#   ESDAEMON_REF    branch or tag to install (default: main)
# Safe to re-run: an existing (tuned) config is kept, an older one is migrated, see install.sh.
set -euo pipefail
DEFAULT_REPO="OWNER/ESDaemon"            # set to the published owner/repo
REPO="${ESDAEMON_REPO:-$DEFAULT_REPO}"; REF="${ESDAEMON_REF:-main}"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
die()  { printf 'quick-install: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "macOS only"
[ "$(id -u)" = 0 ] || die "run as root: sudo $0"
MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
[ "$MAJOR" -ge 15 ] 2>/dev/null || die "macOS 15 or later is required (found $(sw_vers -productVersion)): ESDaemon uses /usr/bin/jq"
[ -x /usr/bin/jq ] || die "/usr/bin/jq not found (macOS 15+ ships it)"
[ -x /usr/bin/eslogger ] || die "/usr/bin/eslogger not found"

# 1. source: this checkout, or a tarball of $REPO@$REF
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$HERE" ] && [ -f "$HERE/install.sh" ] && [ -f "$HERE/src/scope.jq" ]; then
  SRC="$HERE"; say "using this checkout: $SRC"
else
  [ "$REPO" != "OWNER/ESDaemon" ] || die "set ESDAEMON_REPO=<owner>/ESDaemon (or edit DEFAULT_REPO in this script)"
  WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
  say "downloading $REPO@$REF"
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xz -C "$WORK" || die "download failed: https://github.com/$REPO (ref $REF)"
  SRC="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)"
fi

# the checkout names its own repo (REPO file), so a clone needs no environment variable
if [ "$REPO" = "OWNER/ESDaemon" ] && [ -f "$SRC/REPO" ]; then REPO="$(tr -d ' \r\n' < "$SRC/REPO")"; fi

# 2. binary: a prebuilt release asset, else build it (Xcode Command Line Tools)
if [ ! -x "$SRC/build/ESDaemon" ]; then
  mkdir -p "$SRC/build"
  REL="https://github.com/$REPO/releases/latest/download"
  if [ "$REPO" != "OWNER/ESDaemon" ] && curl -fsSL -o "$SRC/build/ESDaemon" "$REL/ESDaemon-macos-universal" 2>/dev/null \
     && WANT="$(curl -fsSL "$REL/ESDaemon-macos-universal.sha256" 2>/dev/null | awk '{print $1}')" \
     && [ -n "$WANT" ] && [ "$(shasum -a 256 "$SRC/build/ESDaemon" | awk '{print $1}')" = "$WANT" ]; then
    chmod 755 "$SRC/build/ESDaemon"; say "using the prebuilt release binary (sha256 verified)"
  elif command -v swiftc >/dev/null 2>&1 && swiftc --version >/dev/null 2>&1; then
    rm -f "$SRC/build/ESDaemon"; say "building ESDaemon (swiftc)"
    swiftc -O -o "$SRC/build/ESDaemon" "$SRC/src/ESDaemon.swift"
  else
    rm -f "$SRC/build/ESDaemon"
    die "no prebuilt binary and no compiler: install the Command Line Tools (xcode-select --install) and re-run"
  fi
fi

# 3. install (validates the config first; nothing changes if it is invalid)
say "installing to /usr/local/ESDaemon"
bash "$SRC/install.sh"   # bash-invoked: a GitHub tarball/ZIP (or a Windows push) may drop the execute bit

# 4. check: is eslogger allowed to run, and do events arrive?
sleep 3
if grep -qiE 'not.?permitted|full disk access|TCC' /var/log/ESDaemon/eslogger.stderr 2>/dev/null; then
  cat <<'MSG'

ESDaemon is installed, but eslogger does not have Full Disk Access yet, so no events are produced.
Grant it once, then events start on their own (no reinstall needed):
  - one Mac: System Settings > Privacy & Security > Full Disk Access > + > Cmd-Shift-G > /usr/bin/eslogger
  - a fleet: deploy mdm/esdaemon-eslogger-fda.mobileconfig with your MDM
MSG
  exit 0
fi
MARK="esdaemon-install-check-$$"
/bin/sh -c "true $MARK"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  if /usr/bin/log show --last 30s --predicate 'subsystem == "com.apple.eslogger"' --style ndjson 2>/dev/null | grep -q "$MARK"; then
    say "events are flowing to the unified log (subsystem com.apple.eslogger)"
    echo "    watch:  log stream --info --predicate 'subsystem == \"com.apple.eslogger\" AND process == \"ESDaemon\"'"
    echo "    config: /usr/local/ESDaemon/configs/ESDaemon.cfg  (apply edits: sudo /usr/local/ESDaemon/reload.sh)"
    exit 0
  fi
done
cat <<'MSG'

ESDaemon is installed, but no test event showed up in 10 seconds. Most often eslogger lacks Full Disk Access:
  System Settings > Privacy & Security > Full Disk Access > + > Cmd-Shift-G > /usr/bin/eslogger
Then check:  sudo launchctl print system/com.esdaemon.eslogger | grep -E 'state|last exit'
             cat /var/log/ESDaemon/*.stderr
MSG
