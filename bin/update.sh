#!/bin/bash
# update.sh — compare the installed ESDaemon with the latest GitHub release, and optionally install it.
#   /usr/local/ESDaemon/update.sh             check only: installed vs latest version
#   sudo /usr/local/ESDaemon/update.sh --install   install the latest release (config kept, see install.sh)
#   /usr/local/ESDaemon/update.sh --version   print the installed version
# Exit code of a check: 0 = up to date, 10 = an update is available, 1 = could not check.
# Environment (optional): ESDAEMON_REPO (owner/repo, default: the REPO file installed next to this script),
#   ESDAEMON_RELEASE_JSON (read the release from this file instead of the GitHub API; used by the tests).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# installed copy: VERSION / REPO next to this script; from a checkout: in the repo root
for d in "$HERE" "$HERE/.."; do [ -f "$d/VERSION" ] && { VFILE="$d/VERSION"; RFILE="$d/REPO"; break; }; done
INSTALLED="$(tr -d ' \r\n' < "${VFILE:-/dev/null}" 2>/dev/null || true)"; INSTALLED="${INSTALLED:-0.0.0}"
REPO="${ESDAEMON_REPO:-$(tr -d ' \r\n' < "${RFILE:-/dev/null}" 2>/dev/null || true)}"

die() { echo "update: $*" >&2; exit 1; }
# newer A B: true when version A is newer than B (numeric x.y.z compare; a leading v is ignored)
newer() {
  local a="${1#v}" b="${2#v}" i x y
  IFS=. read -r -a A <<< "${a%%[-+]*}"; IFS=. read -r -a B <<< "${b%%[-+]*}"
  for i in 0 1 2; do
    x="${A[$i]:-0}"; y="${B[$i]:-0}"
    [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]] || return 1
    ((10#$x > 10#$y)) && return 0
    ((10#$x < 10#$y)) && return 1
  done
  return 1
}

case "${1:-}" in
  --version) echo "$INSTALLED"; exit 0 ;;
  ""|--check|--install) ;;
  *) die "usage: update.sh [--check | --install | --version]" ;;
esac
[ -n "$REPO" ] && [ "$REPO" != "OWNER/ESDaemon" ] || die "repository not set: put owner/repo in $RFILE or set ESDAEMON_REPO"

if [ -n "${ESDAEMON_RELEASE_JSON:-}" ]; then JSON="$(cat "$ESDAEMON_RELEASE_JSON")"
else JSON="$(curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$REPO/releases/latest")" \
       || die "could not reach GitHub (https://github.com/$REPO/releases)"; fi
TAG="$(printf '%s' "$JSON" | jq -r '.tag_name // empty')"; [ -n "$TAG" ] || die "no release found for $REPO"
LATEST="${TAG#v}"; URL="$(printf '%s' "$JSON" | jq -r '.html_url // empty')"

if ! newer "$LATEST" "$INSTALLED"; then
  echo "ESDaemon $INSTALLED is up to date (latest release: $LATEST)"; exit 0
fi
echo "ESDaemon $LATEST is available (installed: $INSTALLED)${URL:+  $URL}"
if [ "${1:-}" != --install ]; then echo "install it with: sudo $HERE/update.sh --install"; exit 10; fi

[ "$(id -u)" = 0 ] || die "run as root to install: sudo $0 --install"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$TAG" | tar -xz -C "$WORK" || die "download of $TAG failed"
SRC="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)"
ESDAEMON_REPO="$REPO" ESDAEMON_REF="$TAG" bash "$SRC/quick-install.sh"
echo "ESDaemon updated: $INSTALLED -> $(tr -d ' \r\n' < /usr/local/ESDaemon/VERSION)"
