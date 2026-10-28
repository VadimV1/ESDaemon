#!/bin/bash
# quick-install-tests.sh — quick-install.sh pairs the prebuilt binary with the SOURCE ref, not always the newest
# release (issue #21). The ref->binary-source mapping lives in release_base(): a pinned release tag takes that
# tag's own release, the default branch tracks the newest release, and any other ref (a branch, or a tag with no
# release) has no asset there, so the download 404s and the install builds from source instead of silently
# grabbing releases/latest. release_base is unit-tested directly; the binary block is then driven with a stubbed
# curl/swiftc to prove a tag uses its own release and a branch falls through to a source build — never latest.
# Offline by design (no network, no jq, no swiftc): the mapping and the branching are checkable on Linux CI.
# shellcheck disable=SC2034  # SRC/REPO/REF/STUB_OK/ESDBIN are read only inside the sed-extracted, eval'd block
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
QI="$ROOT/quick-install.sh"

echo "-- release_base maps a ref to where its binary comes from (unit, no network)"
DEFAULT_REF=main        # the script's own default; asserted below to stay in sync with this value
eval "$(sed -n '/^release_base() {$/,/^}$/p' "$QI")"
ok "a release tag -> that tag's own release, not latest" \
   '[ "$(release_base acme/ESDaemon v0.1.0)" = "https://github.com/acme/ESDaemon/releases/download/v0.1.0" ]'
ok "a different tag -> that other tag's release" \
   '[ "$(release_base acme/ESDaemon v0.2.0)" = "https://github.com/acme/ESDaemon/releases/download/v0.2.0" ]'
ok "the default branch (main) -> the newest release" \
   '[ "$(release_base acme/ESDaemon main)" = "https://github.com/acme/ESDaemon/releases/latest/download" ]'
ok "a feature branch -> its own ref URL (404s -> source build)" \
   '[ "$(release_base acme/ESDaemon feature-x)" = "https://github.com/acme/ESDaemon/releases/download/feature-x" ]'
ok "no tag ever resolves to releases/latest" \
   '! release_base acme/ESDaemon v9.9.9 | grep -q "releases/latest"'
ok "no branch ever resolves to releases/latest" \
   '! release_base acme/ESDaemon some-branch | grep -q "releases/latest"'

echo "-- the script wires release_base in and keeps the integrity + install.sh notes"
ok "DEFAULT_REF is main (matches the unit tests above)"        'grep -Eq "^DEFAULT_REF=\"?main\"?" "$QI"'
ok "the binary URL is built from release_base, per ref"        'grep -q "REL=\"\$(release_base \"\$REPO\" \"\$REF\")\"" "$QI"'
ok "the releases/latest URL is built once, inside release_base" '[ "$(grep -c "releases/latest/download" "$QI")" = 1 ] && grep "releases/latest/download" "$QI" | grep -q "printf"'
ok "the sha256 transit-integrity check is kept"                'grep -q "ESDaemon-macos-universal.sha256" "$QI" && grep -q "shasum -a 256" "$QI"'
ok "the note that install.sh verifies signature+arch is kept"  'grep -q "install.sh verifies its signature and architecture" "$QI"'

echo "-- the binary block, driven with a stubbed curl/swiftc, honours the mapping (no network, no compiler)"
BLOCK="$(sed -n '/^if \[ ! -x "\$SRC\/build\/ESDaemon" \]; then$/,/^fi$/p' "$QI")"
ok "the binary block was extracted"  '[ -n "$BLOCK" ]'
FIXED=deadbeefcafe
# stubs (shell functions shadow PATH): curl records every URL it is asked for and succeeds only for one whose URL
# contains $STUB_OK; swiftc records a source build; shasum prints $FIXED so the stubbed .sha256 matches; say is
# quiet; die exits (the block runs in a subshell, as install-sign-tests runs install.sh's writer block).
say(){ :; }
die(){ echo "die: $*"; exit 1; }
shasum(){ printf '%s  -\n' "$FIXED"; }
curl(){ local o="" u=""
  while [ $# -gt 0 ]; do case "$1" in -o) o="$2"; shift 2;; -*) shift;; *) u="$1"; shift;; esac; done
  printf '%s\n' "$u" >> "$T/curl.log"
  case "$u" in
    *"$STUB_OK"*) if [ -n "$o" ]; then printf 'PREBUILT\n' > "$o"; else printf '%s  -\n' "$FIXED"; fi; return 0;;
  esac
  return 22; }
swiftc(){ case "${1:-}" in --version) return 0;; esac; : > "$ESDBIN"; echo built >> "$T/swiftc.log"; }

# run_block REF STUB_OK -> runs the extracted block in a subshell against a fake checkout; echoes its exit code
run_block(){
  rm -rf "$T/src"; mkdir -p "$T/src/src"; printf 'x\n' > "$T/src/src/ESDaemon.swift"
  : > "$T/curl.log"; : > "$T/swiftc.log"
  SRC="$T/src"; REPO=acme/ESDaemon; REF="$1"; STUB_OK="$2"; ESDBIN="$T/src/build/ESDaemon"
  ( eval "$BLOCK" ) >"$T/out" 2>&1; echo $?
}

echo "-- a pinned release tag uses that tag's own release binary"
rc="$(run_block v0.1.0 releases/download/v0.1.0/)"
ok "the block succeeds"                              '[ "$rc" = 0 ]'
ok "...the prebuilt binary is used, not built"       '[ "$(cat "$T/src/build/ESDaemon" 2>/dev/null)" = PREBUILT ] && [ ! -s "$T/swiftc.log" ]'
ok "...it fetched releases/download/v0.1.0"          'grep -q "releases/download/v0.1.0/ESDaemon-macos-universal" "$T/curl.log"'
ok "...it never fetched releases/latest"             '! grep -q "releases/latest" "$T/curl.log"'

echo "-- a branch (no release at its ref URL) builds from source, never latest"
rc="$(run_block feature-x __no_such_asset__)"
ok "the block succeeds via a source build"           '[ "$rc" = 0 ] && [ -s "$T/swiftc.log" ]'
ok "...it tried the ref's own release URL first"     'grep -q "releases/download/feature-x/ESDaemon-macos-universal" "$T/curl.log"'
ok "...it never fell back to releases/latest"        '! grep -q "releases/latest" "$T/curl.log"'
ok "...no prebuilt binary was left behind"           '[ "$(cat "$T/src/build/ESDaemon" 2>/dev/null)" != PREBUILT ]'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
