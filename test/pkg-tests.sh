#!/bin/bash
# pkg-tests.sh — static checks for the macOS .pkg installer (bin/mkpkg.sh, its generated postinstall, the uninstall
# receipt cleanup, and the release wiring). pkgbuild / installer / pkgutil are macOS-only, so the real build and
# install cannot run here; these assert the *contract* that keeps a .pkg install identical to a script install, and
# run on any OS the CI uses (Linux or macOS):
#   - the .pkg is a delivery wrapper around install.sh: payload -> an opaque staging dir, postinstall runs
#     install.sh from there and removes staging (so a .pkg install reuses install.sh's cfg-preservation, binary
#     verify + arch gate, and reload — it never lays the final tree itself),
#   - the pkgbuild arguments are the agreed ones and the version comes from VERSION,
#   - the payload carries install.sh and the prebuilt writer binary build/ESDaemon,
#   - the receipt identifier is com.esdaemon.pkg everywhere (mkpkg, both uninstall paths' pkgutil --forget, here),
#   - the release workflow bundles the universal binary into the pkg and attaches the pkg + its .sha256.
# The actual `pkgbuild` run, `installer -pkg … -target /`, pkgutil --forget, and the config/reload/uninstall parity
# are confirmed on the Mac lab / macOS CI — see the hand-back.
# shellcheck disable=SC2034  # MKPKG/REL/POST are read only inside the single-quoted strings ok() evals
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
MKPKG="$ROOT/bin/mkpkg.sh"
REL="$ROOT/.github/workflows/release.yml"

echo "-- bin/mkpkg.sh exists and is valid bash"
ok "mkpkg.sh is present"                         '[ -f "$MKPKG" ]'
ok "mkpkg.sh is bash -n clean"                   'bash -n "$MKPKG"'

echo "-- mkpkg.sh builds the component package with the agreed pkgbuild arguments"
ok "receipt identifier is com.esdaemon.pkg"      'grep -qF "com.esdaemon.pkg" "$MKPKG"'
ok "passes --identifier to pkgbuild"             'grep -q -- "--identifier" "$MKPKG"'
ok "passes --version to pkgbuild"                'grep -q -- "--version" "$MKPKG"'
ok "the version comes from the VERSION file"     'grep -qF "ROOT/VERSION" "$MKPKG"'
ok "installs with --install-location /"          'grep -q -- "--install-location /" "$MKPKG"'
ok "lays the payload with --root"                'grep -q -- "--root" "$MKPKG"'
ok "bundles the postinstall with --scripts"      'grep -q -- "--scripts" "$MKPKG"'
ok "output is build/ESDaemon-<version>.pkg"      'grep -qE "build/ESDaemon-.*\.pkg" "$MKPKG"'
ok "optional signing keys off ESDAEMON_PKG_SIGN_ID" 'grep -qF "ESDAEMON_PKG_SIGN_ID" "$MKPKG" && grep -q -- "--sign" "$MKPKG"'
ok "ensures a prebuilt build/ESDaemon (builds if missing)" 'grep -qF "build/ESDaemon" "$MKPKG" && grep -qE "make -C .*build" "$MKPKG"'

echo "-- the payload stages the sources install.sh needs, under an opaque dir (NOT the final tree)"
ok "staging dir is /Library/ESDaemon/pkg-staging" 'grep -qF "STAGING_ABS=/Library/ESDaemon/pkg-staging" "$MKPKG"'
ok "staging is not the final /usr/local tree"     '! grep -qF "STAGING_ABS=/usr/local/ESDaemon" "$MKPKG"'
ok "payload copies install.sh"                    'grep -qE "cp .*install.sh" "$MKPKG"'
ok "payload copies bin/ src/ configs/"            'grep -qE "cp -R .*bin.*src.*configs" "$MKPKG"'
ok "payload copies VERSION and REPO"              'grep -qE "cp .*VERSION.*REPO" "$MKPKG"'
ok "payload carries the prebuilt writer binary"   'grep -qF "STAGE/build/ESDaemon" "$MKPKG"'

echo "-- the generated postinstall runs install.sh from staging, then removes staging (and pins PATH)"
POST="$(sed -n '/<<POSTINSTALL/,/^POSTINSTALL$/p' "$MKPKG" | sed '1d;$d')"
ok "the postinstall block was extracted"          '[ -n "$POST" ]'
ok "postinstall is bash -n clean"                 'printf "%s\n" "$POST" | bash -n'
ok "postinstall pins PATH to the system dirs"     'printf "%s\n" "$POST" | grep -qF "export PATH=/usr/bin:/bin:/usr/sbin:/sbin"'
ok "postinstall runs install.sh"                  'printf "%s\n" "$POST" | grep -qE "bash .*install.sh"'
ok "...from the staging dir"                       'printf "%s\n" "$POST" | grep -qF "STAGING_ABS/install.sh"'
ok "postinstall removes the staging dir"          'printf "%s\n" "$POST" | grep -qE "rm -rf .*STAGING_ABS"'
ok "postinstall never lays the final tree itself" '! printf "%s\n" "$POST" | grep -v "^[[:space:]]*#" | grep -qF "/usr/local/ESDaemon"'

echo "-- uninstall forgets the pkg receipt on both removal paths, same identifier, best-effort"
ok "uninstall.sh: pkgutil --forget com.esdaemon.pkg" 'grep -qF "forget com.esdaemon.pkg" "$ROOT/uninstall.sh"'
ok "bin/esdaemon: pkgutil --forget com.esdaemon.pkg" 'grep -qF "forget com.esdaemon.pkg" "$ROOT/bin/esdaemon"'
ok "uninstall.sh forget is best-effort"           'grep -qF "forget com.esdaemon.pkg 2>/dev/null" "$ROOT/uninstall.sh"'
ok "bin/esdaemon forget is best-effort"           'grep -qF "forget com.esdaemon.pkg 2>/dev/null" "$ROOT/bin/esdaemon"'

echo "-- the release workflow bundles the universal binary into the pkg and attaches it"
ok "release.yml builds the pkg"                   'grep -qE "make pkg|mkpkg.sh" "$REL"'
ok "release.yml puts the universal binary at build/ESDaemon" 'grep -qF "cp build/ESDaemon-macos-universal build/ESDaemon" "$REL"'
ok "release.yml attaches ESDaemon-<version>.pkg"  'grep -qE "ESDaemon-.*\.pkg" "$REL"'
ok "release.yml publishes the pkg .sha256"        'grep -qF "pkg.sha256" "$REL"'
ok "the pkg is in both release asset lists"       '[ "$(grep -cE "ESDaemon-[^ ]*\.pkg" "$REL")" -ge 2 ]'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
