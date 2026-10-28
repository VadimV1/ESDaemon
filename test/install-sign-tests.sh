#!/bin/bash
# install-sign-tests.sh — install.sh signs, verifies and arch-checks the ESDaemon writer BEFORE the daemons run
# it, and a failure stops the install loudly without leaving a half-replaced binary live. Three layers:
#   1. static (every platform): install.sh no longer hides a codesign failure (no `codesign ... || true`), it runs
#      `codesign --verify --strict`, it checks the architecture, and the verify gate comes before reload.sh. These
#      fail on a tree without the fix, so they also prove the behaviour change is wired in.
#   2. esd_verify_binary (macOS only): a valid binary passes; a non-Mach-O cannot be signed and is refused; a
#      wrong-architecture binary is refused. Uses the real codesign/lipo, so it is Darwin-only and skips elsewhere.
#   3. the abort path (macOS only): install.sh's own writer block, evaluated on a bad binary, exits non-zero, does
#      NOT run reload.sh (the daemons are not restarted), keeps the previously installed binary live, and leaves no
#      staging copy. A good binary is the positive control: it installs and reaches reload.
# The macOS-only layers need a compiler for a host-arch stand-in binary (CI builds the writer, so one is present);
# where there is none they skip. The non-Mach-O abort case needs no compiler and is the core check.
# shellcheck disable=SC2034  # SRC/BASE/STAGED/PREVBIN/out are read only inside the eval'd block / single-quoted ok() strings
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
IS="$ROOT/install.sh"

echo "-- install.sh no longer hides codesign failures and verifies the result (static, runs everywhere)"
ok "no codesign failure is swallowed (no 'codesign ... || true')"   '! grep -qE "codesign.*\|\|[[:space:]]*true" "$IS"'
ok "no codesign output is discarded (no 'codesign ... 2>/dev/null')" '! grep -qE "codesign.*2>/dev/null" "$IS"'
ok "the writer is ad-hoc signed (codesign -s -)"                     'grep -qE "codesign -s - -f" "$IS"'
ok "the signature is verified (codesign --verify --strict)"          'grep -qF "codesign --verify --strict" "$IS"'
ok "the architecture is checked (lipo -archs and uname -m)"          'grep -qF "lipo -archs" "$IS" && grep -qF "uname -m" "$IS"'
ok "verification is a named gate (esd_verify_binary, defined+called)" '[ "$(grep -c "esd_verify_binary" "$IS")" -ge 2 ]'
ok "a failed verify restores the previous binary (esd_restore_binary)" 'grep -qF "esd_restore_binary" "$IS"'
vn="$(grep -nF 'esd_verify_binary "$STAGED"' "$IS" | head -1 | cut -d: -f1)"
rn="$(grep -nF '"$BASE/reload.sh"' "$IS" | head -1 | cut -d: -f1)"
ok "the writer is verified before reload.sh restarts the daemons"   '[ -n "$vn" ] && [ -n "$rn" ] && [ "$vn" -lt "$rn" ]'

if [ "$(uname -s)" != Darwin ]; then
  echo "-- codesign/lipo tests: skipped (macOS-only; CI's macOS runners and the Mac lab run these)"
else
  # the writer verification and the install.sh writer block, taken out of install.sh by name (running install.sh
  # itself would install for real), exactly as chain-tests extracts install_files.
  eval "$(sed -n '/^esd_verify_binary() {$/,/^}$/p' "$IS")"
  eval "$(sed -n '/^esd_restore_binary() {$/,/^}$/p' "$IS")"
  BLOCK="$(sed -n '/^# The writer binary:/,/reload\.sh"$/p' "$IS")"

  # a host-arch Mach-O stand-in for a good writer (clang targets the host arch, not arm64e, so the arch check
  # matches uname -m); and, if the toolchain can cross-build, a binary for the arch this Mac is NOT.
  printf 'int main(void){return 0;}\n' > "$T/t.c"; host="$(uname -m)"; other=x86_64; [ "$host" = x86_64 ] && other=arm64
  have_good=0; cc -o "$T/good" "$T/t.c" 2>/dev/null && have_good=1
  have_wrong=0; [ "$have_good" = 1 ] && cc -arch "$other" -o "$T/wrong" "$T/t.c" 2>/dev/null && have_wrong=1

  echo "-- esd_verify_binary: sign + codesign --verify --strict + architecture, on real binaries"
  printf 'not a mach-o binary\n' > "$T/text"
  ok "a non-Mach-O cannot be signed and is refused" '! out="$(esd_verify_binary "$T/text" 2>&1)" && printf %s "$out" | grep -q sign'
  if [ "$have_good" = 1 ]; then
    cp "$T/good" "$T/good1"
    ok "a valid host-arch binary passes" 'esd_verify_binary "$T/good1" >/dev/null 2>&1'
  else echo "  skip valid-binary case: no C compiler to build a host-arch stand-in"; fi
  if [ "$have_wrong" = 1 ]; then
    ok "a binary for the wrong architecture is refused" '! out="$(esd_verify_binary "$T/wrong" 2>&1)" && printf %s "$out" | grep -qi "run on this Mac"'
  else echo "  skip wrong-arch case: the toolchain cannot cross-build $other here"; fi

  echo "-- the install.sh writer block aborts cleanly on a bad binary: no restart, previous binary kept"
  # the state at the start of the block: install_files has laid the new (here: bad) binary at $BASE/ESDaemon, and
  # install.sh has backed up the previously installed one at $PREVBIN. A reload.sh that only records being run
  # stands in for the real restart, so the test can tell whether the daemons would have been restarted.
  SRC="$T/nsrc"; BASE="$T/nbase"; mkdir -p "$SRC/build" "$BASE"
  printf 'BAD-NEW\n' > "$SRC/build/ESDaemon"; chmod 755 "$SRC/build/ESDaemon"   # non-Mach-O: signing fails
  STAGED="$BASE/.ESDaemon.staged.$$"; PREVBIN="$BASE/.ESDaemon.prev.$$"
  printf 'OLD-GOOD\n' > "$BASE/ESDaemon"; printf 'OLD-GOOD\n' > "$PREVBIN"
  SENT="$T/nreload.ran"; printf '#!/bin/bash\ntouch %q\n' "$SENT" > "$BASE/reload.sh"; chmod +x "$BASE/reload.sh"
  rc=0; ( eval "$BLOCK" ) >/dev/null 2>&1 || rc=$?
  ok "a bad binary makes the install exit non-zero"      '[ "$rc" != 0 ]'
  ok "...reload.sh is not run (daemons not restarted)"   '[ ! -e "$SENT" ]'
  ok "...the previously installed binary is kept live"   '[ "$(cat "$BASE/ESDaemon")" = OLD-GOOD ]'
  ok "...no staging copy is left behind"                 '[ ! -e "$STAGED" ]'

  if [ "$have_good" = 1 ]; then
    echo "-- the writer block installs and reaches reload on a good binary (positive control)"
    SRC="$T/psrc"; BASE="$T/pbase"; mkdir -p "$SRC/build" "$BASE"
    cp "$T/good" "$SRC/build/ESDaemon"; chmod 755 "$SRC/build/ESDaemon"
    STAGED="$BASE/.ESDaemon.staged.$$"; PREVBIN="$BASE/.ESDaemon.prev.$$"
    printf 'OLD-GOOD\n' > "$BASE/ESDaemon"; printf 'OLD-GOOD\n' > "$PREVBIN"
    SENT="$T/preload.ran"; printf '#!/bin/bash\ntouch %q\n' "$SENT" > "$BASE/reload.sh"; chmod +x "$BASE/reload.sh"
    rc=0; ( eval "$BLOCK" ) >/dev/null 2>&1 || rc=$?
    ok "a good binary makes the install succeed"         '[ "$rc" = 0 ]'
    ok "...reload.sh is run (daemons restarted)"          '[ -e "$SENT" ]'
    ok "...the live binary is the verified one"           'codesign --verify --strict "$BASE/ESDaemon" 2>/dev/null'
    ok "...no staging copy is left behind"                '[ ! -e "$STAGED" ]'
  else echo "  skip positive control: no C compiler to build a host-arch stand-in"; fi
fi

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
