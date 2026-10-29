#!/bin/bash
# path-tests.sh — every script that can run as root pins PATH to the system directories before its first external
# command. macOS sudo keeps the caller's PATH (there is no secure_path), so without the pin a bare tool name — jq,
# launchctl, install, curl, tar, codesign, dscl, awk ... — resolves through the admin's PATH, and anyone who can
# change that environment could get their own binary run as root during an install or reload.
# This is a static check: it greps the scripts, it never runs them, so it is unaffected by which jq is on PATH and
# passes identically here and in CI.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT" || exit 1
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }

# The class, enumerated (not hard-listed) so a script added later is covered automatically: every standalone entry
# point and every bin/ helper a root user runs directly or through launchd/sudo —
#   install.sh uninstall.sh quick-install.sh, bin/esdaemon, bin/*.sh, redteam/*.sh
# minus the files that are only ever *sourced* (never executed standalone) and so inherit their caller's pinned PATH:
#   bin/chain.sh, bin/jqcheck.sh  (sourced by install.sh / reload.sh / esdaemon, all pinned below)
#   redteam/lib.sh, redteam/scenarios.sh  (sourced by redteam/run.sh, pinned below)
# test/*.sh are developer harnesses, not root entry points, so they are out of scope — and so is bin/mkpkg.sh, a
# build tool a developer / CI runs as a normal user (never as root) to make the .pkg: it may use the caller's PATH
# to reach the Swift toolchain / pkgbuild, so the root-PATH-pin rule does not apply (the postinstall it generates,
# which DOES run as root, pins PATH like the install scripts).
SOURCED_ONLY=" bin/chain.sh bin/jqcheck.sh redteam/lib.sh redteam/scenarios.sh "
BUILD_TOOLS=" bin/mkpkg.sh "
candidates=()
for f in install.sh uninstall.sh quick-install.sh bin/esdaemon bin/*.sh redteam/*.sh; do
  [ -f "$f" ] || continue
  case "$SOURCED_ONLY$BUILD_TOOLS" in *" $f "*) continue ;; esac
  candidates+=("$f")
done

# Pass = the exact pin is present AND nothing runs before it: every line above the pin is the shebang, a comment, a
# blank line, or the single `set -...` line. That is precisely "before the first external command".
pinned_before_first_command(){   # $1 = file
  local f="$1" pn before
  pn="$(grep -nE '^[[:space:]]*export PATH=/usr/bin:/bin:/usr/sbin:/sbin[[:space:]]*$' "$f" | head -1 | cut -d: -f1)"
  [ -n "$pn" ] || { echo "    $f: no 'export PATH=/usr/bin:/bin:/usr/sbin:/sbin'" >&2; return 1; }
  before="$(head -n "$((pn - 1))" "$f" | grep -vE '^[[:space:]]*#|^[[:space:]]*$|^[[:space:]]*set -' || true)"
  [ -z "$before" ] || { echo "    $f: a command runs before PATH is pinned:" >&2; printf '      %s\n' "$before" >&2; return 1; }
  return 0
}

echo "-- every root-runnable script pins PATH=/usr/bin:/bin:/usr/sbin:/sbin before its first external command"
for f in "${candidates[@]}"; do ok "$f" "pinned_before_first_command '$f'"; done

# Guards so the check can't silently pass with nothing (or the wrong set) examined.
ok "the root-runnable class is non-empty" '[ "${#candidates[@]}" -gt 0 ]'
# The sourced-only exclusions really are sourced-only: none opens with a standalone options prologue (a column-0
# `set -e`/`-u`/`-o`, as every entry point here does; an indented `set --` for positional params does not count). If
# one ever gains that prologue it is being run directly and must move into the pinned set above instead of skipped.
for f in bin/chain.sh bin/jqcheck.sh redteam/lib.sh redteam/scenarios.sh; do
  ok "$f excluded as sourced-only (no top-level options prologue)" "[ -f '$f' ] && ! grep -qE '^set -[euox]' '$f'"
done

echo; echo "PASS $pass  FAIL $fail"; [ "$fail" -eq 0 ]
