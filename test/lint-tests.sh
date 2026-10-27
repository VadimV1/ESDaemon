#!/bin/bash
# lint-tests.sh — make lint on the trees people actually have: a git clone, a copy whose files lost the execute bit
# (ZIP download, copy from Windows) and a release tarball without .git. The README starts with sudo ./quick-install.sh,
# so a clone must get every script executable: lint fails on a script committed without the bit, and reads the mode
# from the git index, never from the files on disk. Each case runs make lint in a throwaway copy of this tree.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
command -v make >/dev/null && command -v git >/dev/null || { echo "make or git not installed, skipped"; exit 0; }
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE   # set when run from a git hook; git must only touch the throwaway repo
# the copy as a clone gets it: its own repo, every script 100755 in the index. shellcheck is stubbed (slow, not tested here)
mkdir -p "$T/clone" "$T/stub"; cp -R "$ROOT"/* "$T/clone"/; printf '#!/bin/sh\n' > "$T/stub/shellcheck"; chmod +x "$T/stub/shellcheck"
{ git -C "$T/clone" init -q && git -C "$T/clone" add -A && git -C "$T/clone" add --chmod=+x -- '*.sh' bin/esdaemon; } >/dev/null 2>&1
lint(){ (cd "$T/clone" && PATH="$T/stub:$PATH" make lint) >"$T/out" 2>&1; echo $?; }

echo "-- a clone: every script committed executable"
ok "lint passes"                                  '[ "$(lint)" = 0 ] && grep -qx "exec bits ok" "$T/out"'

echo "-- a script committed without the execute bit fails lint, by name, whatever its bit on disk"
for f in quick-install.sh bin/esdaemon redteam/lib.sh; do
  chmod +x "$T/clone/$f"; git -C "$T/clone" update-index --chmod=-x "$f"
  ok "$f at 100644 fails"                         '[ "$(lint)" != 0 ] && grep -qx "not executable in git, fix: git update-index --chmod=+x $f" "$T/out"'
  git -C "$T/clone" update-index --chmod=+x "$f"
done

echo "-- a copy that lost its execute bits (ZIP, Windows) still lints: cfg.sh is bash-invoked, modes come from git"
chmod a-x "$T"/clone/*.sh "$T"/clone/bin/* "$T"/clone/test/*.sh "$T"/clone/redteam/*.sh
ok "lint passes"                                  '[ "$(lint)" = 0 ] && grep -qx "cfg ok" "$T/out" && grep -qx "exec bits ok" "$T/out"'

echo "-- a release tarball (no .git): the check is skipped with a one-line notice"
rm -rf "$T/clone/.git"
ok "lint passes, says the check was skipped"      '[ "$(lint)" = 0 ] && [ "$(grep -c "exec-bit check skipped" "$T/out")" = 1 ]'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
