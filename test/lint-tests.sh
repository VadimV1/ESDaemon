#!/bin/bash
# lint-tests.sh — make lint on the trees people actually have: a git clone, a copy whose files lost the execute bit
# (ZIP download, copy from Windows) and a release tarball without .git. The README starts with sudo ./quick-install.sh,
# so a clone must get every script executable: lint fails on a script committed without the bit, and reads the mode
# from the git index, never from the files on disk. Each case runs make lint in a throwaway copy of this tree.
# Line endings the same way: a clone made with core.autocrlf=true (Git for Windows' default) checks out LF, and lint
# fails on a file committed with CRLF: once in git, every checkout gets it, .gitattributes or not.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
command -v make >/dev/null && command -v git >/dev/null || { echo "make or git not installed, skipped"; exit 0; }
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE   # set when run from a git hook; git must only touch the throwaway repo
# the copy as a clone gets it: its own repo, every script 100755 in the index. shellcheck is stubbed: slow, and make lint
# runs the real one on this tree anyway; here only lint's handling of its exit status is tested
mkdir -p "$T/clone" "$T/stub"; cp -R "$ROOT"/* "$ROOT"/.gitattributes "$ROOT"/.gitignore "$T/clone"/; printf '#!/bin/sh\n' > "$T/stub/shellcheck"; chmod +x "$T/stub/shellcheck"
{ git -C "$T/clone" init -q && git -C "$T/clone" add -A && git -C "$T/clone" add --chmod=+x -- '*.sh' bin/esdaemon; } >/dev/null 2>&1
lint(){ (cd "$T/clone" && PATH="$T/stub:$PATH" make lint) >"$T/out" 2>&1; echo $?; }
# put $1 in git with CRLF, as a commit made outside git add would; the copy on disk keeps LF
crlf_in_git(){ local m h; m=$(git -C "$T/clone" ls-files -s "$1" | cut -c1-6)
  h=$(awk '{ printf "%s\r\n", $0 }' "$T/clone/$1" | git -C "$T/clone" hash-object -w --stdin); git -C "$T/clone" update-index --cacheinfo "$m,$h,$1"; }

echo "-- a clone: every script committed executable"
ok "lint passes"                                  '[ "$(lint)" = 0 ] && grep -qx "exec bits ok" "$T/out"'

echo "-- a syntax error in any script or a shellcheck finding fails lint; shellcheck is skipped only when it is missing"
cp "$T/clone/install.sh" "$T/install.sh"; echo 'if then' >> "$T/clone/install.sh"   # install.sh is checked first, not last
ok "syntax error in install.sh fails, by name"    '[ "$(lint)" != 0 ] && grep -qx "syntax errors in: install.sh" "$T/out"'
cp "$T/install.sh" "$T/clone/install.sh"
printf '#!/bin/sh\necho "install.sh:1:1: warning: stub finding"\nexit 1\n' > "$T/stub/shellcheck"
ok "shellcheck finding fails, not reported as not installed" '[ "$(lint)" != 0 ] && grep -qx "install.sh:1:1: warning: stub finding" "$T/out" && ! grep -q "not installed" "$T/out"'
# no shellcheck on PATH: the stub removed, and a directory holding a real one (CI's Linux: /usr/bin) swapped for links to the rest of it
rm "$T/stub/shellcheck"; nosc=""; i=0; IFS=: read -ra dirs <<< "$PATH"
for d in "${dirs[@]}"; do
  [ -e "$d/shellcheck" ] && { i=$((i+1)); mkdir "$T/path$i"; ln -s "$d"/* "$T/path$i"; rm "$T/path$i/shellcheck"; d="$T/path$i"; }
  nosc="$nosc${nosc:+:}$d"
done
PATH="$nosc" ok "shellcheck missing: skipped with a notice, the rest still checked" '[ "$(lint)" = 0 ] && grep -qx "shellcheck not installed, skipped" "$T/out" && grep -qx "syntax ok" "$T/out" && grep -qx "exec bits ok" "$T/out"'
printf '#!/bin/sh\n' > "$T/stub/shellcheck"; chmod +x "$T/stub/shellcheck"

echo "-- a script committed without the execute bit fails lint, by name, whatever its bit on disk"
for f in quick-install.sh bin/esdaemon redteam/lib.sh; do
  chmod +x "$T/clone/$f"; git -C "$T/clone" update-index --chmod=-x "$f"
  ok "$f at 100644 fails"                         '[ "$(lint)" != 0 ] && grep -qx "not executable in git, fix: git update-index --chmod=+x $f" "$T/out"'
  git -C "$T/clone" update-index --chmod=+x "$f"
done

echo "-- a clone made with core.autocrlf=true (Git for Windows' default): every text file checks out LF and lints"
rm -rf "$T"/clone/*; git -C "$T/clone" -c core.autocrlf=true checkout -- . >/dev/null 2>&1
ok "no file checks out CRLF"                      '! git -C "$T/clone" ls-files --eol | grep -qE "^i/[^ ]+ +w/(crlf|mixed)"'
ok "lint passes"                                  '[ "$(lint)" = 0 ] && grep -qx "cfg ok" "$T/out" && grep -qx "line endings ok" "$T/out"'

echo "-- a file committed with CRLF fails lint, by name, whatever its line endings on disk"
for f in quick-install.sh bin/esdaemon src/scope.jq; do
  crlf_in_git "$f"
  ok "$f with CRLF fails"                         '[ "$(lint)" != 0 ] && grep -qx "CRLF in git, fix: git add --renormalize $f" "$T/out"'
  git -C "$T/clone" add --renormalize -- "$f"
done

echo "-- a copy that lost its execute bits (ZIP, Windows) still lints: cfg.sh is bash-invoked, modes come from git"
chmod a-x "$T"/clone/*.sh "$T"/clone/bin/* "$T"/clone/test/*.sh "$T"/clone/redteam/*.sh
ok "lint passes"                                  '[ "$(lint)" = 0 ] && grep -qx "cfg ok" "$T/out" && grep -qx "exec bits ok" "$T/out"'

echo "-- a release tarball (no .git): the git checks are skipped, each with a one-line notice"
rm -rf "$T/clone/.git"
ok "lint passes, says the check was skipped"      '[ "$(lint)" = 0 ] && [ "$(grep -c "exec-bit check skipped" "$T/out")" = 1 ]'
ok "says the line-ending check was skipped"       '[ "$(lint)" = 0 ] && [ "$(grep -c "line-ending check skipped" "$T/out")" = 1 ]'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
