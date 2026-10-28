#!/bin/bash
# update-tests.sh — update.sh version check against a release (offline: the release JSON comes from a file).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
# a fake install: update.sh with VERSION and REPO beside it, as install.sh lays it out
mkdir -p "$T/inst"; cp "$ROOT/bin/update.sh" "$T/inst/"; echo "acme/ESDaemon" > "$T/inst/REPO"
rel(){ printf '{"tag_name":"%s","html_url":"https://github.com/acme/ESDaemon/releases/tag/%s"}' "$1" "$1" > "$T/rel.json"; }
run(){ echo "$1" > "$T/inst/VERSION"; ESDAEMON_RELEASE_JSON="$T/rel.json" bash "$T/inst/update.sh" >"$T/out" 2>&1; echo $?; }

echo "-- check: exit 0 = up to date, 10 = update available"
rel v0.1.0; ok "same version -> up to date (0)"           '[ "$(run 0.1.0)" = 0 ] && grep -q "is up to date" "$T/out"'
rel v0.2.0; ok "newer minor -> available (10)"            '[ "$(run 0.1.0)" = 10 ] && grep -q "0.2.0 is available" "$T/out"'
rel v0.1.10; ok "0.1.10 is newer than 0.1.9 (numeric)"    '[ "$(run 0.1.9)" = 10 ]'
rel v1.0.0; ok "major bump -> available"                  '[ "$(run 0.9.9)" = 10 ]'
rel v0.1.0; ok "installed newer than release -> up to date" '[ "$(run 0.2.0)" = 0 ]'
rel 0.3.0;  ok "tag without leading v works"              '[ "$(run 0.2.0)" = 10 ]'
rel v0.2.0; ok "prints the release page and how to install" '[ "$(run 0.1.0)" = 10 ] && grep -q "releases/tag/v0.2.0" "$T/out" && grep -q -- "--install" "$T/out"'
echo "-- errors and --version"
rel v0.1.0; ok "--version prints the installed version"  '[ "$(echo 0.1.0 > "$T/inst/VERSION"; bash "$T/inst/update.sh" --version)" = 0.1.0 ]'
printf '{"message":"Not Found"}' > "$T/rel.json"; ok "no release -> error (1)" '[ "$(run 0.1.0)" = 1 ] && grep -q "no release found" "$T/out"'
echo "OWNER/ESDaemon" > "$T/inst/REPO"; rel v0.2.0; ok "placeholder repo -> clear error" '[ "$(run 0.1.0)" = 1 ] && grep -q "repository not set" "$T/out"'
echo "acme/ESDaemon" > "$T/inst/REPO"
mkdir -p "$T/bare"; cp "$ROOT/bin/update.sh" "$T/bare/"; rel v0.2.0
ok "no VERSION/REPO beside it, no ESDAEMON_REPO -> repository not set (1)" '[ "$(ESDAEMON_REPO= ESDAEMON_RELEASE_JSON="$T/rel.json" bash "$T/bare/update.sh" --check >"$T/out" 2>&1; echo $?)" = 1 ] && grep -q "repository not set" "$T/out" && grep -q "/REPO" "$T/out" && ! grep -q "unbound variable" "$T/out"'
ok "unknown option refused"                               '! bash "$T/inst/update.sh" --bogus >/dev/null 2>&1'
ok "repo VERSION file is x.y.z"                           'grep -Eq "^[0-9]+\.[0-9]+\.[0-9]+$" "$ROOT/VERSION"'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
