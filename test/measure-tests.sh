#!/bin/bash
# measure-tests.sh — measure.sh's leftover capture. raw.ndjson is eslogger's output untouched, so it holds
# each process's full environment (tokens, secrets). It is kept (try.sh dry-runs a config against it), so the
# closing note must tell the operator it is there, what it holds, and how to delete it, and the capture dir
# must stay owner-only. measure.sh needs root, macOS, /usr/bin/eslogger and a timed capture, so it cannot run
# here or in CI; these check the operator-facing note and the capture-dir mode on the script itself, the way
# control-tests.sh checks a property of uninstall.sh. The full interactive run is covered by the Mac test plan.
# shellcheck disable=SC2034  # $M is read only inside the single-quoted strings ok() evals, which look unused
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; M="$HERE/../bin/measure.sh"
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }

echo "-- the capture directory stays owner-only"
ok "created with mktemp -d (mode 700)"       'grep -q "mktemp -d" "$M"'
ok "nothing widens the capture dir mode"     '! grep -Eq "chmod.+TMP" "$M"'

echo "-- the closing note names the capture, warns it holds environments, and gives the delete command"
ok "names raw.ndjson"                         'grep -q "raw\.ndjson" "$M"'
ok "still prints where the samples are kept"  'grep -E "^[[:space:]]*echo" "$M" | grep -qE "samples.*TMP"'
ok "a printed line warns of environments"     'grep -E "^[[:space:]]*echo" "$M" | grep -qi "environment"'
ok "a printed line warns of tokens/secrets"   'grep -E "^[[:space:]]*echo" "$M" | grep -qiE "secret|token"'
ok "the delete command is rm -rf of TMP"      'grep -E "^[[:space:]]*echo" "$M" | grep -qE "rm -rf.*TMP"'

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
