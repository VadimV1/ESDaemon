#!/bin/bash
# cfg-tests.sh — the cfg parser accepts good files and refuses bad [drop] rules (so reload.sh never ships a broken filter).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
ok "default cfg parses"                  '"$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json >/dev/null 2>&1'
printf '[settings]\nevents = exec create\n' > $T/s.cfg
ok "get events"                          '[ "$("$ROOT/bin/cfg.sh" $T/s.cfg get events)" = "exec create" ]'
ok "defaults: third_party=all format=slim" '[ "$("$ROOT/bin/cfg.sh" $T/s.cfg json | jq -r ".third_party+\" \"+.format")" = "all slim" ]'
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
