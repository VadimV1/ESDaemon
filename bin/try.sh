#!/bin/bash
# try.sh — dry-run a cfg against a saved eslogger capture, without touching the running daemon.
# Usage: bin/try.sh <capture.ndjson> [cfg=configs/ESDaemon.cfg]
#   capture: raw eslogger JSON, e.g. from measure.sh (it prints where it saved raw.ndjson)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; CAP="${1:?capture.ndjson}"
if [ -f "$HERE/scope.jq" ]; then JQF="$HERE/scope.jq"; DEF="$HERE/configs/ESDaemon.cfg"; else JQF="$HERE/../src/scope.jq"; DEF="$HERE/../configs/ESDaemon.cfg"; fi
CFGF="${2:-$DEF}"; CFG="$("$HERE/cfg.sh" "$CFGF" json)"
OUT="$(mktemp)"; jq -n -cR --argjson cfg "$(echo "$CFG" | jq -c '.format="slim"')" -f "$JQF" < "$CAP" > "$OUT"
RB=$(wc -c < "$CAP"); RN=$(wc -l < "$CAP"); KB=$(wc -c < "$OUT"); KN=$(wc -l < "$OUT")
echo "raw  $RN events $RB bytes"; echo "kept $KN events $KB bytes ($(( RB ? KB*100/RB : 0 ))% of raw bytes)"
echo "-- top kept images:"; jq -r '.exec.target.path // .event' "$OUT" | sort | uniq -c | sort -rn | head -25
echo "kept events: $OUT"
