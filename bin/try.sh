#!/bin/bash
# try.sh — dry-run a cfg against a saved eslogger capture, without touching the running daemon.
# Usage: bin/try.sh <capture.ndjson> [cfg=configs/ESDaemon.cfg]
#   capture: raw eslogger JSON, e.g. from measure.sh (it prints where it saved raw.ndjson)
set -euo pipefail
# fixed PATH: this can run as root, and macOS sudo keeps the caller's PATH — so bare tool names resolve to system binaries
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
HERE="$(cd "$(dirname "$0")" && pwd)"; CAP="${1:?capture.ndjson}"
if [ -f "$HERE/scope.jq" ]; then JQF="$HERE/scope.jq"; DEF="$HERE/configs/ESDaemon.cfg"; else JQF="$HERE/../src/scope.jq"; DEF="$HERE/../configs/ESDaemon.cfg"; fi
CFGF="${2:-$DEF}"; CFG="$("$HERE/cfg.sh" "$CFGF" json)"
OUT="$(mktemp)"; ALL="$(mktemp)"; jq -n -cR --argjson cfg "$(echo "$CFG" | jq -c '.format="slim"')" -f "$JQF" < "$CAP" > "$ALL"
# eslogger_scoped_gap markers are not kept events: they mean EndpointSecurity dropped events while capturing
grep -v '"eslogger_scoped_gap"' "$ALL" > "$OUT" || true
GAPS=$(grep '"eslogger_scoped_gap"' "$ALL" | jq -n '[inputs.eslogger_scoped_gap] | add // 0'); rm -f "$ALL"
RB=$(wc -c < "$CAP"); RN=$(wc -l < "$CAP"); KB=$(wc -c < "$OUT"); KN=$(wc -l < "$OUT")
echo "raw  $RN events $RB bytes"; echo "kept $KN events $KB bytes ($(awk -v k="$KB" -v r="$RB" 'BEGIN{printf "%.2f", r ? k*100/r : 0}')% of raw bytes)"
[ "$GAPS" = 0 ] || echo "WARNING: EndpointSecurity dropped $GAPS events during this capture (eslogger_scoped_gap); raw numbers are a lower bound"
echo "-- top kept images:"; jq -r '.exec.target.path // .event' "$OUT" | sort | uniq -c | sort -rn | head -25
echo "kept events: $OUT"
