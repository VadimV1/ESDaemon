#!/bin/bash
# measure.sh — run interactively (Terminal with Full Disk Access) BEFORE and AFTER scoping.
# Shows which exec targets produce the volume, in events AND bytes, so the lists can be tuned from data.
# Usage: sudo ./measure.sh [seconds=300]
# Use the Mac normally from OTHER windows while it runs: eslogger suppresses every process in its own process group,
# so commands typed in the terminal running measure.sh are not captured (and would show up as false ES gaps).
set -uo pipefail
# fixed PATH: this can run as root, and macOS sudo keeps the caller's PATH — so bare tool names resolve to system binaries
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
SECS="${1:-300}"; HERE="$(cd "$(dirname "$0")" && pwd)"; TMP="$(mktemp -d)"
if [ -f "$HERE/scope.jq" ]; then JQF="$HERE/scope.jq"; CFGF="$HERE/configs/ESDaemon.cfg"      # installed layout
else JQF="$HERE/../src/scope.jq"; CFGF="$HERE/../configs/ESDaemon.cfg"; fi                 # repo layout
echo "capturing exec for ${SECS}s ..."
# raw.ndjson is eslogger's output untouched: each exec event carries the process's full environment (tokens,
# secrets). Kept so try.sh can dry-run a config on it; the closing note says so and how to delete the capture.
/usr/bin/eslogger exec > "$TMP/raw.ndjson" 2>/dev/null & P=$!
# a background job ignores Ctrl-C: without this, an interrupted run leaves eslogger filling $TMP forever
trap 'kill "$P" 2>/dev/null' EXIT; trap 'exit 130' INT TERM HUP
sleep "$SECS"; kill "$P" 2>/dev/null; wait "$P" 2>/dev/null
RAW_B=$(wc -c < "$TMP/raw.ndjson"); RAW_N=$(wc -l < "$TMP/raw.ndjson")
CFG="$("$HERE/cfg.sh" "$CFGF" json)"
/usr/bin/jq -n -cR --argjson cfg "$CFG" -f "$JQF" < "$TMP/raw.ndjson" > "$TMP/out.ndjson"
# eslogger_scoped_gap markers are not kept events: they mean EndpointSecurity dropped events during the capture
grep -v '"eslogger_scoped_gap"' "$TMP/out.ndjson" > "$TMP/kept.ndjson"
GAPS=$(grep '"eslogger_scoped_gap"' "$TMP/out.ndjson" | /usr/bin/jq -n '[inputs.eslogger_scoped_gap] | add // 0')
K_B=$(wc -c < "$TMP/kept.ndjson"); K_N=$(wc -l < "$TMP/kept.ndjson")
echo; echo "== TOP 30 exec targets by BYTES (raw, unscoped) =="
/usr/bin/jq -rR 'fromjson? | select(.event.exec) | "\(.event.exec.target.executable.path)\t\(tojson|length)"' "$TMP/raw.ndjson" \
 | awk -F'\t' '{b[$1]+=$2; n[$1]++} END{for(k in b) printf "%12d B  %7d ev  %s\n", b[k], n[k], k}' | sort -rn | head -30
echo; echo "== TOP 20 launches STILL LOGGED after [include]/[exclude] (candidates for an [exclude] rule) =="
# records are Sysmon-shaped (Image) or slim-shaped (exec.target.path) depending on format
/usr/bin/jq -r '"\(.Image // .exec.target.path // .event // "-")"' "$TMP/kept.ndjson" | sort | uniq -c | sort -rn | head -20
echo; echo "== TOP 10 parents of logged launches (exclude a noisy tool and its children with ParentImage) =="
/usr/bin/jq -r '"\(.ParentImage // .process.path // "-")"' "$TMP/kept.ndjson" | sort | uniq -c | sort -rn | head -10
echo
awk -v rb="$RAW_B" -v rn="$RAW_N" -v kb="$K_B" -v kn="$K_N" -v s="$SECS" 'BEGIN{
 printf "raw:  %d events  %.1f MB  -> %.2f GB/hour\n", rn, rb/1e6, rb/s*3600/1e9;
 printf "kept: %d events  %.1f MB  -> %.3f GB/hour  (%.2f%% of raw bytes)\n", kn, kb/1e6, kb/s*3600/1e9, (rb?kb*100/rb:0) }'
[ "$GAPS" = 0 ] || echo "WARNING: EndpointSecurity dropped $GAPS events during the capture (eslogger_scoped_gap); raw numbers are a lower bound"
echo
echo "samples kept in $TMP (readable only by you):"
echo "  raw.ndjson       eslogger's output untouched — each exec carries the process's FULL environment,"
echo "                   which can hold tokens and other secrets; try.sh can dry-run a config against it"
echo "  out.ndjson / kept.ndjson   the scoped records to tune from"
echo "delete the capture when done:  rm -rf \"$TMP\""
