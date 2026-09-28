#!/bin/bash
# filter.sh — ESDaemon filter job. eslogger output (FIFO) -> scope.jq (rules from ESDaemon.cfg) -> uls-writer -> unified log.
set -euo pipefail
BASE=/usr/local/ESDaemon; CFGF="$BASE/configs/ESDaemon.cfg"; FIFO=/var/run/ESDaemon/raw.fifo
CFG="$("$BASE/cfg.sh" "$CFGF" json)"
SUB="$("$BASE/cfg.sh" "$CFGF" get subsystem)"; CAT="$("$BASE/cfg.sh" "$CFGF" get category)"
/usr/bin/jq -n -cR --unbuffered --argjson cfg "$CFG" -f "$BASE/scope.jq" < "$FIFO" | "$BASE/uls-writer" "${SUB:-com.apple.eslogger}" "${CAT:-events}"
