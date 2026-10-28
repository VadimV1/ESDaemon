#!/bin/bash
# filter.sh — ESDaemon filter job. eslogger output (FIFO) -> scope.jq (rules from ESDaemon.cfg) -> ESDaemon -> unified log.
set -euo pipefail
# fixed PATH: this can run as root, and macOS sudo keeps the caller's PATH — so bare tool names resolve to system binaries
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
# ESDAEMON_BASE: the tests run this job against a throwaway tree
BASE="${ESDAEMON_BASE:-/usr/local/ESDaemon}"; RUN="$BASE/run"; FIFO="$RUN/raw.fifo"
# the cfg reload.sh last validated: an edited-but-not-reloaded cfg must never break a restart or a reboot
CFGF="$RUN/active.cfg"; [ -f "$CFGF" ] || CFGF="$BASE/configs/ESDaemon.cfg"
# The FIFO must be a FIFO. If it is missing, launchd creates eslogger's StandardOutPath as a regular file,
# and jq re-reads that file from byte 0 on every restart (every event re-logged, file grows without bound).
if [ ! -p "$FIFO" ]; then
  rm -f "$FIFO"; install -d -o root -g wheel -m 700 "$RUN"; mkfifo -m 600 "$FIFO"
  launchctl kickstart -k system/com.esdaemon.eslogger 2>/dev/null || true   # reopen eslogger's stdout on the new FIFO
fi
# self_pid: this job's pid. Every process the job starts (cfg.sh, awk, jq, ESDaemon ...) has it as its responsible
# process, so the filter can leave them all out even when it never saw this script start (eslogger restarting).
CFG="$("$BASE/cfg.sh" "$CFGF" json | /usr/bin/jq -c --argjson p $$ '.self_pid = $p')"
SUB="$("$BASE/cfg.sh" "$CFGF" get subsystem)"; CAT="$("$BASE/cfg.sh" "$CFGF" get category)"
# Heartbeat: ESDaemon itself logs a liveness record every HB seconds (0 = off), shaped for the format. Never a second
# process printing into the pipe below: jq writes a big record in several writes, so a line printed between two of
# them cuts the record into invalid JSON, and a printer that outlives jq keeps ESDaemon, and so this job, running.
HB="$("$BASE/cfg.sh" "$CFGF" get heartbeat)"; FMT="$(printf '%s' "$CFG" | /usr/bin/jq -r .format)"
# Restart marker: global_seq_num restarts with eslogger, so events lost while eslogger restarted cannot show up as
# an eslogger_scoped_gap. Every eslogger restart also restarts this job (EOF on the FIFO), so this marks the spot.
{ printf '{"eslogger_scoped_restart":1,"time":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  /usr/bin/jq -n -cR --unbuffered --argjson cfg "$CFG" -f "$BASE/scope.jq" < "$FIFO"
} | "$BASE/ESDaemon" "${SUB:-com.apple.eslogger}" "${CAT:-events}" "${HB:-300}" "$FMT"
