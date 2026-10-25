# lib.sh — shared helpers for the ESDaemon adversary-emulation harness.
# Each scenario is one function that answers `meta`, `run` and `clean`. A scenario emulates a documented macOS
# attacker technique using the real living-off-the-land binary, but with a HARMLESS, self-cleaning payload: the
# point is to make ESDaemon log the behaviour (process start, file create/delete, login), not to harm the VM.
#
# Safety rules every scenario follows:
#   - benign effect: no real data leaves the box, no real credential is read out, no real malware is fetched;
#   - self-cleaning: whatever it creates, its `clean` removes; whatever it changes, its `clean` restores;
#   - anything that genuinely weakens the machine (disable Gatekeeper, enable root, erase the log, add an account,
#     write a LaunchDaemon) runs its real form ONLY when ESD_RT_DESTRUCTIVE=1, and still restores state.
# A unique NONCE is put in paths and arguments so the runner can find each scenario's own record unambiguously.

NONCE="${ESD_RT_NONCE:-rt$(date +%s)$RANDOM}"
WORK="${ESD_RT_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/esd-redteam.XXXXXX")}"
DESTRUCTIVE="${ESD_RT_DESTRUCTIVE:-0}"
RT_SELF_TAG="esd-redteam"        # marks everything this harness creates, so cleanup is total

note() { printf '      %s\n' "$*"; }
# a disposable file under WORK, its name carrying the nonce
decoy() { local p="$WORK/${1:-decoy}.$NONCE"; : > "$p"; printf '%s' "$p"; }
# run a destructive step only when allowed; otherwise print what was skipped
destructive() { if [ "$DESTRUCTIVE" = 1 ]; then eval "$1"; else note "skipped (set ESD_RT_DESTRUCTIVE=1 to run): $2"; return 9; fi; }

# ---- scenario registry ----------------------------------------------------------------------------------------
# A scenario file sources this lib, defines functions, and appends their names to RT. Each function takes one arg:
#   meta  -> echo "<mitre>|<name>|<tactic>|<loobin>|<expect_image>|<expect_type>|<match>"
#            expect_type: ProcessStart (default) | FileCreate | FileDelete | FileRead | UserLogin | any
#            match: substring the record must contain (default: the NONCE). "-" to match on image+type alone.
#   run   -> perform the benign technique
#   clean -> undo it (files removed, state restored)
RT=()
meta_field() { "$1" meta | awk -F'|' -v n="$2" '{print $n}'; }
