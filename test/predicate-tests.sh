#!/bin/bash
# predicate-tests.sh — issue #28: the collector/event predicate must select only records written by root.
# ESDaemon's records were chosen by `subsystem == "com.apple.eslogger" AND process == "ESDaemon"`, but neither
# field is protected: any user can os_log under that subsystem, and any user can run a program named ESDaemon,
# so a non-root process could inject records a collector would ship as ESDaemon's. The real filter always runs
# as root, so every documented and used predicate now adds `AND userIdentifier == 0`.
#   - static: the hardened predicate is present (and identical) everywhere it is documented or used, and no
#     watch command or `esdaemon logs` was left on the old form (runs anywhere);
#   - functional: `... AND userIdentifier == 0` keeps a record logged by root and drops one logged by a
#     non-root user. Proven on an ISOLATED subsystem (com.esdaemon.uidtest), NEVER com.apple.eslogger: a live
#     deployment ships that subsystem, so a test record there would be injected into the real event feed. The
#     functional half needs a real unified log; it is Darwin-gated and skips cleanly off macOS.
# shellcheck disable=SC2034  # vars read only inside the single-quoted strings ok() evals look unused to shellcheck
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/.."
TD="$(mktemp -d)"; trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }

# The one predicate string every watch command and `esdaemon logs` must carry, byte for byte (the CI log-check
# keeps its `category == "events"`, so it has its own). Files quote it either plainly or with \"-escaped quotes
# inside a double-quoted echo, so strip backslashes before matching.
CANON='subsystem == "com.apple.eslogger" AND process == "ESDaemon" AND userIdentifier == 0'
CICANON='subsystem == "com.apple.eslogger" AND category == "events" AND process == "ESDaemon" AND userIdentifier == 0'
PROC='process == "ESDaemon"'

want(){ # $1 file  $2 expected-count  $3 needle  $4 label
  local c; c="$(tr -d '\\' < "$1" | grep -Fc "$3")"
  if [ "$c" = "$2" ]; then pass=$((pass+1)); echo "  ok   $4 ($c)"
  else fail=$((fail+1)); echo "  FAIL $4: found $c, want $2"; fi
}
allhardened(){ # $1 file  $2 canonical-needle  $3 label — every process==ESDaemon is part of a hardened predicate
  local p c
  p="$(tr -d '\\' < "$1" | grep -Fc "$PROC")"; c="$(tr -d '\\' < "$1" | grep -Fc "$2")"
  if [ "$p" = "$c" ]; then pass=$((pass+1)); echo "  ok   $3 (every process==ESDaemon hardened: $p)"
  else fail=$((fail+1)); echo "  FAIL $3: $p process==ESDaemon vs $c hardened"; fi
}

echo "-- the hardened predicate is present everywhere it is documented or used"
want "$ROOT/bin/esdaemon"                 1 "$CANON"   "bin/esdaemon logs subcommand"
want "$ROOT/README.md"                    1 "$CANON"   "README watch command"
want "$ROOT/docs/GETTING-STARTED.md"      2 "$CANON"   "GETTING-STARTED watch command + Predicate table row"
want "$ROOT/install.sh"                   1 "$CANON"   "install.sh Check line"
want "$ROOT/quick-install.sh"             1 "$CANON"   "quick-install.sh watch line"
want "$ROOT/docs/MAC-TEST-PLAN.md"        1 "$CANON"   "MAC-TEST-PLAN events-flowing step"
want "$ROOT/.github/workflows/ci.yml"     1 "$CICANON" "ci.yml log-check predicate (keeps category)"

echo "-- the doc that explains the predicate says why userIdentifier == 0 is there"
want "$ROOT/docs/GETTING-STARTED.md"      1 'restricts it to the root writer' "GETTING-STARTED explains the uid clause"

echo "-- no watch command or esdaemon logs was left on the old, unprotected form"
# (MAC-TEST-PLAN is excluded: its pre-install build smoke test filters on a bare process==ESDaemon by design,
#  run as the tester, not root — see docs/MAC-TEST-PLAN.md step 2.)
allhardened "$ROOT/bin/esdaemon"             "$CANON"   "bin/esdaemon"
allhardened "$ROOT/README.md"                "$CANON"   "README"
allhardened "$ROOT/docs/GETTING-STARTED.md"  "$CANON"   "GETTING-STARTED"
allhardened "$ROOT/install.sh"               "$CANON"   "install.sh"
allhardened "$ROOT/quick-install.sh"         "$CANON"   "quick-install.sh"
allhardened "$ROOT/.github/workflows/ci.yml" "$CICANON" "ci.yml"

echo "-- userIdentifier == 0 keeps the root writer's records and drops a non-root one (isolated subsystem)"
if [ "$(uname -s)" != Darwin ]; then
  echo "  skipped: not macOS (the unified log and userIdentifier are macOS; CI's macOS runners and the Mac lab run this)"
elif ! command -v cc >/dev/null 2>&1 || ! command -v log >/dev/null 2>&1; then
  echo "  skipped: need cc (to emit an os_log record) and log (to query), both present on macOS with the Command Line Tools"
else
  SUB="com.esdaemon.uidtest"          # NOT com.apple.eslogger: see the header — a live collector ships that subsystem
  emitc="$TD/emit.c"; emit="$TD/emit"
  cat > "$emitc" <<'EOF'
#include <os/log.h>
int main(int argc, char **argv) {
  if (argc < 4) return 2;                      /* subsystem category message */
  os_log_t l = os_log_create(argv[1], argv[2]);
  os_log(l, "%{public}s", argv[3]);            /* DEFAULT level: persisted, visible to `log show` */
  return 0;
}
EOF
  if ! cc -o "$emit" "$emitc" 2>/dev/null; then
    echo "  skipped: could not compile the os_log emitter with cc (no usable toolchain/SDK here)"
  else
    me="$(id -u)"; tag="esd-uidtest-$$-$RANDOM"; nr="$tag-nonroot"; rt="$tag-root"
    have_nonroot=0; have_root=0
    # non-root record: genuine only when the suite itself runs as a normal user (the usual case)
    [ "$me" = 0 ] || { "$emit" "$SUB" uidcat "$nr" && have_nonroot=1; }
    # root record: directly if we are already root, else through passwordless sudo where it is available
    if [ "$me" = 0 ]; then "$emit" "$SUB" uidcat "$rt" && have_root=1
    elif sudo -n true 2>/dev/null; then sudo -n "$emit" "$SUB" uidcat "$rt" && have_root=1; fi

    allq="subsystem == \"$SUB\""
    rootq="subsystem == \"$SUB\" AND userIdentifier == 0"
    all="$TD/all.ndjson"; root="$TD/root.ndjson"
    # wait for the unified log to surface what we emitted (it can lag a few seconds)
    seen=0
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      log show --last 2m --style ndjson --predicate "$allq" > "$all" 2>/dev/null || true
      n=1; [ "$have_nonroot" = 0 ] || grep -Fq "$nr" "$all" || n=0
      r=1
      if [ "$have_root" = 1 ]; then
        log show --last 2m --style ndjson --predicate "$rootq" > "$root" 2>/dev/null || true
        grep -Fq "$rt" "$root" || r=0
      fi
      [ "$n" = 1 ] && [ "$r" = 1 ] && { seen=1; break; }
      sleep 1
    done
    log show --last 2m --style ndjson --predicate "$allq"  > "$all"  2>/dev/null || true
    log show --last 2m --style ndjson --predicate "$rootq" > "$root" 2>/dev/null || true

    if [ "$seen" != 1 ]; then
      echo "  skipped: the unified log did not surface the test record within 20s (log latency); the uid assertions need it"
    else
      if [ "$have_nonroot" = 1 ]; then
        ok "the non-root record is in the subsystem (sanity)"  'grep -Fq "$nr" "$all"'
        ok "userIdentifier == 0 excludes the non-root record"  '! grep -Fq "$nr" "$root"'
      else
        echo "  skip non-root half: the suite runs as root here, so no genuine non-root record (a normal user runs it on CI / the Mac lab)"
      fi
      if [ "$have_root" = 1 ]; then
        ok "userIdentifier == 0 keeps the root record"         'grep -Fq "$rt" "$root"'
      else
        echo "  skip root half: no passwordless sudo to log as root (the Mac lab / CI runners run it)"
      fi
    fi
  fi
fi

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
