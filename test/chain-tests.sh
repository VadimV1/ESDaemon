#!/bin/bash
# chain-tests.sh — bin/chain.sh, the check install.sh, reload.sh and esdaemon status make: only root may be able to change
# ESDaemon's install tree, anything in it, or any directory above it. Each case builds a tree in a temp
# dir (top/usr/local/ESDaemon ...) and runs the real check on it. The owner everything must have is a parameter: the
# test's own uid makes the tree "root's", any other uid makes the same tree foreign-owned, so this runs without root.
# install.sh and reload.sh then run from a copy whose chain.sh refuses, to show that they stop there before anything
# else. That part is skipped as root, where a broken install.sh would install for real. Last, install.sh's own
# install_files lays out temporary trees: what goes where, and when the control command goes on PATH.
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
umask 022
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
trap 'rm -rf "$T"' EXIT
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
# shellcheck source=bin/chain.sh
. "$ROOT/bin/chain.sh"
ME="$(id -u)"; OTHER=$((ME + 1))

# What this filesystem can express. Git Bash on Windows ignores chmod and copies instead of linking, so there those cases
# are skipped. Linux and macOS (CI) can express both: there a case that cannot run fails, so a skip never hides one.
mkdir "$T/probe"; chmod g+w "$T/probe"; ln -s "$T/probe" "$T/probe-link" 2>/dev/null
CHMOD=0; case "$(ls -ldn "$T/probe")" in ?????w*) CHMOD=1 ;; esac
LINK=0; [ -L "$T/probe-link" ] && LINK=1
case "$(uname -s)" in Linux|Darwin) MUST=1 ;; *) MUST=0 ;; esac
can(){ [ "$1" = 1 ] && return 0
  if [ $MUST = 1 ]; then fail=$((fail+1)); echo "  FAIL $2: this filesystem cannot express it"
  else echo "  skip $2: this filesystem cannot express it (CI on Linux and macOS runs it)"; fi; return 1; }

# a tree as install.sh lays it out, under $T/<case>/top: every entry the test user's, and writable by it alone
new(){ TOP="$T/$1/top"; B="$TOP/usr/local/ESDaemon"; mkdir -p "$B/configs" "$B/run"
  : > "$B/filter.sh"; : > "$B/configs/ESDaemon.cfg"; : > "$B/run/active.cfg"; chmod 700 "$B/run"; }
chk(){ out="$(esd_root_only_tree "$B" "${1:-$ME}" "$TOP")"; rc=$?; }
has(){ grep -qF -- "$1" <<< "$out"; }

echo "-- a clean tree: owned by the expected user, writable by it alone, no symlinks"
new clean; chk
ok "passes, says nothing"                                  '[ $rc = 0 ] && [ -z "$out" ]'
ok "the path alone (esd_root_only) passes too"             'out="$(esd_root_only "$B" "$ME" "$TOP")" && [ -z "$out" ]'
mkdir -p "$T/first/top/usr/local"; TOP="$T/first/top"; B="$TOP/usr/local/ESDaemon"; chk
ok "first install: no tree yet, the directories above pass" '[ $rc = 0 ] && [ -z "$out" ]'
chk "$OTHER"
ok "...and are still checked: a foreign-owned one is refused" '[ $rc = 1 ] && has "$TOP/usr/local is owned by uid $ME"'

echo "-- foreign-owned: another user owns it (Homebrew's /usr/local), whatever its mode"
new foreign; chk "$OTHER"
ok "refused"                                               '[ $rc = 1 ]'
ok "names each entry and its owner, with the fix"          'has "$TOP/usr/local is owned by uid $ME, not uid $OTHER; fix: sudo chown $OTHER $TOP/usr/local" && has "$B/run/active.cfg is owned by uid $ME"'
# root expected: as root, give the tree away for real; without root the test user's own tree is the foreign one
if [ "$ME" = 0 ]; then chown -R 65534 "$TOP"; F=65534; else F="$ME"; fi
chk 0
ok "root expected, uid $F owns it: refused, chown root:wheel" '[ $rc = 1 ] && has "$TOP/usr/local is owned by uid $F, not root; fix: sudo chown root:wheel $TOP/usr/local"'
if [ "$ME" = 0 ]; then echo "  skip the defaults: running as root, the temp dir is root's"
else out="$(esd_root_only "$B")"; rc=$?
  ok "by default root must own it, up to /"               '[ $rc = 1 ] && has "$B is owned by uid $ME, not root"'
fi

echo "-- group- or world-writable: anyone in the group, or anyone at all, can replace what is in it"
new gw
if can $CHMOD "group-writable /usr/local"; then chmod g+w "$TOP/usr/local"; chk
  ok "group-writable /usr/local: refused, with the fix"    '[ $rc = 1 ] && has "$TOP/usr/local is group-writable (drwxrwxr-x" && has "fix: sudo chmod go-w $TOP/usr/local"'
fi
new ww
if can $CHMOD "world-writable /usr"; then chmod o+w "$TOP/usr"; chk
  ok "world-writable /usr: refused"                        '[ $rc = 1 ] && has "$TOP/usr is world-writable (drwxr-xrwx"'
fi
new sticky
if can $CHMOD "1777 /usr/local"; then chmod 1777 "$TOP/usr/local"; chk
  ok "1777 like /tmp: refused (sticky stops deleting, not creating)" '[ $rc = 1 ] && has "$TOP/usr/local is group- and world-writable (drwxrwxrwt"'
fi
new top
if can $CHMOD "writable top"; then chmod g+w "$TOP"; chk
  ok "the top (/ in production) is checked too"            '[ $rc = 1 ] && has "$TOP is group-writable"'
fi

echo "-- inside the tree: root runs or reads all of it, and ESDaemon logs nothing that runs from it"
new inside
if can $CHMOD "writable entries inside the tree"; then chmod g+w "$B/run"; chmod o+w "$B/configs/ESDaemon.cfg"; chk
  ok "group-writable run/: refused"                        '[ $rc = 1 ] && has "$B/run is group-writable"'
  ok "world-writable config: refused"                      'has "$B/configs/ESDaemon.cfg is world-writable"'
  ok "esd_root_only (the path alone) does not look inside" 'out="$(esd_root_only "$B" "$ME" "$TOP")" && [ -z "$out" ]'
fi
new several
if can $CHMOD "several problems"; then chmod g+w "$TOP/usr"; chmod o+w "$B/run"; chk
  ok "every problem is listed, the top one first"          '[ $rc = 1 ] && [ "$(grep -c writable <<< "$out")" = 2 ] && head -1 <<< "$out" | grep -qF "$TOP/usr is group-writable"'
fi

echo "-- symlinks: refused, not followed (the check has to see where root really runs from)"
new link
if can $LINK "symlinked /usr/local"; then mv "$TOP/usr/local" "$T/link/local"; ln -s "$T/link/local" "$TOP/usr/local"; chk
  ok "a symlinked /usr/local is refused, even to a clean directory" '[ $rc = 1 ] && has "$TOP/usr/local is a symbolic link (to $T/link/local)" && [ "$(grep -c . <<< "$out")" = 1 ]'
fi
new linkbase
if can $LINK "symlinked install dir"; then mv "$B" "$T/linkbase/real"; chmod o+w "$T/linkbase/real/run"; ln -s "$T/linkbase/real" "$B"; chk
  ok "a symlinked install dir is refused"                  '[ $rc = 1 ] && has "$B is a symbolic link (to $T/linkbase/real)"'
  ok "...and not walked into"                              '[ "$(grep -c . <<< "$out")" = 1 ]'
fi
new dangling
if can $LINK "dangling symlink"; then mv "$B" "$T/dangling/gone"; ln -s "$T/dangling/nowhere" "$B"; chk
  ok "a dangling symlink is refused too"                   '[ $rc = 1 ] && has "$B is a symbolic link (to $T/dangling/nowhere)"'
fi
new linkin
if can $LINK "symlink inside the tree"; then ln -s /etc "$B/x"; chk
  ok "a symlink inside the tree is refused"                '[ $rc = 1 ] && has "$B/x is a symbolic link (to /etc)"'
fi

echo "-- names as they are: a space in a path, a fix quoted for the shell, no relative or empty path"
new "with space"; chk "$OTHER"; printf -v q '%q' "$TOP/usr/local"
ok "names the path, quotes the fix"                        '[ $rc = 1 ] && has "$TOP/usr/local is owned by uid $ME" && has "fix: sudo chown $OTHER $q"'
ok "a relative path is refused, not checked from here"     '! out="$(cd "$T/clean/top/usr/local" && esd_root_only_tree ESDaemon "$OTHER")" && has "is not an absolute path" && [ "$(grep -c . <<< "$out")" = 1 ]'
ok "an empty path is refused"                              '! out="$(esd_root_only_tree "" "$ME")" && has "is not an absolute path"'

echo "-- esd_gate: what install.sh and reload.sh print when they stop"
new gate
ok "a clean tree: passes, prints nothing"                  'out="$(esd_gate "$B" install.sh "$ME" "$TOP" 2>&1)" && [ -z "$out" ]'
out="$( { esd_gate "$B" install.sh "$OTHER" "$TOP" >/dev/null; } 2>&1 )"; rc=$?
ok "a foreign tree: stops (1), on stderr"                  '[ $rc = 1 ] && [ -z "$(esd_gate "$B" install.sh "$OTHER" "$TOP" 2>/dev/null)" ]'
ok "says it stopped and changed nothing"                   'has "install.sh: stopped, nothing was changed"'
ok "names the path and the fix"                            'has "$TOP/usr/local is owned by uid $ME, not uid $OTHER; fix: sudo chown $OTHER $TOP/usr/local"'
ok "says to run it again, and what to do if it was changed" 'has "Fix that, then run install.sh again." && has "Another user may already have changed what is in $B"'

echo "-- install.sh and reload.sh check /usr/local/ESDaemon before anything else, and stop there"
if [ "$ME" = 0 ]; then echo "  skip running as root: a broken install.sh would install for real"
else
  mkdir -p "$T/src" "$T/out"; cp -R "$ROOT/install.sh" "$ROOT/bin" "$ROOT/configs" "$ROOT/src" "$T/src/"
  # a chain.sh that refuses, and says how far the script got before it asked: the cfg not read, no events parsed
  printf '%s\n' 'esd_gate(){ echo "gate $1 $2 cfg=${CFGF-unset} events=${EVENTS-unset}"; return 1; }' > "$T/src/bin/chain.sh"
  out="$(bash "$T/src/install.sh" 2>&1)"; rc=$?
  ok "install.sh: checks first, stops (1)"                 '[ $rc = 1 ] && [ "$out" = "gate /usr/local/ESDaemon install.sh cfg=unset events=unset" ]'
  out="$(bash "$T/src/bin/reload.sh" 2>&1)"; rc=$?
  ok "reload.sh: checks before it parses the cfg, stops (1)" '[ $rc = 1 ] && [ "$out" = "gate /usr/local/ESDaemon reload.sh cfg=/usr/local/ESDaemon/configs/ESDaemon.cfg events=unset" ]'
  out="$(bash "$T/src/bin/reload.sh" --render "$T/out" "$ROOT/configs/ESDaemon.cfg" 2>&1)"; rc=$?
  ok "reload.sh --render: no check (no root needed), renders" '[ $rc = 0 ] && [ -z "$out" ] && [ -f "$T/out/com.esdaemon.eslogger.plist" ] && [ -f "$T/out/com.esdaemon.filter.plist" ]'
fi

echo "-- install.sh lays out the tree: its install_files, run on a temporary tree as the test user"
# taken out of install.sh by name: running install.sh itself would install for real
eval "$(sed -n '/^install_files() {$/,/^}$/p' "$ROOT/install.sh")"
mkdir -p "$T/isrc/build"; cp -R "$ROOT/bin" "$ROOT/src" "$ROOT/configs" "$ROOT/VERSION" "$ROOT/REPO" "$T/isrc/"
printf '#!/bin/sh\n# the ESDaemon writer\n' > "$T/isrc/build/ESDaemon"; chmod 755 "$T/isrc/build/ESDaemon"   # #!: executable on Git Bash too
# what goes into the tree, as <file in the checkout>:<path in the tree>
PAIRS="bin/chain.sh:chain.sh bin/cfg.sh:cfg.sh bin/filter.sh:filter.sh bin/measure.sh:measure.sh bin/reload.sh:reload.sh
  bin/try.sh:try.sh bin/update.sh:update.sh bin/esdaemon:bin/esdaemon VERSION:VERSION REPO:REPO src/scope.jq:scope.jq
  src/ESDaemon.swift:ESDaemon.swift configs/ESDaemon.cfg:configs/ESDaemon.cfg build/ESDaemon:ESDaemon"
NFILES="$(printf '%s\n' $PAIRS | grep -c .)"
copies(){ local p; for p in $PAIRS; do cmp -s "$T/isrc/${p%%:*}" "$B/${p#*:}" || return 1; done; }
lay(){ TOP="$T/$1/top"; B="$TOP/usr/local/ESDaemon"; BIN="$TOP/usr/local/bin"; mkdir -p "$TOP/usr/local"; }
inst(){ CMD=""; install_files "$T/isrc" "$B" "$BIN" "$ME" "$(id -g)" "$TOP" > "$T/inst.out" 2>&1; rc=$?; out="$(cat "$T/inst.out")"; }

lay fresh; inst
ok "a fresh tree: installs (0)"                            '[ $rc = 0 ]'
ok "every file is a copy of its own source (on APFS, names equal but for case are one file)" 'copies'
ok "no other file, and no two names equal but for case"    '[ "$(find "$B" -type f | grep -c .)" = "$NFILES" ] && [ -z "$(find "$B" | tr "[:upper:]" "[:lower:]" | sort | uniq -d)" ]'
ok "the control command is in the tree, as bin/esdaemon"   'cmp -s "$T/isrc/bin/esdaemon" "$B/bin/esdaemon"'
ok "/usr/local/bin missing, /usr/local root's: created, command on PATH" '[ "$CMD" = esdaemon ] && cmp -s "$T/isrc/bin/esdaemon" "$BIN/esdaemon"'
ok "all of it root's alone (here: the test user's)"        'esd_root_only_tree "$B" "$ME" "$TOP" >/dev/null && esd_root_only "$BIN/esdaemon" "$ME" "$TOP" >/dev/null'

lay keep; mkdir -p "$B/configs" "$B/bin" "$BIN"; printf 'tuned\n' > "$B/configs/ESDaemon.cfg"
[ $CHMOD = 0 ] || chmod 750 "$B" "$B/configs" "$B/bin" "$BIN"
inst
ok "an existing tree: a tuned cfg is kept"                 '[ $rc = 0 ] && [ "$(cat "$B/configs/ESDaemon.cfg")" = tuned ]'
if can $CHMOD "existing directories keep their mode"; then
  ok "existing directories keep owner and mode (install -d would make them 755)" \
     'm=0; for d in "$B" "$B/configs" "$B/bin" "$BIN"; do case "$(ls -ldn "$d")" in "drwxr-x---"*" $ME "*) ;; *) m=1 ;; esac; done; [ $m = 0 ]'
fi

lay brew; mkdir -p "$BIN"; printf 'brew tool\n' > "$BIN/brewtool"; printf 'old esdaemon\n' > "$BIN/esdaemon"
if can $CHMOD "a Homebrew-style, group-writable /usr/local/bin"; then chmod 775 "$BIN"; inst
  ok "Homebrew's /usr/local/bin: installs (0), puts no command there" '[ $rc = 0 ] && [ ! -e "$BIN/esdaemon" ]'
  ok "...removes the earlier install's command, and says so" 'grep -qF "removed $BIN/esdaemon: other users can replace files there" <<< "$out"'
  ok "...admins run the copy in the tree"                  '[ "$CMD" = "$B/bin/esdaemon" ] && cmp -s "$T/isrc/bin/esdaemon" "$B/bin/esdaemon"'
  ok "...leaves the directory and Homebrew's files as they were" \
     '[ "$(cat "$BIN/brewtool")" = "brew tool" ] && case "$(ls -ldn "$BIN")" in "drwxrwxr-x"*" $ME "*) true ;; *) false ;; esac'
fi
lay link; mkdir -p "$T/link/brewbin"; printf 'old esdaemon\n' > "$T/link/brewbin/esdaemon"
if can $LINK "a symlinked /usr/local/bin"; then ln -s "$T/link/brewbin" "$BIN"; inst
  ok "a symlinked /usr/local/bin: no command there either, the earlier one removed" \
     '[ $rc = 0 ] && [ "$CMD" = "$B/bin/esdaemon" ] && [ ! -e "$T/link/brewbin/esdaemon" ]'
fi

echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
