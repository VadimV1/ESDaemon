#!/bin/bash
# chain.sh — can anyone but root change ESDaemon's install tree, or a directory above it? Sourced by install.sh,
# reload.sh and esdaemon. Whoever can write to a directory can replace anything in it, whatever that file's own owner
# and mode. So every directory from / down to the files root runs must be root's alone: owned by root, writable by no
# group and no other user, and not a symlink (that would move the check to wherever it points). Everything inside the
# install tree must be root's alone too, because ESDaemon never logs what runs from it (src/scope.jq, esd_base). On
# macOS it also reads each entry's ACL (ls -le): an ACL that grants write to anyone but the owner is refused. Linux
# and Git Bash list no ACL, so there the mode bits stand alone.
#
#   esd_root_only <path> [uid] [top]        <path> and every directory above it, up to <top> (default /)
#   esd_root_only_tree <dir> [uid] [top]    the same, and everything inside <dir>
#     Return 0 when all of it is root's alone; otherwise print one line per problem, each with the command that fixes
#     it, and return 1. A path that does not exist yet is skipped: root creates it, in a directory checked here.
#     <uid> is the owner everything must have (default 0, root); the tests pass their own, and a <top> of their own.
#   esd_gate <dir> <name> [uid] [top]       esd_root_only_tree, as install.sh and reload.sh run it before they change
#     anything: when it finds a problem, say on stderr that <name> stopped and why, and return 1.

# one entry, not followed if it is a symlink. ls -ldn prints the mode and the numeric owner alike on macOS and Linux.
_esd_entry() {   # <path> <uid>
  local p="$1" uid="$2" q m u who=root own=root:wheel bad=0 e rest who2
  printf -v q '%q' "$p"
  [ "$uid" = 0 ] || { who="uid $uid"; own="$uid"; }
  if [ -L "$p" ]; then
    echo "  $p is a symbolic link (to $(readlink "$p")); fix: put the directory or file itself there"; return 1
  fi
  [ -e "$p" ] || return 0
  read -r m _ u _ <<< "$(ls -ldn "$p" 2>/dev/null)"
  [ -n "$u" ] || { echo "  $p could not be checked (ls -ldn failed)"; return 1; }
  [ "$u" = "$uid" ] || { echo "  $p is owned by uid $u, not $who; fix: sudo chown $own $q"; bad=1; }
  case "${m:5:1}${m:8:1}" in   # the group and the other write bits of e.g. drwxrwxr-x
    ww) echo "  $p is group- and world-writable ($m); fix: sudo chmod go-w $q"; bad=1 ;;
    w?) echo "  $p is group-writable ($m); fix: sudo chmod go-w $q"; bad=1 ;;
    ?w) echo "  $p is world-writable ($m); fix: sudo chmod go-w $q"; bad=1 ;;
  esac
  # ACLs are macOS-only. ls -l's +/@ marker is unreliable — an extended attribute alone shows @, hiding an ACL's + —
  # so read the ACL entries themselves with ls -lde. On Linux and Git Bash ls has no -e and lists none, so this finds
  # nothing and the mode bits above stand alone: no ACL facility means no ACL to worry about. (uname cached in _esd_os.)
  if [ "${_esd_os:=$(uname)}" = Darwin ]; then
    { IFS= read -r _                                     # line 1 is the long listing; the ACL entries follow it
      while IFS= read -r e; do
        case "$e" in *" allow "*) ;; *) continue ;; esac # an allow entry only (a deny entry grants nothing)
        rest="${e#*: }"                                  # "<who> allow <perms>"
        case "${rest#* allow }" in                       # the rights it grants
          *write*|*add_*|*append*|*delete*|*chown*) ;;   # a write-class right
          *) continue ;;                                 # a read-only grant is harmless
        esac
        who2="${rest% allow *}"                          # the principal: user:NAME, group:NAME, or a bare GUID
        case "$who2" in
          user:*) [ "$(id -u "${who2#user:}" 2>/dev/null)" = "$uid" ] && continue ;; # the owner's own entry: fine
        esac
        echo "  $p is writable via an ACL by someone other than $who ($rest); fix: sudo chmod -N $q"; bad=1
      done
    } <<< "$(ls -lde "$p" 2>/dev/null)"
  fi
  return $bad
}

_esd_up() {   # <path> <uid> <top>: from <top> (or /) down to <path>
  local up bad=0
  if [ "$1" != "$3" ] && [ "$1" != / ]; then up="${1%/*}"; _esd_up "${up:-/}" "$2" "$3" || bad=1; fi
  _esd_entry "$1" "$2" || bad=1
  return $bad
}

esd_root_only() {   # <path> [uid] [top]
  local p="${1:-}" top="${3:-/}"
  [ "$p" = / ] || p="${p%/}"; [ "$top" = / ] || top="${top%/}"
  case "$p" in
    /*) _esd_up "$p" "${2:-0}" "$top" ;;
    *)  echo "  \"$p\" is not an absolute path"; return 1 ;;
  esac
}

esd_root_only_tree() {   # <dir> [uid] [top]
  local dir="${1:-}" uid="${2:-0}" bad=0
  [ "$dir" = / ] || dir="${dir%/}"
  esd_root_only "$dir" "$uid" "${3:-/}" || bad=1
  if [ "${dir#/}" != "$dir" ] && [ -d "$dir" ] && [ ! -L "$dir" ]; then
    # NUL-separated: a name with a newline in it must not pass as two names that do not exist
    find "$dir" -mindepth 1 -print0 2>/dev/null \
      | { b=0; while IFS= read -r -d '' e; do _esd_entry "$e" "$uid" || b=1; done; exit $b; }
    set -- "${PIPESTATUS[@]}"
    [ "$2" = 0 ] || bad=1
    # Root reads every directory, so there a find error means part of the tree went unchecked. Without root, find
    # cannot list what only root may read (run/); install.sh, reload.sh and sudo esdaemon status check that too.
    [ "$1" = 0 ] || [ "$(id -u)" != 0 ] || { echo "  $dir could not be read completely"; bad=1; }
  fi
  return $bad
}

esd_gate() {   # <dir> <name> [uid] [top]
  local why
  why="$(esd_root_only_tree "$1" "${3:-0}" "${4:-/}")" && return 0
  { echo "$2: stopped, nothing was changed. ESDaemon runs as root from $1, so only root may be able to change it,"
    echo "anything in it, or any directory above it:"
    printf '%s\n' "$why"
    echo "Fix that, then run $2 again."
    [ ! -e "$1" ] || echo "Another user may already have changed what is in $1: if so, remove it with uninstall.sh (it runs nothing from there) and install again."
  } >&2
  return 1
}
