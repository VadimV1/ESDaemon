#!/bin/bash
# jqcheck.sh — can this Mac's jq run ESDaemon's filter? Sourced by install.sh and reload.sh. The filter daemon is the
# first to compile src/scope.jq (filter.sh): on a jq that cannot run it (a construct or a builtin this jq does not
# have), the daemon exits at once, launchd starts it again every few seconds, and nothing is collected. So before they
# change anything, install.sh and reload.sh run it here, as filter.sh will: on the same jq, with the config the daemon
# will run, over a few sample events.
#
#   esd_jq_check <scope.jq> <cfg json> <name> [jq]
#     Run <scope.jq> on <jq> (default /usr/bin/jq, the one filter.sh runs) with <cfg json> (cfg.sh's output) over the
#     sample events below. Return 0 when jq runs it to the end, reports the event missing from the sample, and no event
#     hits a filter error (esd_filter_error: no record could be built) or a rule error (esd_rule_error: a rule could not
#     be evaluated). Otherwise say on stderr that <name> stopped, which jq it is and what it printed, and return 1. The
#     tests pass a jq of their own.

# A shell started by login, a program the shell starts (its ParentCommandLine comes from the shell's own start, so the
# pid cache is used), and a login. global_seq_num skips 2: the filter must report that one event is missing, whatever
# the config's rules drop, so a jq that reads nothing or prints nothing fails too.
_esd_jq_sample() {
  cat <<'E'
{"time":"2026-01-01T00:00:01.000000001Z","global_seq_num":1,"process":{"executable":{"path":"/usr/bin/login"},"audit_token":{"pid":101,"pidversion":1,"euid":0},"ppid":100,"start_time":"2026-01-01T00:00:00.5Z"},"event":{"exec":{"target":{"executable":{"path":"/bin/zsh"},"audit_token":{"pid":101,"pidversion":1,"euid":501},"ppid":100,"original_ppid":100,"parent_audit_token":{"pid":100},"responsible_audit_token":{"pid":100},"is_platform_binary":true,"signing_id":"com.apple.zsh"},"args":["-zsh"],"cwd":{"path":"/"}}}}
{"time":"2026-01-01T00:00:02.000000001Z","global_seq_num":3,"process":{"executable":{"path":"/bin/zsh"},"audit_token":{"pid":102,"pidversion":2,"euid":501},"ppid":101,"start_time":"2026-01-01T00:00:01.5Z"},"event":{"exec":{"target":{"executable":{"path":"/usr/bin/true"},"audit_token":{"pid":102,"pidversion":2,"euid":501},"ppid":101,"original_ppid":101,"parent_audit_token":{"pid":101,"pidversion":1},"responsible_audit_token":{"pid":100},"is_platform_binary":true,"signing_id":"com.apple.true"},"args":["true"],"cwd":{"path":"/"}}}}
{"time":"2026-01-01T00:00:03.000000001Z","global_seq_num":4,"process":{"executable":{"path":"/usr/bin/login"},"audit_token":{"pid":103,"pidversion":3,"euid":0},"ppid":1,"start_time":"2026-01-01T00:00:02.5Z"},"event":{"authentication":{"success":true,"type":0}}}
E
}

esd_jq_check() {   # <scope.jq> <cfg json> <name> [jq]
  local jq="${4:-/usr/bin/jq}" out ver
  # with filter.sh's own options
  out="$(_esd_jq_sample | "$jq" -n -cR --unbuffered --argjson cfg "$2" -f "$1" 2>&1)" \
    && [[ "$out" == *'"eslogger_scoped_gap":1'* && "$out" != *'"esd_filter_error"'* && "$out" != *'"esd_rule_error"'* ]] \
    && return 0
  ver="$("$jq" --version </dev/null 2>/dev/null)" || ver=""   # nothing on stdin: a jq wrapper that reads it must not hang here
  { echo "$3: stopped, nothing was changed. $jq (${ver:-version unknown}) cannot run ESDaemon's filter, $1, with this config:"
    # what went wrong: jq's own errors, or the error markers, shown from the marker on (a record ends with esd_rule_error)
    if [ -z "$out" ]; then echo "  (jq printed nothing)"
    elif [[ "$out" == *error* ]]; then
      printf '%s\n' "$out" | grep error | sed 's/^{.*\("esd_[a-z]*_error":\)/... \1/' | head -8 | cut -c1-300 | sed 's/^/  /'
    else printf '%s\n' "$out" | head -8 | cut -c1-200 | sed 's/^/  /'; fi
    echo "ESDaemon supports macOS 15.0 or later, with the /usr/bin/jq that comes with it: on such a Mac, please report this"
    echo "with the lines above."
  } >&2
  return 1
}
