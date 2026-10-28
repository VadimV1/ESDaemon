#!/bin/bash
# cfg.sh — read and validate ESDaemon.cfg.
#   cfg.sh <file> json          -> JSON object the filter (scope.jq) uses
#   cfg.sh <file> get <key>     -> one [settings] value
#   cfg.sh <file> events        -> the eslogger event types [modules] needs (space separated, for the LaunchDaemon)
# Anything cfg.sh does not understand is an error, never silently ignored: an unknown [section] or key, a
# typo'd value, a line outside a section. A typo must fail reload.sh, not quietly switch detection off.
set -euo pipefail
# fixed PATH: this can run as root, and macOS sudo keeps the caller's PATH — so bare tool names resolve to system binaries
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
F="${1:?cfg file}"; MODE="${2:-json}"
# [modules]: what to log, as <object> = <operation> ...  ->  the eslogger events behind each operation.
# The one place modules are defined (scope.jq names each event: ProcessStart, FileRead ...; docs/CONFIG.md lists them).
#   object  operation   eslogger events
export MODTAB='
process start       exec
process exit        exit
process inject      get_task get_task_read get_task_inspect remote_thread_create trace
file    read        open
file    write       close
file    create      create
file    delete      unlink
file    rename      rename
file    attributes  setextattr deleteextattr setmode setowner setflags setacl
user    login       authentication login_login openssh_login lw_session_login lw_session_unlock screensharing_attach
user    logout      login_logout openssh_logout lw_session_logout lw_session_lock screensharing_detach
user    sudo        sudo su
user    account     od_create_user od_delete_user od_disable_user od_enable_user od_modify_password od_create_group od_delete_group od_group_add od_group_remove od_group_set od_attribute_set od_attribute_value_add od_attribute_value_remove
system  persistence btm_launch_item_add btm_launch_item_remove
system  malware     xp_malware_detected xp_malware_remediated
system  kernel      kextload kextunload
system  mount       mount unmount remount
'
# One pass over the file -> "section<TAB>value" lines. Tolerates what editors produce: CRLF, a UTF-8 BOM,
# tabs, trailing spaces, "  # comment" after a header/value (not in [drop], where # can be part of a command line).
NORM="$(LC_ALL=C awk '
  function err(m) { printf "ESDaemon.cfg line %d: %s\n  %s\n", NR, m, orig > "/dev/stderr"; bad=1; exit 1 }
  function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
  BEGIN { split("settings modules include exclude drop", a, " "); for (i in a) known[a[i]]=1
          split("always download conditional noisy_team_ids noisy_path_prefixes", a, " "); for (i in a) gone[a[i]]=1
          split("subsystem category format parent_cmdline_max args_max record_max slim", a, " "); for (i in a) keys[a[i]]=1
          n = split(ENVIRON["MODTAB"], rows, "\n")
          for (i = 1; i <= n; i++) { if (split(rows[i], c, " ") >= 3) { mod[c[1] " " c[2]] = 1; obj[c[1]] = obj[c[1]] " " c[2] } } }
  NR == 1 { sub(/^\357\273\277/, "") }
  { sub(/\r$/, ""); orig=$0; line=trim($0) }
  line == "" || line ~ /^#/ { next }
  line ~ /^\[/ {
    h=line; sub(/[ \t]+#.*$/, "", h)
    if (h !~ /^\[.*\]$/) err("bad section header")
    sect=trim(substr(h, 2, length(h)-2))
    if (sect in gone) err("[" sect "] was removed: ESDaemon logs every event now; filter with [include] / [exclude] rules (docs/CONFIG.md)")
    if (!(sect in known)) err("unknown section [" sect "]  (valid: [settings] [modules] [include] [exclude])")
    next }
  sect == "" { err("line is not inside a [section]") }
  sect == "settings" || sect == "modules" { sub(/[ \t]+#.*$/, "", line) }
  sect == "modules" {
    i=index(line, "="); if (!i) err("expected <object> = <operation>[, <operation> ...], e.g. file = read, write")
    o=trim(substr(line, 1, i-1)); v=trim(substr(line, i+1))
    if (!(o in obj)) err("unknown object \"" o "\"  (valid: process file user system)")
    if (v == "") err("no operation for " o "  (valid:" obj[o] ")")
    m=split(v, ops, /[ \t]*,[ \t]*|[ \t]+/)
    for (j = 1; j <= m; j++) { if (ops[j] == "") continue
      if (!((o " " ops[j]) in mod)) err("unknown operation \"" ops[j] "\" for " o "  (valid:" obj[o] ")")
      print "modules\t" o " " ops[j] }
    next }
  sect == "settings" {
    i=index(line, "="); if (!i) err("expected key = value")
    k=trim(substr(line, 1, i-1)); v=trim(substr(line, i+1))
    if (k == "third_party") err("third_party was removed: every executable is logged now; filter with [exclude] (e.g. TeamId is EQHXZ8M8AV)")
    if (k == "events") err("events was removed: list what to log under [modules], e.g.  process = start  /  file = read, write")
    if (!(k in keys)) err("unknown setting \"" k "\"  (valid: subsystem category format parent_cmdline_max args_max record_max)")
    if (k in seen) err("\"" k "\" is set twice (first on line " seen[k] ")")
    seen[k]=NR
    if (v != "") {
      if (k == "format"      && v !~ /^(sysmon|sysmon\+extras|slim|raw)$/) err("format must be sysmon, sysmon+extras, slim or raw")
      if (k == "slim"        && v !~ /^(true|false)$/)                      err("slim must be true or false (or use format =)")
      if (k == "parent_cmdline_max" && v !~ /^[0-9]+$/)                     err("parent_cmdline_max must be a whole number (0 = no cap)")
      if (k == "args_max"           && v !~ /^[0-9]+$/)                     err("args_max must be a whole number of argv elements (0 = no cap)")
      if (k == "record_max" && v !~ /^[0-9]+$/)                             err("record_max must be a whole number of bytes (0 = no limit)")
      if ((k == "subsystem" || k == "category") && v !~ /^[A-Za-z0-9._-]+$/) err(k " may only contain letters, digits, . _ -")
    }
    print sect "\t" k "=" v; next }
  { print sect "\t" line }
' "$F")" || { echo "ESDaemon.cfg: invalid (see above), nothing applied" >&2; exit 1; }
section() { [ -z "$NORM" ] || printf '%s\n' "$NORM" | awk -F'\t' -v s="$1" '$1 == s { print substr($0, length(s) + 2) }'; }
get() { section settings | awk -v k="$1" '!done { i=index($0, "="); if (substr($0, 1, i-1) == k) { print substr($0, i+1); done=1 } }'; }
# [include] / [exclude] rules (the old name [drop] = [exclude]). Every regex is compiled here so a typo fails
# reload.sh instead of crashing the running filter.
rules() {
  # Syntax = Sysmon's own filter vocabulary, one rule per line, clauses joined with AND; lines are ORed:
  #   <Field> <condition> <value> [AND <Field> <condition> <value> ...]
  # Fields: EventType, Image, CommandLine, CurrentDirectory, ParentImage, ParentCommandLine, User, TeamId,
  #   SigningId, IsPlatformBinary, TargetFilename
  # Conditions (case-insensitive, same meaning as Sysmon): is, is not, is any, contains, contains any,
  #   contains all, excludes, excludes any, excludes all, begin with, not begin with, end with, not end with,
  #   image, regex, not regex.  "... any/all" take ;-separated values. Quote a value ("...") if it contains " AND ".
  # Output: [[{field, op, value}, ...], ...]  (outer list = OR of lines, inner list = AND of clauses)
  { for s in "$@"; do section "$s"; done; } | jq -R '
    def fields: ["EventType","Image","CommandLine","CurrentDirectory","ParentImage","ParentCommandLine","User","TeamId","SigningId","IsPlatformBinary","TargetFilename"];
    # Any run of spaces/tabs between the words: "excludes  any" must not fall back to "excludes" with value "any ...".
    def ops: "not begin with|not end with|not regex|begin with any|end with any|begin with|end with|is any|is not|is|contains any|contains all|contains|excludes any|excludes all|excludes|image|regex" | gsub(" "; "\\s+");
    def clause_re: "(?:^\\s*|\\s+(?-i:AND)\\s+)(?<field>[A-Za-z]+)\\s+(?<op>" + ops + ")\\s+(?<value>\"(?:[^\"\\\\]|\\\\.)*\"|.+?)(?=\\s+(?-i:AND)\\s+|\\s*$)";
    . as $line
    | [ match(clause_re; "gi") | [.captures[] | {(.name): .string}] | add
        | .op |= (ascii_downcase | gsub("\\s+"; " "))
        | if (.value | test("\\s(?-i:AND)$")) then error("dangling AND at end of: \($line)") else . end
        # Unquoted values that swallowed another clause or a comment; with is not / excludes they would drop almost everything.
        | if (.value | startswith("\"")) then .
          elif (.value | test("\\s(?i:and)\\s+(?i:" + (fields | join("|")) + ")\\s+(?i:" + ops + ")(\\s|$)")) then error("clauses must be joined with uppercase AND (or quote the value) in: \($line)")
          elif (.value | test("\\s#")) then error("comments go on their own line (or quote the value) in: \($line)")
          else . end
        | .value |= (if test("^\".*\"$") then .[1:-1] | gsub("\\\\\""; "\"") else . end)
        # An empty value (or an any/all list with no items) matches every launch and would silently drop them all.
        | if .value == "" or ((.op | test(" (any|all)$")) and ([.value | split(";")[] | select(. != "")] | length) == 0)
          then error("empty value in: \($line)") else . end
        | . as $c | (fields | map(ascii_downcase) | index($c.field | ascii_downcase)) as $fi
        | if $fi == null then error("unknown field \"\($c.field)\" in: \($line)  (use one of \(fields | join(", ")))") else .field = fields[$fi] end
        | if .op == "regex" then (. as $c | try ("x" | test($c.value)) catch error("bad regex \"\($c.value)\" in: \($line)")) as $_ | . else . end
      ] as $clauses
    | ($line | gsub(clause_re; ""; "gi") | gsub("\\s+(?-i:AND)\\s+|\\s+"; "")) as $rest
    | if ($clauses | length) == 0 or $rest != "" then error("cannot parse rule: \($line)\n  expected: <Field> <condition> <value> [AND ...], e.g.  Image is /usr/bin/curl AND CommandLine contains updates.example.com") else $clauses end
  ' | jq -cs .
}
# [modules] as "object operation" lines; none listed = process start (the default).
modules() { local m; m="$(section modules | awk '!seen[$0]++')"; printf '%s\n' "${m:-process start}"; }
# the eslogger events for those modules, minus any this Mac's eslogger does not offer (older macOS lacks some);
# an operation with none left is an error, so a module is never silently switched off
es_events() {
  local known; known="$( [ -x /usr/bin/eslogger ] && /usr/bin/eslogger --list-events 2>/dev/null || true)"
  modules | KNOWN="$known" awk '
    BEGIN { n = split(ENVIRON["MODTAB"], rows, "\n"); for (i = 1; i <= n; i++) if (split(rows[i], c, " ") >= 3) { k = c[1] " " c[2]; ev[k] = rows[i] }
            if (ENVIRON["KNOWN"] != "") { m = split(ENVIRON["KNOWN"], kk, "\n"); for (i = 1; i <= m; i++) have[kk[i]] = 1; check = 1 } }
    { split(ev[$0], c, " "); got = 0
      for (i = 3; i in c; i++) if (!check || (c[i] in have)) { got = 1; if (!(c[i] in out)) { out[c[i]] = 1; list = list (list == "" ? "" : " ") c[i] } }
      if (!got) { printf "ESDaemon.cfg: [modules] %s: this Mac'"'"'s eslogger offers none of its events\n", $0 > "/dev/stderr"; bad = 1 } }
    END { if (bad) exit 1; print list }'
}
# uid -> account name, so the Sysmon User field names the real (effective) account. Read once per (re)start;
# an account created later shows as uid:N until reload.sh.
users() {
  { dscl . -list /Users UniqueID 2>/dev/null || awk -F: '{print $1, $3}' /etc/passwd 2>/dev/null; } \
    | awk 'NF == 2 && $2 ~ /^-?[0-9]+$/ && !seen[$2]++ {print $2 "\t" $1}' | jq -R 'split("\t") | {(.[0]): .[1]}' | jq -cs 'add // {}'
}
case "$MODE" in
  get)  get "${3:?key}" ;;
  events) es_events ;;
  json) INC="$(rules include)" || { echo "ESDaemon.cfg: invalid [include] rule" >&2; exit 1; }
        EXC="$(rules exclude drop)" || { echo "ESDaemon.cfg: invalid [exclude] rule" >&2; exit 1; }
        PCM="$(get parent_cmdline_max)"; PCM="${PCM:-256}"
        [[ "$PCM" =~ ^[0-9]+$ ]] || { echo "ESDaemon.cfg: parent_cmdline_max must be a whole number (0 = no cap), got: $PCM" >&2; exit 1; }
        AMX="$(get args_max)"; AMX="${AMX:-4096}"
        [[ "$AMX" =~ ^[0-9]+$ ]] || { echo "ESDaemon.cfg: args_max must be a whole number (0 = no cap), got: $AMX" >&2; exit 1; }
        RMAX="$(get record_max)"; RMAX="${RMAX:-32000}"
        [[ "$RMAX" =~ ^[0-9]+$ ]] || { echo "ESDaemon.cfg: record_max must be a whole number of bytes (0 = no limit), got: $RMAX" >&2; exit 1; }
        # what reload.sh puts into the LaunchDaemon plists: a bad value here would leave eslogger crash-looping
        es_events >/dev/null || exit 1
        MODS="$(modules | jq -R 'split(" ") | {(.[0]): [.[1]]}' | jq -cs 'reduce .[] as $m ({}; . as $a | $m | to_entries[0] as $e | $a | .[$e.key] += $e.value)')"
        for k in subsystem category; do [[ "$(get $k)" =~ ^[A-Za-z0-9._-]*$ ]] || { echo "ESDaemon.cfg: $k may only contain letters, digits, . _ -" >&2; exit 1; }; done
        FMT="$(get format)"; [ -n "$FMT" ] || { [ "$(get slim)" = false ] && FMT=raw || FMT=slim; }
        case "$FMT" in sysmon|sysmon+extras|slim|raw) ;; *) echo "ESDaemon.cfg: format must be sysmon, sysmon+extras, slim or raw, got: $FMT" >&2; exit 1 ;; esac
        jq -cn --argjson modules "$MODS" --argjson include "$INC" --argjson exclude "$EXC" --arg format "$FMT" \
          --argjson parent_cmdline_max "$PCM" --argjson args_max "$AMX" --argjson record_max "$RMAX" --argjson users "$(users)" \
          '{modules:$modules,include:$include,exclude:$exclude,format:$format,parent_cmdline_max:$parent_cmdline_max,args_max:$args_max,record_max:$record_max,users:$users}' ;;
esac
