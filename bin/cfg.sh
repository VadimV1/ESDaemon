#!/bin/bash
# cfg.sh — read ESDaemon.cfg.
#   cfg.sh <file> json          -> JSON object the filter (scope.jq) uses
#   cfg.sh <file> get <key>     -> one [settings] value
set -euo pipefail
F="${1:?cfg file}"; MODE="${2:-json}"
section() { awk -v s="[$1]" '/^[[:space:]]*#/||/^[[:space:]]*$/{next} /^\[/{on=($0==s);next} on{gsub(/^[ \t]+|[ \t]+$/,"");print}' "$F"; }
get() { section settings | awk -v k="$1" '{i=index($0,"="); if(!i)next; key=substr($0,1,i-1); val=substr($0,i+1); gsub(/[ \t]/,"",key); gsub(/^[ \t]+|[ \t]+$/,"",val); if(key==k){print val; exit}}'; }
arr() { section "$1" | jq -R . | jq -cs .; }
# [drop] lines: "<binary | full path | *> | <regex on the command line>"  ->  [{bin,re}]. Every regex is compiled
# here so a typo fails reload.sh instead of crashing the running filter.
drops() {
  # [drop] syntax = Sysmon's own filter vocabulary, one rule per line, clauses joined with AND:
  #   <Field> <condition> <value> [AND <Field> <condition> <value> ...]
  # Fields: Image, CommandLine, ParentImage, ParentCommandLine, User, TeamId, SigningId
  # Conditions (case-insensitive, same meaning as Sysmon): is, is not, is any, contains, contains any,
  #   contains all, excludes, excludes any, excludes all, begin with, not begin with, end with, not end with,
  #   image, regex.  "... any/all" take ;-separated values. Quote a value ("...") if it contains " AND ".
  # Output: [[{field, op, value}, ...], ...]  (outer list = OR of lines, inner list = AND of clauses)
  section drop | jq -R '
    def fields: ["Image","CommandLine","ParentImage","ParentCommandLine","User","TeamId","SigningId"];
    def ops: "not begin with|not end with|begin with|end with|is any|is not|is|contains any|contains all|contains|excludes any|excludes all|excludes|image|regex";
    def clause_re: "(?:^\\s*|\\s+(?-i:AND)\\s+)(?<field>[A-Za-z]+)\\s+(?<op>" + ops + ")\\s+(?<value>\"(?:[^\"\\\\]|\\\\.)*\"|.+?)(?=\\s+(?-i:AND)\\s+|\\s*$)";
    . as $line
    | [ match(clause_re; "gi") | [.captures[] | {(.name): .string}] | add
        | .op |= (ascii_downcase | gsub("\\s+"; " "))
        | if (.value | test("\\s(?-i:AND)$")) then error("dangling AND at end of: \($line)") else . end
        | .value |= (if test("^\".*\"$") then .[1:-1] | gsub("\\\\\""; "\"") else . end)
        | . as $c | (fields | map(ascii_downcase) | index($c.field | ascii_downcase)) as $fi
        | if $fi == null then error("unknown field \"\($c.field)\" in: \($line)  (use one of \(fields | join(", ")))") else .field = fields[$fi] end
        | if .op == "regex" then (. as $c | try ("x" | test($c.value)) catch error("bad regex \"\($c.value)\" in: \($line)")) as $_ | . else . end
      ] as $clauses
    | ($line | gsub(clause_re; ""; "gi") | gsub("\\s+(?-i:AND)\\s+|\\s+"; "")) as $rest
    | if ($clauses | length) == 0 or $rest != "" then error("cannot parse drop rule: \($line)\n  expected: <Field> <condition> <value> [AND ...], e.g.  Image is /usr/bin/curl AND CommandLine contains updates.example.com") else $clauses end
  ' | jq -cs .
}
case "$MODE" in
  get)  get "${3:?key}" ;;
  json) DROP="$(drops)" || { echo "ESDaemon.cfg: invalid [drop] rule" >&2; exit 1; }
        jq -cn --argjson always "$( (section always; section download) | jq -R . | jq -cs .)" --argjson conditional "$(arr conditional)" \
          --argjson noisy_team_ids "$(arr noisy_team_ids)" --argjson noisy_prefixes "$(arr noisy_path_prefixes)" --argjson drop "$DROP" \
          --arg third_party "$(t=$(get third_party); echo "${t:-all}")" --arg format "$(f=$(get format); [ -z "$f" ] && { [ "$(get slim)" = false ] && f=raw || f=slim; }; echo "$f")" \
          '{always:$always,conditional:$conditional,noisy_team_ids:$noisy_team_ids,noisy_prefixes:$noisy_prefixes,drop:$drop,third_party:$third_party,format:$format}' ;;
esac
