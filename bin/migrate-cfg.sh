#!/bin/bash
# migrate-cfg.sh — rewrite an older ESDaemon.cfg for this version, keeping what it logged and what it filtered out:
#   events = <eslogger events>  -> [modules] <object> = <operation>  (events with no module are listed in a comment)
#   [settings]                  kept, minus events and third_party
#   [include] / [exclude] / [drop]  kept ([drop] goes into [exclude])
#   [noisy_path_prefixes]       -> [exclude] Image begin with <p> / ParentImage begin with <p>  (ESDaemon's own path is built in)
#   [noisy_team_ids]            -> [exclude] TeamId is any <ids>  (only if third_party = drop_noisy: otherwise never applied)
#   [always] [download] [conditional]  dropped: they chose what to KEEP; every event is kept now
# Usage: migrate-cfg.sh <old.cfg>   (new cfg on stdout; validate it with cfg.sh before use)
set -euo pipefail
F="${1:?old cfg}"; HERE="$(cd "$(dirname "$0")" && pwd)"
# the module table lives in cfg.sh (installed copy or the repo's bin/)
MODTAB="$(sed -n "/^export MODTAB='/,/^'/p" "$HERE/cfg.sh" | sed '1d;$d')"; export MODTAB
[ -n "$MODTAB" ] || { echo "migrate-cfg.sh: module table not found in $HERE/cfg.sh" >&2; exit 1; }
LC_ALL=C awk '
  function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
  BEGIN { n = split(ENVIRON["MODTAB"], rows, "\n")
          for (i = 1; i <= n; i++) { m = split(rows[i], c, " "); for (j = 3; j <= m; j++) owner[c[j]] = c[1] " " c[2] } }
  NR == 1 { sub(/^\357\273\277/, "") }
  { sub(/\r$/, ""); line = trim($0) }
  line ~ /^\[.*\]/ { h = line; sub(/[ \t]+#.*$/, "", h); sect = trim(substr(h, 2, length(h) - 2)); next }
  line == "" || line ~ /^#/ { next }
  sect == "settings" {
    v = line; sub(/[ \t]+#.*$/, "", v); i = index(v, "="); k = trim(substr(v, 1, i - 1))
    if (k == "third_party") { tp = trim(substr(v, i + 1)); next }
    if (k == "events") { ne = split(trim(substr(v, i + 1)), evs, /[ \t]+/); had_events = 1; next }
    settings = settings v "\n"; next }
  sect == "modules" { mods = mods line "\n"; next }
  sect == "include" { incl = incl line "\n"; next }
  sect == "exclude" || sect == "drop" { excl = excl line "\n"; next }
  sect == "noisy_path_prefixes" { p = line; sub(/[ \t]+#.*$/, "", p)
    if (p != "/usr/local/ESDaemon/") prefixes = prefixes "Image begin with " p "\nParentImage begin with " p "\n"; next }
  sect == "noisy_team_ids" { t = line; sub(/[ \t]+#.*$/, "", t); teams = teams (teams == "" ? "" : ";") t; next }
  END {
    # events -> modules, grouped per object in the module table order
    if (had_events) {
      for (i = 1; i <= ne; i++) { e = evs[i]; if (e == "") continue
        if (e in owner) { split(owner[e], oc, " "); if (!((oc[1] " " oc[2]) in seen)) { seen[oc[1] " " oc[2]] = 1; ops[oc[1]] = ops[oc[1]] (ops[oc[1]] == "" ? "" : ", ") oc[2] } }
        else nomod = nomod " " e }
      if (mods == "") { split("process file user system", objs, " "); for (i = 1; i <= 4; i++) if (objs[i] in ops) mods = mods objs[i] " = " ops[objs[i]] "\n" }
    }
    printf "# ESDaemon.cfg — migrated from an older version by install.sh (it printed where the old file was kept).\n"
    printf "# ESDaemon logs everything [modules] lists; [include] / [exclude] narrow that down (docs/CONFIG.md).\n\n"
    printf "[settings]\n%s\n", settings
    printf "[modules]\n"
    if (nomod != "") printf "# from events =; no module for:%s (not logged any more)\n", nomod
    printf "%s\n", (mods == "" ? "process = start\n" : mods)
    printf "[include]\n%s\n[exclude]\n", incl
    if (excl != "") printf "%s", excl
    if (prefixes != "") printf "# from [noisy_path_prefixes]\n%s", prefixes
    if (teams != "" && tp == "drop_noisy") printf "# from [noisy_team_ids] (third_party = drop_noisy)\nTeamId is any %s\n", teams
  }' "$F"
