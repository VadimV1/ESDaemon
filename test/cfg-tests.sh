#!/bin/bash
# cfg-tests.sh — the cfg parser accepts what real editors produce and refuses anything it would otherwise silently ignore (so reload.sh never ships a broken or half-read filter).
# shellcheck disable=SC2034  # variables read only in the single-quoted test strings ok() evals look unused to shellcheck
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; T="$(mktemp -d)"; pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ok   $1"; else fail=$((fail+1)); echo "  FAIL $1"; fi; }
ok "default cfg parses"                  '"$ROOT/bin/cfg.sh" "$ROOT/configs/ESDaemon.cfg" json >/dev/null 2>&1'
printf '[settings]\nsubsystem = com.apple.eslogger\n' > $T/s.cfg
ok "no [modules] = process = start"      '[ "$("$ROOT/bin/cfg.sh" $T/s.cfg events)" = "exec" ]'
ok "defaults: format=slim, no include/exclude rules" '[ "$("$ROOT/bin/cfg.sh" $T/s.cfg json | jq -r "[.format,(.include|length),(.exclude|length)]|map(tostring)|join(\" \")")" = "slim 0 0" ]'
J(){ "$ROOT/bin/cfg.sh" "$1" json 2>/dev/null; }
REF="$(J "$ROOT/configs/ESDaemon.cfg")"
echo "-- what editors produce is read the same as the clean file"
sed 's/$/\r/' "$ROOT/configs/ESDaemon.cfg" > $T/crlf.cfg
ok "CRLF line endings"                   '[ "$(J $T/crlf.cfg)" = "$REF" ]'
printf '\357\273\277[settings]\nformat = raw\n' > $T/bom.cfg
ok "UTF-8 BOM before the first header"   '[ "$(J $T/bom.cfg | jq -r .format)" = raw ]'
sed -e 's/^\[always\]$/  [always]   # LOOBins/' -e 's/^curl$/\tcurl  # network/' -e 's/^format = .*/format = sysmon+extras   # SIEM/' "$ROOT/configs/ESDaemon.cfg" > $T/ws.cfg
ok "indent, tabs, inline # comments"     '[ "$(J $T/ws.cfg)" = "$REF" ]'
printf '[settings]\nsubsystem = com.corp.esd # ours\n[modules]\nfile = read, write   # loud\n' > $T/ev.cfg
ok "inline comment not part of a module or setting" '[ "$("$ROOT/bin/cfg.sh" $T/ev.cfg events)" = "open close" ] && [ "$("$ROOT/bin/cfg.sh" $T/ev.cfg get subsystem)" = com.corp.esd ]'
printf '[drop]\nCommandLine is "echo #1" AND Image is /bin/echo\n' > $T/dh.cfg
ok "# stays in a [drop] value"           '[ "$(J $T/dh.cfg | jq -r ".exclude[0][0].value")" = "echo #1" ]'
printf '[settings]\nslim = false\n' > $T/legacy.cfg
ok "legacy slim = false -> raw"          '[ "$(J $T/legacy.cfg | jq -r .format)" = raw ]'
echo "-- silent misconfiguration is refused (a typo must not switch detection off)"
bad(){ printf "$1" > $T/b.cfg; ! "$ROOT/bin/cfg.sh" $T/b.cfg json >/dev/null 2>&1; }
ok "unknown section [alwyas]"            'bad "[alwyas]\ncurl\n"'
ok "section name case [Always]"          'bad "[Always]\ncurl\n"'
ok "value before any section"            'bad "curl\n[always]\nwget\n"'
ok "unknown key (Format)"                'bad "[settings]\nFormat = raw\n"'
ok "settings line without ="             'bad "[settings]\nformat raw\n"'
ok "key set twice"                       'bad "[settings]\nformat = raw\nformat = sysmon\n"'
ok "format typo sysmonextras"            'bad "[settings]\nformat = sysmonextras\n"'
ok "format wrong case"                   'bad "[settings]\nformat = Sysmon\n"'
ok "third_party typo drop-noisy"         'bad "[settings]\nthird_party = drop-noisy\n"'
ok "slim not true/false"                 'bad "[settings]\nslim = no\n"'
ok "old events = setting refused"        'bad "[settings]\nevents = exec\n"'
ok "unknown module object refused"       'bad "[modules]\nfiles = read\n"'
ok "unknown module operation refused"    'bad "[modules]\nfile = reed\n"'
ok "module XML injection refused"        'bad "[modules]\nfile = read</string><string>-h\n"'
ok "module without operation refused"    'bad "[modules]\nfile =\n"'
ok "subsystem with spaces"               'bad "[settings]\nsubsystem = com.corp esd\n"'
ok "subsystem path traversal"            'bad "[settings]\nsubsystem = ../../../tmp/x\n"'
ok "path in [always]"                    'bad "[always]\n/usr/local/bin/kubectl\n"'
ok "path in [conditional]"               'bad "[conditional]\n/bin/sh\n"'
ok "Team ID malformed"                   'bad "[noisy_team_ids]\nubf8t346g9\n"'
ok "prefix /"                            'bad "[noisy_path_prefixes]\n/\n"'
ok "prefix relative"                     'bad "[noisy_path_prefixes]\nopt/foo/\n"'
ok "get refuses an invalid file too"     'bad "[alwyas]\ncurl\n" &&! "$ROOT/bin/cfg.sh" $T/b.cfg get subsystem >/dev/null 2>&1'
echo "-- end to end: a CRLF cfg still logs curl"
EV='{"process":{"executable":{"path":"/bin/zsh"},"is_platform_binary":true,"audit_token":{"pid":7}},"event":{"exec":{"target":{"executable":{"path":"/usr/bin/curl"},"is_platform_binary":true,"audit_token":{"pid":8},"ppid":7},"args":["curl","-s","https://x/a"]}}}'
ok "curl kept with CRLF cfg"             '[ "$(echo "$EV" | jq -n -cR --argjson cfg "$(J $T/crlf.cfg)" -f "$ROOT/src/scope.jq" | grep -c /usr/bin/curl)" = 1 ]'
echo "-- removed keep-rule settings fail loudly (an old cfg must not be half-read)"
ok "[always] refused"                     'bad "[always]\ncurl\n" && { "$ROOT/bin/cfg.sh" $T/b.cfg json 2>&1 || true; } | grep -q "was removed"'
ok "third_party refused"                  'bad "[settings]\nthird_party = all\n" && { "$ROOT/bin/cfg.sh" $T/b.cfg json 2>&1 || true; } | grep -q "third_party was removed"'
printf '[include]\nEventType is ProcessStart\n[exclude]\nImage is /bin/ls\n[drop]\nImage is /bin/ps\n' > $T/ie.cfg
ok "[include] parsed; [drop] is an alias of [exclude]" '[ "$(J $T/ie.cfg | jq -c "[(.include|length),(.exclude|length)]")" = "[1,2]" ]'
echo "-- a keep-rule (v1) cfg migrates: settings and exclusions carried over, keep lists gone"
"$ROOT/bin/migrate-cfg.sh" "$ROOT/test/fixtures/v1.cfg" > $T/m.cfg
ok "migrated v1 default cfg is valid"     '"$ROOT/bin/cfg.sh" $T/m.cfg json >/dev/null'
M="$(J $T/m.cfg)"
ok "settings kept (format, record_max)"   '[ "$(echo "$M" | jq -r "[.format,.record_max]|map(tostring)|join(\" \")")" = "sysmon+extras 32000" ]'
ok "noisy_path_prefixes -> Image/ParentImage excludes, ESDaemon path left to the built-in" '[ "$(echo "$M" | jq -c "[.exclude[][] | .field+\" \"+.value]")" = "[\"Image /opt/observiq-otel-collector/\",\"ParentImage /opt/observiq-otel-collector/\"]" ]'
ok "noisy_team_ids not carried when third_party = all (v1 never applied them)" '! grep -q "TeamId" $T/m.cfg'
ok "no keep-list sections left"           '! grep -Eq "^\[(always|download|conditional|noisy_team_ids|noisy_path_prefixes)\]|^third_party" $T/m.cfg'
printf '[settings]\nformat = slim\nthird_party = drop_noisy\n[always]\ncurl\n[drop]\nImage is /usr/bin/true AND User is root\n[noisy_team_ids]\nEQHXZ8M8AV\nUBF8T346G9\n' > $T/v1b.cfg
"$ROOT/bin/migrate-cfg.sh" $T/v1b.cfg > $T/m2.cfg
ok "drop_noisy team IDs and [drop] rules carried into [exclude]" '[ "$(J $T/m2.cfg | jq -c "[.format, (.exclude|length), .exclude[0][1].field, .exclude[1][0].value]")" = "[\"slim\",2,\"User\",\"EQHXZ8M8AV;UBF8T346G9\"]" ]'
printf '[settings]\nevents = exec create unlink open chdir\nformat = sysmon\n[include]\nImage image curl\n[exclude]\nImage is /bin/ls\n' > $T/v2.cfg
"$ROOT/bin/migrate-cfg.sh" $T/v2.cfg > $T/m3.cfg
ok "events = migrates to [modules]; unknown events listed, include/exclude kept" '"$ROOT/bin/cfg.sh" $T/m3.cfg json >/dev/null && [ "$("$ROOT/bin/cfg.sh" $T/m3.cfg events)" = "exec create unlink open" ] && grep -q "no module for: chdir" $T/m3.cfg && [ "$(J $T/m3.cfg | jq -c "[(.include|length),(.exclude|length),.format]")" = "[1,1,\"sysmon\"]" ]'
echo; echo "PASS $pass  FAIL $fail"; [ $fail -eq 0 ]
