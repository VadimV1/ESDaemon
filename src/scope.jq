# scope.jq — decide per eslogger event whether it is worth shipping, and slim it.
# Invoked:  jq -n -cR --unbuffered --argjson cfg "$CFG" -f scope.jq
# Input:    one eslogger JSON event per line (raw, parsed with fromjson? so a bad line is skipped not fatal)
# Output:   the kept events, slimmed, one per line. Dropped events produce nothing.
#
# $cfg = {always:[...], conditional:[...], noisy_team_ids:[...], noisy_prefixes:[...], slim:true|false}

def base: if . == null then "" else (split("/") | last) end;
def starts_any($prefixes): . as $p | any($prefixes[]; . as $x | $p | startswith($x));

# Execution from a place legitimate software rarely runs from (curated: staging, hidden dirs, DMG mounts).
def staging_path:
  test("^/(private/)?(tmp|var/tmp)/|^/private/var/folders/|^/var/folders/|^/Users/Shared/|^/Volumes/|/Downloads/|/Library/Application Support/\\.|/\\.com\\.apple\\.|/Library/Caches/|/bun-dl-");

# An Apple platform binary living outside the OS locations = copied/masqueraded system binary.
def platform_outside_system:
  test("^/(System|usr|bin|sbin|Applications|Library/Apple|Library/Developer|private/var/db)/") | not;

# argv content that makes an otherwise chatty binary interesting (derived from the curated macOS rule regexes + LOOBins).
def risky_argv:
  test("curl|wget|https?://|base64|osascript|/tmp/|/private/var/tmp|/Users/Shared|/Volumes/|\\beval\\b|nohup|\\bsecurity\\b|xattr|com\\.apple\\.quarantine|chmod\\s+(\\+x|[0-7]*7)|dscl|launchctl\\s+(load|bootstrap|submit|enable)|LaunchAgents|LaunchDaemons|Keychains|keychain-db|Cookies|Login Data|Local State|TCC\\.db|\\.ssh/|Telegram|ditto\\s+-c|zip\\s+-|/dev/tcp|mkfifo|\\bnc\\b|(python[0-9.]*|perl|ruby|node|php)(\\s.*)?\\s-(c|e)\\s|urlopen|urlretrieve|requests\\.(get|post)|http\\.client|NSURLSession|curl_exec|file_get_contents|net/http|open-uri|IOPlatform|VirtualMac|VMware|Parallels|screencapture|pbpaste|loginwindow|kextload|nvram|spctl|csrutil"; "i");

# File paths worth a file event (curated macOS file rules + persistence locations).
def file_interesting:
  test("/Library/Launch(Agents|Daemons)/|/Library/StartupItems/|com\\.apple\\.loginwindow\\.plist|com\\.apple\\.loginitems|backgrounditems\\.btm|/\\.(zshrc|zprofile|zshenv|zlogin|bash_profile|bashrc|profile)$|/usr/lib/cron/|/private/etc/(sudoers|hosts|pam\\.d|periodic)|\\.ccache$|^/(private/)?(tmp|var/tmp)/|/Users/Shared/|/Library/Application Support/\\.|/Library/Google/Cache/\\.|/\\.vscode-oss/|site-packages/[^/]+\\.pth$|\\.keychain(-db)?$|TCC\\.db$|/Library/Caches/com\\.apple\\.|\\.(command|scpt|applescript|terminal)$|\\.tar\\.gz$|/Chrome/.*/(Extensions|NativeMessagingHosts)/"; "i");

def keep_env: [ (.[]? // empty) | select(test("^(XPC_SERVICE_NAME|PATH|USER|LOGNAME|HOME|SHELL|SUDO_[A-Z]+|DYLD_[A-Z_]+|LD_[A-Z_]+|SSH_CONNECTION|TERM_PROGRAM)=")) ];

# Slim a process block: keep identity, signing, lineage; drop stat blocks, audit-token noise, thread, mach_time.
def slim_proc:
  if . == null then null else {
    path: .executable.path,
    pid: .audit_token.pid,
    euid: .audit_token.euid,
    ruid: .audit_token.ruid,
    ppid: .ppid,
    original_ppid: .original_ppid,
    responsible_pid: .responsible_audit_token.pid,
    group_id: .group_id,
    session_id: .session_id,
    signing_id: .signing_id,
    team_id: .team_id,
    cdhash: .cdhash,
    is_platform_binary: .is_platform_binary,
    codesigning_flags: .codesigning_flags,
    is_es_client: .is_es_client,
    tty: .tty.path,
    start_time: .start_time,
    parent_path: .parent_path
  } | with_entries(select(.value != null)) end;

def slim_rec($ev):
  if true then
    { time: .time, seq_num: .seq_num, global_seq_num: .global_seq_num, event: $ev,
      process: (.process | slim_proc) }
    + ( if $ev == "exec" then
          { exec: { target: (.event.exec.target | slim_proc),
                    args: .event.exec.args,
                    cwd: .event.exec.cwd.path,
                    script: .event.exec.script.path,
                    env: (.event.exec.env | keep_env),
                    target_birthtime: .event.exec.target.executable.stat.st_birthtimespec,
                    fds: .event.exec.fds } }
        else { detail: .event[$ev] } end )
  else . end;

# ---- Sysmon-style output (format = sysmon) ----
# Exec -> EventID 1 ProcessCreate, create/rename -> 11 FileCreate, unlink -> 23 FileDelete; other events fall back to slim.
# Field names follow Sysmon (and Sysmon for Linux). Values eslogger cannot supply are left out, never invented.
def sysmon_time: (. // "") | sub("T"; " ") | sub("(?<ms>\\.[0-9]{3})[0-9]*Z$"; "\(.ms)") | sub("Z$"; "");
def cmdline: [ .[]? | tostring | if test("[ \\t\"]") then "\"" + gsub("\""; "\\\"") + "\"" else . end ] | join(" ");
def user_of($env; $uid): ([$env[]? | select(startswith("USER=")) | sub("^USER="; "")] | first) // ("uid:" + ($uid | tostring));
def sysmon($ev):
  .time as $t | .process as $p |
  { Channel: "ESDaemon/Operational", Computer: null, UtcTime: ($t | sysmon_time), RuleName: "-" } +
  ( if $ev == "exec" then
      .event.exec as $x | $x.target as $tg |
      { EventID: 1, EventType: "ProcessCreate",
        ProcessGuid: ("{" + ($tg.audit_token.pid | tostring) + "-" + (($p.start_time // $t) | tostring) + "}"),
        ProcessId: $tg.audit_token.pid,
        Image: $tg.executable.path,
        CommandLine: ($x.args | cmdline),
        CurrentDirectory: $x.cwd.path,
        User: user_of($x.env; $tg.audit_token.euid),
        TerminalSessionId: $tg.session_id,
        Hashes: (if $tg.cdhash then "CDHASH=" + $tg.cdhash else null end),
        ParentProcessId: $tg.ppid,
        ParentImage: $p.executable.path,
        ParentCommandLine: (.__esd_parent.c // null),
        ParentProcessGuid: (.__esd_parent.g // null),
        OriginalFileName: ($tg.executable.path | split("/") | last) }
      + ( if $cfg.format == "sysmon+extras" then
          # macOS extras (not in Sysmon): code signing and lineage Sysmon has no slot for
          { SigningId: $tg.signing_id, TeamId: $tg.team_id, IsPlatformBinary: $tg.is_platform_binary,
        ParentSigningId: $p.signing_id, ParentTeamId: $p.team_id, ParentIsPlatformBinary: $p.is_platform_binary,
        OriginalParentProcessId: $tg.original_ppid, ResponsibleProcessId: $tg.responsible_audit_token.pid,
        Uid: $tg.audit_token.euid, Tty: $tg.tty.path, Script: $x.script.path } else {} end )
    elif ($ev | IN("create","rename","unlink")) then
      [ .event[$ev] | .. | objects | select(has("dir") and has("filename")) | ((.dir.path // "") + "/" + (.filename // "")) ] as $newp |
      [ .event[$ev] | .. | objects | select(has("dir") | not) | .path? | select(type == "string") ] as $plain |
      ($plain + $newp) as $paths |
      { EventID: (if $ev == "unlink" then 23 else 11 end),
        EventType: (if $ev == "unlink" then "FileDelete" else "FileCreate" end),
        ProcessGuid: ("{" + ($p.audit_token.pid | tostring) + "-" + (($p.start_time // $t) | tostring) + "}"),
        ProcessId: $p.audit_token.pid, Image: $p.executable.path, User: ("uid:" + ($p.audit_token.euid | tostring)),
        TargetFilename: ($paths | last),
        SourceFilename: (if $ev == "rename" then ($paths | first) else null end) }
      + ( if $cfg.format == "sysmon+extras" then { SigningId: $p.signing_id, TeamId: $p.team_id, IsPlatformBinary: $p.is_platform_binary } else {} end )
    else { EventID: 255, EventType: $ev, Detail: slim_rec($ev) } end )
  | with_entries(select(.value != null));

def emit($ev):
  if   $cfg.format == "raw" then del(.__esd_parent)
  elif ($cfg.format | startswith("sysmon")) then sysmon($ev)
  else slim_rec($ev) end;

# [drop] rule match. A rule is a list of clauses {field, op, value}; every clause must hold (AND).
# Conditions follow Sysmon semantics and are case-insensitive. A clause on a field the event doesn't carry
# (e.g. ParentCommandLine when the parent's exec was never seen) is false, so unknown data never drops an event.
def clause_ok($f):
  . as $c
  | ($f[$c.field]) as $v
  | if $v == null then false else
      ($v | tostring | ascii_downcase) as $s
      | ($c.value | ascii_downcase) as $x
      | ($x | split(";") | map(select(. != ""))) as $xs
      | if   $c.op == "is"             then $s == $x
        elif $c.op == "is not"         then $s != $x
        elif $c.op == "is any"         then any($xs[]; . == $s)
        elif $c.op == "contains"       then ($s | contains($x))
        elif $c.op == "contains any"   then any($xs[]; . as $y | $s | contains($y))
        elif $c.op == "contains all"   then all($xs[]; . as $y | $s | contains($y))
        elif $c.op == "excludes"       then ($s | contains($x) | not)
        elif $c.op == "excludes any"   then any($xs[]; . as $y | $s | contains($y) | not)
        elif $c.op == "excludes all"   then all($xs[]; . as $y | $s | contains($y) | not)
        elif $c.op == "begin with"     then ($s | startswith($x))
        elif $c.op == "not begin with" then ($s | startswith($x) | not)
        elif $c.op == "end with"       then ($s | endswith($x))
        elif $c.op == "not end with"   then ($s | endswith($x) | not)
        elif $c.op == "image"          then ($s == $x or ($s | split("/") | last) == $x)
        elif $c.op == "regex"          then ($v | tostring | test($c.value; "i"))
        else false end
    end;
def rule_ok($f): all(.[]; clause_ok($f));

def decide:
(.event | keys[0]) as $ev |
( .process.executable.path // "" ) as $ppath |
if ($ev | IN("create","rename","write","close","open","unlink","link","clone","truncate")) then
  # File events: keep only persistence / staging / credential paths (curated file rules + LOOBins persistence).
  # Shape-tolerant: collects every .path and every {dir,filename} pair anywhere under the event.
  [ .event[$ev] | .. | objects
    | if has("dir") and has("filename") then ((.dir.path // "") + "/" + (.filename // ""))
      elif ((.path? | type) == "string") then .path else empty end ] as $paths
  | if ([$paths[] | file_interesting] | any) and ($ppath | starts_any($cfg.noisy_prefixes) | not)
    then emit($ev) else empty end
elif $ev != "exec" then
  # Other non-exec events (btm_launch_item_add, xp_malware_detected, authentication, sudo, od_*, login_*, setextattr ...)
  # are subscribed deliberately because they are low-volume and high-value; pass them through slimmed.
  emit($ev)
else
  .event.exec.target as $t |
  ($t.executable.path // "") as $tpath |
  ($tpath | base) as $tb |
  ([.event.exec.args[]? | tostring] | join(" ")) as $argv |
  ($t.is_platform_binary == true) as $tplat |
  (($t.team_id // "") ) as $tteam |
  # --- hard drops: collector self-noise and allowlisted vendors (target side only) ---
  # [drop] rules (Sysmon-style clauses, see docs/CONFIG.md). Checked before every keep rule.
  (.__esd_parent.c // null) as $pcmd |
  { Image: $tpath, CommandLine: (.event.exec.args | cmdline), ParentImage: $ppath, ParentCommandLine: $pcmd,
    User: user_of(.event.exec.env; $t.audit_token.euid), TeamId: $t.team_id, SigningId: $t.signing_id } as $df |
  if any(($cfg.drop // [])[]; rule_ok($df)) then empty
  elif ($tpath | starts_any($cfg.noisy_prefixes)) or ($ppath | starts_any($cfg.noisy_prefixes)) then empty
  elif ($cfg.third_party == "drop_noisy") and ($tplat | not) and ($tteam != "") and (any($cfg.noisy_team_ids[]; . == $tteam)) then empty
  else
    ( ($ppath | base) as $pb
      | ($pb | IN("osascript","osacompile","curl","wget","bun","Script Editor"))
        or ((.process.is_platform_binary != true) and ((.process.team_id // "") == ""))
        or ($ppath | staging_path) ) as $interesting_parent |
    if   ($tpath | staging_path) then emit($ev)                                  # ran from staging/hidden/DMG
    elif $tplat and ($tpath | platform_outside_system) then emit($ev)            # masqueraded Apple binary
    elif ($tplat | not) then emit($ev)                                           # third-party / unsigned / ad-hoc
    elif any($cfg.always[]; . == $tb) then emit($ev)
    elif any($cfg.conditional[]; . == $tb) then
      if $interesting_parent or ($argv | risky_argv)
         or (($tb | IN("sh","bash","zsh","dash","ksh")) and ((.event.exec.args | length) <= 1))  # script on stdin
      then emit($ev) else empty end
    elif $interesting_parent then emit($ev)                                      # anything osascript/unsigned spawns
    else empty end
  end
end
;

# Main loop (run with jq -n -R): track global_seq_num across ALL raw events, before filtering.
# A jump > 1 means EndpointSecurity dropped events (usually a slow reader filling the pipe). Emit a marker
# so drops are visible in the SIEM instead of silently looking like a quiet host.
# It also keeps pid -> {command line, guid} from EVERY exec it sees (kept or dropped), so a later child can be given
# ParentCommandLine / ParentProcessGuid. ES exec events carry args for the NEW process only; the parent's args come
# from the parent's own earlier exec. Parents started before ESDaemon (or by launchd at boot) stay unknown.
foreach (inputs | fromjson? | select(type == "object")) as $e (
  {last: null, pc: {}};
  ($e.global_seq_num // null) as $g
  | .gap = (if (.last != null and $g != null and ($g - .last) > 1) then ($g - .last - 1) else 0 end)
  | .last = ($g // .last)
  | if $e.event.exec then
      ($e.event.exec.target) as $tg
      | (($tg.ppid // "none") | tostring) as $pp
      | .e = ($e + {__esd_parent: .pc[$pp]})
      | (if (.pc | length) > 50000 then .pc = {} else . end)          # bound memory; a reset only loses parent context
      | .pc[($tg.audit_token.pid | tostring)] = { c: ($e.event.exec.args | cmdline),
            g: ("{" + ($tg.audit_token.pid | tostring) + "-" + (($e.process.start_time // $e.time) | tostring) + "}") }
    else .e = $e end;
  (if .gap > 0 then {eslogger_scoped_gap: .gap, time: .e.time, after_global_seq_num: .last} else empty end),
  (.e | decide)
)
