# scope.jq — turn eslogger events into ESDaemon records. Every event is logged unless the [include]/[exclude]
# rules in ESDaemon.cfg say otherwise (Sysmon semantics, see docs/CONFIG.md).
# Invoked:  jq -n -cR --unbuffered --argjson cfg "$CFG" -f scope.jq
# Input:    one eslogger JSON event per line (raw, parsed with fromjson? so a bad line is skipped not fatal)
# Output:   one record per logged event. Filtered events produce nothing.
#
# $cfg = {include:[rule...], exclude:[rule...], format, parent_cmdline_max, record_max, users}
#        rule = [{field, op, value}, ...]  (clauses ANDed; rules in a section ORed)

# ESDaemon's own install. Its processes are never logged (see the main loop), or every record it writes would
# spawn more records. Only root can put a binary here or start the launchd jobs: install.sh, reload.sh and
# esdaemon status check that nobody else can write here or above (bin/chain.sh).
def esd_base: "/usr/local/ESDaemon/";
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
          { exec: ({ target: (.event.exec.target | slim_proc),
                    args: .event.exec.args,
                    cwd: .event.exec.cwd.path,
                    script: .event.exec.script.path,
                    env: (.event.exec.env | keep_env),
                    target_birthtime: .event.exec.target.executable.stat.st_birthtimespec,
                    fds: .event.exec.fds } | with_entries(select(.value != null))) }
        else { detail: .event[$ev] } end )
  else . end;

# ---- Sysmon-style output (format = sysmon) ----
# Every event is named <Object><Operation> by event_kind (ProcessStart = Sysmon 1, FileCreate = 11, FileDelete = 23 ...).
# Field names follow Sysmon (and Sysmon for Linux). Values eslogger cannot supply are left out, never invented.
def sysmon_time: (. // "") | (capture("^(?<d>[0-9-]+)T(?<h>[0-9:]+)(\\.(?<f>[0-9]+))?Z$") // null) as $c
  | if $c == null then . else $c.d + " " + $c.h + "." + (($c.f // "") + "000")[0:3] end;
# ProcessGuid in Sysmon's GUID shape, derived from (process start time, pid) so a child's ParentProcessGuid equals its
# parent's ProcessGuid: {SSSSSSSS-UUUU-UUUU-0000-PPPPPPPPPPPP} = start epoch seconds, microseconds, pid (hex).
def hex($w): [recurse(if . >= 16 then (. / 16 | floor) else empty end) | . % 16 | "0123456789ABCDEF"[.:.+1]]
  | reverse | join("") | ("0" * ($w - length)) + .;
def procguid($pid; $start):
  ($start // "" | tostring | capture("^(?<d>[0-9-]+T[0-9:]+)(\\.(?<f>[0-9]+))?Z$") // null) as $c
  | if $c == null or $pid == null then null else
      # the capture regex admits impossible dates (month 13, 1-1-1T...): fromdateiso8601 throws on those, so guard
      # it — this runs in the per-event state update, which must never throw (see the main loop's no-crash rule).
      (($c.d + "Z") | (try fromdateiso8601 catch null)) as $sec
      | if $sec == null then null else
          ($sec | hex(8)) as $s | ((($c.f // "") + "000000")[0:6] | tonumber | hex(8)) as $u
          | ($pid | hex(12)) as $p
          | "{" + $s + "-" + $u[0:4] + "-" + $u[4:8] + "-0000-" + $p + "}" end end;
# Windows (CommandLineToArgvW) quoting, the convention Sysmon's CommandLine uses: an argument is quoted when it is empty
# or holds whitespace or a quote; inside quotes a quote is \" and backslashes are doubled only before a quote.
# Every argv maps to one string that parses back to the same argv.
# argv is attacker-controlled and can hold hundreds of thousands of elements (within ARG_MAX ~1 MB); rendering all
# of them (a regex test per element) stalls this serial filter for seconds, so EndpointSecurity drops real events
# behind it. Cap the element count at args_max (0 = no cap) and mark the cut; record_max still bounds total bytes.
# One argument can be that long too, so quoting takes time linear in its length, whatever it holds: split it at the
# quotes, double the backslashes each part ends in (they stand before a quote), rejoin with \". No regex rewrite:
# its time can grow with the square of the length.
def cmdline:
  # the backslashes a string ends in, found by halving it: if the second half is all backslashes, the run takes it
  # whole and may go on into the first; else it lies within the second. Linear in the string's length; the first
  # tests settle short runs at once.
  def bs_tail: if endswith("\\") | not then "" elif endswith("\\\\") | not then "\\" elif . == "\\" * length then .
    else (length / 2 | floor) as $h | .[$h:] as $r
    | if $r == "\\" * ($r | length) then (.[:$h] | bs_tail) + $r else $r | bs_tail end end;
  # join($s) without jq's join, which copies the string built so far for every element: this appends to it in place
  # (. + $s | . + $x: written as one sum, it would be copied too)
  def cat($s): reduce .[1:][] as $x (.[0] // ""; . + $s | . + $x);
  def quote: "\"" + (split("\"") | map(if endswith("\\") then . + bs_tail else . end) | cat("\\\"")) + "\"";
  (if type == "array" then . else [] end) as $a | ($a | length) as $n | ($cfg.args_max // 0) as $cap
  | (if $cap > 0 and $n > $cap then $a[0:$cap] else $a end
     | map(tostring | if length == 0 or test("[\\s\"]") then quote else . end) | cat(" "))
  | if $cap > 0 and $n > $cap then . + " …[+" + (($n - $cap) | tostring) + " args]" else . end;
# ParentCommandLine is copied into every child's event, so one long parent command inflates all its children.
# Cap it on output only ([drop] rules still see the full value); the parent's own event keeps its full CommandLine.
def cap($n): if $n > 0 and length > $n then .[0:$n] + " …[+" + ((length - $n) | tostring) + " chars]" else . end;
# User = account of the effective uid, resolved from the host's user list (cfg.sh). Never from the USER env var:
# the environment is attacker-controlled (env USER=svc_x cmd), and [drop] rules can match User.
def user_of($uid): if $uid == null then null else (($cfg.users // {})[$uid | tostring] // ("uid:" + ($uid | tostring))) end;
# Parent image/signing: the parent's own cached exec when known (checked by pidversion), else the exec event's
# .process -- that is the pre-exec image of the SAME pid, which equals the parent only after a fork. If this pid had
# already exec'd (sh -c 'exec curl', env curl), .process is that earlier image, not the parent: leave it unknown.
# Started by launchd: parent pid 1 from the start (original_ppid 1 too). pid 1 is always launchd, so its image is
# known without having seen it. A process re-parented to pid 1 later (double fork, parent exited) keeps its
# original_ppid, so it is not mistaken for a launchd job.
def launchd_child($p): $p != null and $p.ppid == 1 and (($p.original_ppid // null) == 1);
# When the prior exec of this pid was not seen (pre-ESDaemon, or after a cache reset), .process is this pid's own
# earlier image, not its parent. For a reparented process (original_ppid != ppid) that is misleading, so report the
# parent as unknown there (matches docs/CONFIG.md); only a plain fork+exec (original_ppid == ppid) keeps .process.
def parent_info: .__esd_parent
  // (if launchd_child(.event.exec.target) then {i: "/sbin/launchd"}
      elif .__esd_chain then {}
      else (.event.exec.target as $t
            | if $t.original_ppid != null and $t.original_ppid != $t.ppid then {}
              else (.process | {i: .executable.path}) end) end);
# ES file event shapes: unlink {target, parent_dir}; create {destination: {existing_file | new_path{dir,filename}}};
# rename {source, destination: same}; open {file}; close / attribute changes {target}. JSON key order varies,
# so pick fields by name, never by position.
def fpath: if .existing_file then .existing_file.path
           elif .new_path then ((.new_path.dir.path // "" | rtrimstr("/")) + "/" + (.new_path.filename // ""))
           else .path end;
def target_file($ev): .event[$ev] as $fe
  | if $ev == "unlink" then $fe.target.path elif ($ev | IN("create","rename")) then ($fe.destination // {} | fpath)
    else ($fe.target.path // $fe.file.path // null) end;
# What each eslogger event is called in the output: [EventType, EventID]. [modules] (cfg.sh) picks the events; this
# names them <Object><Operation>. Sysmon's EventID where Sysmon has the same event, ESDaemon's own 100+ otherwise.
def event_kind($ev):
  { exec: ["ProcessStart", 1], exit: ["ProcessExit", 5],
    get_task: ["ProcessInject", 10], get_task_read: ["ProcessInject", 10], get_task_inspect: ["ProcessInject", 10],
    remote_thread_create: ["ProcessInject", 8], trace: ["ProcessInject", 10],
    create: ["FileCreate", 11], unlink: ["FileDelete", 23],
    open: ["FileRead", 101], close: ["FileWrite", 102], rename: ["FileRename", 103],
    setextattr: ["FileAttributes", 104], deleteextattr: ["FileAttributes", 104], setmode: ["FileAttributes", 104],
    setowner: ["FileAttributes", 104], setflags: ["FileAttributes", 104], setacl: ["FileAttributes", 104],
    authentication: ["UserLogin", 111], login_login: ["UserLogin", 111], openssh_login: ["UserLogin", 111],
    lw_session_login: ["UserLogin", 111], lw_session_unlock: ["UserLogin", 111], screensharing_attach: ["UserLogin", 111],
    login_logout: ["UserLogout", 112], openssh_logout: ["UserLogout", 112], lw_session_logout: ["UserLogout", 112],
    lw_session_lock: ["UserLogout", 112], screensharing_detach: ["UserLogout", 112],
    sudo: ["UserSudo", 113], su: ["UserSudo", 113],
    btm_launch_item_add: ["SystemPersistence", 121], btm_launch_item_remove: ["SystemPersistence", 121],
    xp_malware_detected: ["SystemMalware", 122], xp_malware_remediated: ["SystemMalware", 122],
    kextload: ["SystemKernel", 123], kextunload: ["SystemKernel", 123],
    mount: ["SystemMount", 124], unmount: ["SystemMount", 124], remount: ["SystemMount", 124] }[$ev]
  // (if ($ev | startswith("od_")) then ["UserAccount", 114] else [$ev, 255] end);
def is_file_kind($ev): event_kind($ev)[0] | startswith("File");
# file = read is an open WITHOUT write access; file = write is a close of a file that was changed (one record per
# written file, not per write call). Other opens/closes are not those operations.
def wanted($ev):
  if   $ev == "open"  then ((.event.open.fflag // 0) / 2 | floor) % 2 == 0      # FWRITE (0x2) not set
  elif $ev == "close" then .event.close.modified == true
  else true end;
# event payload without the bulky stat blocks, for records that carry it as Detail
def detail($ev): .event[$ev] | walk(if type == "object" then del(.stat) else . end);
# Field order of every sysmon record, read top-down: what happened (and its number, in sysmon+extras), who ran what,
# the process, its parent and lineage, then code-signing identity. Keys not listed keep their place after these.
def field_order:
  . as $o
  | ["EventID","EventType","UtcTime","GlobalSeqNum",
     "User","Image","CommandLine","CurrentDirectory","TargetFilename","SourceFilename",
     "TargetImage","TargetProcessId","ExitStatus",
     "ProcessId","ProcessGuid",
     "ParentImage","ParentCommandLine","ParentProcessId","ParentProcessGuid",
     "OriginalParentProcessId","ResponsibleProcessId","TerminalSessionId","Tty","Script",
     "SigningId","TeamId","IsPlatformBinary","CDHash","Detail"] as $k
  | ([$k[] | . as $f | select($o | has($f)) | {key: $f, value: $o[$f]}] | from_entries)
    + ($o | with_entries(select(.key as $f | $k | index([$f]) | not)));
# Only fields that carry information: no constant Channel, no Uid beside User, OriginalParentProcessId only when it
# differs from ParentProcessId. EventType stays beside EventID (readable name for the number).
# GlobalSeqNum (sysmon+extras): EndpointSecurity's number for the event, the global_seq_num slim and raw keep. It puts
# one eslogger run's records in order and tells a repeated record from a new one. It is no loss counter: events the
# filter leaves out use up numbers too, so records skip numbers all the time (the heartbeat's count shows loss).
def sysmon($ev):
  .time as $t | .process as $p | event_kind($ev) as $kind |
  { EventID: $kind[1], EventType: $kind[0], UtcTime: ($t | sysmon_time),
    GlobalSeqNum: (if $cfg.format == "sysmon+extras" then .global_seq_num else null end) } +
  ( if $ev == "exec" then
      .event.exec as $x | $x.target as $tg | parent_info as $pi |
      { ProcessGuid: procguid($tg.audit_token.pid; $p.start_time // $t),
        ProcessId: $tg.audit_token.pid,
        Image: $tg.executable.path,
        CommandLine: (.__esd_cmdline // ($x.args | cmdline)),
        CurrentDirectory: $x.cwd.path,
        User: user_of($tg.audit_token.euid),
        TerminalSessionId: $tg.session_id,
        CDHash: $tg.cdhash,
        ParentProcessId: $tg.ppid,
        ParentImage: $pi.i,
        ParentCommandLine: ($pi.c // null | if . == null then null else cap($cfg.parent_cmdline_max // 0) end),
        ParentProcessGuid: ($pi.g // null) }
      + ( if $cfg.format == "sysmon+extras" then
          # macOS extras (not in Sysmon): code signing and lineage Sysmon has no slot for
          { SigningId: $tg.signing_id, TeamId: $tg.team_id, IsPlatformBinary: $tg.is_platform_binary,
        OriginalParentProcessId: (if $tg.original_ppid != $tg.ppid then $tg.original_ppid else null end),
        ResponsibleProcessId: $tg.responsible_audit_token.pid,
        Tty: $tg.tty.path, Script: $x.script.path } else {} end )
    else
      # every other event: the process that caused it, plus what it acted on
      { ProcessGuid: procguid($p.audit_token.pid; $p.start_time // $t),
        ProcessId: $p.audit_token.pid, Image: $p.executable.path, User: user_of($p.audit_token.euid) }
      + ( if is_file_kind($ev) then
            { TargetFilename: target_file($ev),
              SourceFilename: (if $ev == "rename" then .event.rename.source.path else null end),
              Detail: (if $kind[0] == "FileAttributes" then (detail($ev) | del(.target)) else null end) }
          elif $kind[0] == "ProcessExit" then { ExitStatus: .event.exit.stat }
          elif $kind[0] == "ProcessInject" then
            (.event[$ev].target // {}) as $tp | { TargetImage: $tp.executable.path, TargetProcessId: $tp.audit_token.pid }
          else { Detail: detail($ev) } end )
      + ( if $cfg.format == "sysmon+extras" then { SigningId: $p.signing_id, TeamId: $p.team_id, IsPlatformBinary: $p.is_platform_binary } else {} end )
    end )
  | with_entries(select(.value != null)) | field_order;

# A record the unified log cannot hold whole is cut there at 32759 bytes with "<…>" appended: invalid JSON, so the
# SIEM loses the entire event (Image, User, everything). An attacker gets that by padding argv past 32 KB. Keep every
# record under record_max bytes by cutting the biggest string (or array) in the middle, marked "…[+N chars]…",
# so head and tail survive and the cut itself is searchable.
def cut_mid($keep):
  ($keep / 2 | floor) as $h
  | if type == "string" then .[0:$h] + "…[+" + ((length - $keep) | tostring) + " chars]…" + .[length - $h:]
    else .[0:$h] + ["…[+" + ((length - $keep) | tostring) + " items]…"] + .[length - $h:] end;
def fit($max):
  def size: tojson | utf8bytelength;
  if $max <= 0 or size <= $max then . else
    last(limit(16; recurse(
      if size <= $max then empty else
        . as $r | size as $sz
        | [paths(type == "string" or type == "array")
           | . as $q | ($r | getpath($q)) as $v | {p: $q, n: ($v | tojson | utf8bytelength), s: ($v | type == "string")}] as $c
        | (([$c[] | select(.s and .n > 256)] | max_by(.n)) // ($c | max_by(.n))) as $b
        | if $b == null then empty else
          ($r | getpath($b.p) | length) as $len
        | ((($b.n - ($sz - $max) - 256) / $b.n * $len) | floor | if . < 0 then 0 else . end) as $keep
        | $r | setpath($b.p; getpath($b.p) | cut_mid(if $keep >= $len then $len - 1 else $keep end)) end
      end)))
    # still too big: a marker in its place names the event with the record's own fields, its number among them
    | if size <= $max then . else {esd_record_too_large: (tojson | utf8bytelength), time: .time, UtcTime: .UtcTime,
        EventID: .EventID, GlobalSeqNum: .GlobalSeqNum, global_seq_num: .global_seq_num, Image: .Image}
        | with_entries(select(.value != null)) end
  end;

# $rule_error: null, or why a rule could not be evaluated on this event (see verdict). It goes in before fit, so the
# record still fits.
def emit($ev; $rule_error):
  ( if   $cfg.format == "raw" then del(.__esd_parent, .__esd_chain, .__esd_self, .__esd_pimg, .__esd_cmdline)
    elif ($cfg.format | startswith("sysmon")) then sysmon($ev)
    else slim_rec($ev) end )
  | if $rule_error == null then . else . + {esd_rule_error: $rule_error} end
  # os_log keeps at most 32759 bytes of a message and hard-cuts the rest into invalid JSON the SIEM drops whole, so
  # record_max is clamped to that ceiling even when set to 0 ("no software limit") or above it — the backend limit
  # is real regardless of config, so a record is always kept parseable.
  | fit(($cfg.record_max // 32000) | if . <= 0 or . > 32759 then 32759 else . end);

# [include]/[exclude] rule match. A rule is a list of clauses {field, op, value}; every clause must hold (AND).
# Conditions follow Sysmon semantics and are case-insensitive. A clause on a field the event doesn't carry
# (e.g. ParentCommandLine when the parent's exec was never seen) is false: unknown data never excludes an event,
# and never includes one either.
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
        elif $c.op == "begin with any" then any($xs[]; . as $y | $s | startswith($y))
        elif $c.op == "begin with"     then ($s | startswith($x))
        elif $c.op == "not begin with" then ($s | startswith($x) | not)
        elif $c.op == "end with any"   then any($xs[]; . as $y | $s | endswith($y))
        elif $c.op == "end with"       then ($s | endswith($x))
        elif $c.op == "not end with"   then ($s | endswith($x) | not)
        elif $c.op == "image"          then ($s == $x or ($s | split("/") | last) == $x)
        elif $c.op == "regex"          then ($v | tostring | test($c.value; "i"))
        elif $c.op == "not regex"      then ($v | tostring | test($c.value; "i") | not)
        else false end
    end;
def rule_ok($f): all(.[]; clause_ok($f));

# The fields [include]/[exclude] rules can test: the record's own Sysmon fields, for every event type.
def filter_fields($ev):
  .process as $p
  | if $ev == "exec" then
      .event.exec.target as $t | parent_info as $pi
      | { EventType: "ProcessStart", Image: $t.executable.path, CommandLine: (.__esd_cmdline // (.event.exec.args | cmdline)),
          CurrentDirectory: .event.exec.cwd.path, ParentImage: $pi.i, ParentCommandLine: ($pi.c // null),
          User: user_of($t.audit_token.euid), TeamId: $t.team_id, SigningId: $t.signing_id,
          IsPlatformBinary: $t.is_platform_binary }
    else
      { EventType: event_kind($ev)[0], Image: $p.executable.path, User: user_of($p.audit_token.euid),
        TeamId: $p.team_id, SigningId: $p.signing_id, IsPlatformBinary: $p.is_platform_binary,
        TargetFilename: (if is_file_kind($ev) then target_file($ev) else null end),
        ParentImage: (.__esd_pimg // (if launchd_child(.process) then "/sbin/launchd" else null end)) }   # parent of the acting process
    end;

# Log everything, then filter like Sysmon: an empty [include] includes every event, a non-empty one only events
# matching one of its rules; an event matching any [exclude] rule is never logged (exclude wins).
# A rule can fail on an event: a regex the regex engine gives up on, say, run on a command line the process itself
# chose. A failed rule must never hide the event, so it counts as matching in [include] and as not matching in
# [exclude]; only rules that evaluate cleanly drop an event. Result: false = not logged, true = logged, a string =
# logged with that error in the record (esd_rule_error). An event whose fields cannot be read is logged that way too.
def verdict($ev):
  try (
    filter_fields($ev) as $f
    | def rule($s; $r):   # true, false, or why the rule failed
        try ($r | rule_ok($f)) catch "\(tostring) in [\($s)]: \($r | map("\(.field) \(.op) \(.value)") | join(" AND "))";
    # [include]: the first rule that matches or fails lets the event in
    (if ($cfg.include | length) == 0 then true
     else reduce $cfg.include[] as $r (false; if . == false then rule("include"; $r) else . end) end)
    # [exclude]: the first rule that matches drops the event; a failed one is passed over, its error kept for the record
    | reduce ($cfg.exclude // [])[] as $r (.;
        if . == false then . else rule("exclude"; $r) as $m
          | if $m == true then false elif . == true and $m != false then $m else . end end)
  ) catch tostring;
def decide:
  (.event | keys[0]) as $ev
  | if .__esd_self or (wanted($ev) | not) then empty else
      verdict($ev) as $v
      | if $v == false then empty elif $v == true then emit($ev; null) else emit($ev; $v) end
    end;

# No record could be built for this event (a malformed event, or a bug): the marker written in its place still names
# it, by EventKind (the eslogger event), GlobalSeqNum (eslogger's number for it, in every format), User, Image and
# ProcessId of the process the record is about, each read on its own so one bad field cannot take the others with it.
# In the sysmon formats it carries the Sysmon envelope, as the gap marker does (255 is Sysmon's error event).
def filter_error($x):
  tostring as $err | (try ($x.event | keys[0]) catch null) as $ev
  | def of_proc(f): try (if $ev == "exec" then $x.event.exec.target else $x.process end | f) catch null;
  (if ($cfg.format | startswith("sysmon")) then
     {EventID: 255, EventType: "esd_filter_error", UtcTime: (try ($x.time | sysmon_time) catch null)} else {} end)
  + {esd_filter_error: $err, time: $x.time, EventKind: $ev, GlobalSeqNum: $x.global_seq_num,
     User: of_proc(user_of(.audit_token.euid)), Image: of_proc(.executable.path), ProcessId: of_proc(.audit_token.pid)}
  | with_entries(select(.value != null));

# Main loop (run with jq -n -R): track global_seq_num across ALL raw events, before filtering.
# A jump > 1 means EndpointSecurity dropped events (usually a slow reader filling the pipe). Emit a marker
# so drops are visible in the SIEM instead of silently looking like a quiet host.
# It also keeps pid -> {command line, guid} from EVERY exec it sees (kept or dropped), so a later child can be given
# ParentCommandLine / ParentProcessGuid. ES exec events carry args for the NEW process only; the parent's args come
# from the parent's own earlier exec. Parents started before ESDaemon (or by launchd at boot) stay unknown.
foreach (inputs | fromjson? | select(type == "object" and (.event | type) == "object")) as $e (
  {last: null, pc: {}, pcb: 0};
  ($e.global_seq_num // null) as $g
  | .gap = (if (.last != null and $g != null and ($g - .last) > 1) then ($g - .last - 1) else 0 end)
  | .last = ($g // .last)
  # ESDaemon's own processes (s = self): its binaries under esd_base, the launchd job running filter.sh (ppid 1)
  # with the xpcproxy that starts it, and every process whose *responsible* process is that job. Responsibility,
  # not the parent pid, links them: filter.sh starts jq/awk from subshells that never exec, so the parent chain
  # breaks there. A user cannot become part of it: that takes root (launchd job, files under esd_base).
  # An admin running reload.sh by hand is not the job, so it is logged like any other admin action.
  # filter.sh also passes its own pid (self_pid): the job's processes are recognised by that alone, even when the
  # job's start was never seen (it starts while eslogger restarts). The pid cannot be reused while this filter runs.
  | .pc as $pc
  | def self_via($tok): ($tok.pid | tostring) as $r | $pc[$r] as $rp
      | ($cfg.self_pid != null and $tok.pid == $cfg.self_pid)
        or ($rp.s == true and ($tok.pidversion == null or $rp.v == null or $rp.v == $tok.pidversion));
    # The state update must never throw: a throw here aborts jq and loses every event queued behind this one (the
    # `try decide` below only guards record building, not this). On any error, keep the prior pid cache and pass the
    # raw event through so decide still tries to log it.
    . as $prev
    | try (
    if $e.event.exec then
      ($e.event.exec.target) as $tg
      | (($tg.ppid // "none") | tostring) as $pp
      | ($tg.audit_token.pid | tostring) as $me
      | ($me + "@" + (($e.process.start_time // $e.time) | tostring)) as $key
      | procguid($tg.audit_token.pid; $e.process.start_time // $e.time) as $guid
      | ($tg.executable.path // "") as $img | (($e.event.exec.args[1] // "") | tostring) as $a1
      | ( ($img | startswith(esd_base))
          or ($tg.ppid == 1 and ($tg.audit_token.euid == 0) and (($img == "/bin/bash" and $a1 == esd_base + "filter.sh")
                                 or ($img == "/usr/libexec/xpcproxy" and ($a1 | IN("com.esdaemon.filter", "com.esdaemon.eslogger")))))
          or ($cfg.self_pid != null and $tg.audit_token.pid == $cfg.self_pid)
          or (($tg.responsible_audit_token.pid | tostring) != $me and self_via($tg.responsible_audit_token)) ) as $self
      # a pid is reused once its process exits; the cached entry is this child's parent only if the pidversion
      # the child's parent_audit_token carries matches (older eslogger without pidversion: trust the pid)
      | .pc[$pp] as $par | $tg.parent_audit_token.pidversion as $pv
      | .e = ($e + {__esd_parent: (if $par != null and ($pv == null or $par.v == null or $par.v == $pv) then $par else null end),
                    __esd_chain: (.pc[$me].k == $key),   # this pid already exec'd once: .process is its old image
                    __esd_self: $self})
      | ($e.event.exec.args | cmdline) as $c
      # bound memory by entries AND bytes: argv can be ~1 MB, so 50000 entries alone could hold tens of GB.
      # A reset only loses parent context (ESDaemon's own entries are kept, or its job would start being logged).
      | (if (.pc | length) >= 50000 or .pcb > 67108864 then .pc |= with_entries(select(.value.s)) | .pcb = 0 else . end)
      | .pcb += ($c | length)
      | .e += {__esd_cmdline: $c}   # computed once here; sysmon and filter_fields reuse it instead of re-rendering
      # p = this process's parent image (as ParentImage is worked out for its ProcessStart), so its later file and
      # other events can be matched on ParentImage too: "exclude a tool and everything it launches" then covers the
      # files those children write, not only their launches.
      | (.e | parent_info | .i) as $pimg
      | .pc[$me] = { c: $c, k: $key, g: $guid, v: $tg.audit_token.pidversion, i: $img, p: $pimg, s: $self }
    else
      ($e.process.audit_token // {}) as $at | .pc[($at.pid // "none") | tostring] as $me
      | .e = ($e + {__esd_self: ((($e.process.executable.path // "") | startswith(esd_base)) or self_via($e.process.responsible_audit_token // {})),
                    __esd_pimg: (if $me != null and ($at.pidversion == null or $me.v == null or $me.v == $at.pidversion) then $me.p else null end)})
    end
    ) catch ( $prev | .e = ($e + {__esd_self: false, __esd_parent: null, __esd_chain: false}) );
  (if .gap > 0 then {eslogger_scoped_gap: .gap, time: .e.time, after_global_seq_num: (.last - .gap - 1)}
     | if ($cfg.format | startswith("sysmon")) then
         {EventID: 255, EventType: "eslogger_scoped_gap", UtcTime: (.time | sysmon_time)} + . else . end
   else empty end),
  # a filter bug on one odd event must not kill the pipeline (and every event queued behind it): report it instead.
  # Nor may the report: should the marker itself fail, the bare error is written.
  (.e | . as $x | try decide catch (tostring as $err | try filter_error($x) catch {esd_filter_error: $err, time: $x.time}))
)
