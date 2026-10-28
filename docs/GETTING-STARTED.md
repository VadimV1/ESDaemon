# Getting started

From a clean Mac to ESDaemon events in your SIEM. About 10 minutes for one Mac.

## 1. Requirements

| Need | Why |
|---|---|
| macOS 15 or later (Apple silicon or Intel) | ESDaemon's filter uses `/usr/bin/jq`, which ships with macOS 15 |
| Admin rights (`sudo`) | it installs two LaunchDaemons |
| Only root can write to `/usr/local` and the directories above it (the macOS default) | the daemons run as root from `/usr/local/ESDaemon`; the installer checks this and stops if another user could change the install tree or a directory above it |
| Xcode Command Line Tools (`xcode-select --install`) | only to build the small `ESDaemon` binary; not needed with a prebuilt release binary |
| A log collector that reads the macOS unified log | to ship events off the Mac (step 5) |

**Homebrew on an Intel Mac.** `/usr/local/bin` belongs to the Homebrew user there, so anything running as that user can replace a command in it, without sudo. Leave it as it is: the installer puts no `esdaemon` command there, says so, and you run the copy in the install tree instead, `sudo /usr/local/ESDaemon/bin/esdaemon status` and so on. If `/usr/local` itself belongs to your user (older Homebrew installs did that), the installer stops: give it back to root with `sudo chown root:wheel /usr/local && sudo chmod 755 /usr/local`. Current Homebrew needs only the subdirectories it owns.

## 2. Install

From a checkout:

```bash
git clone https://github.com/<owner>/ESDaemon.git && cd ESDaemon
sudo ./quick-install.sh
```

Without a checkout:

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/ESDaemon/main/quick-install.sh | sudo bash
```

`quick-install.sh` checks the macOS version, gets the source, uses the prebuilt release binary or builds one, runs `install.sh`, and then checks that events arrive. `install.sh` validates the config before it changes anything, never overwrites a config you have edited, and migrates a config from an older version (keeping the old file next to it).

What lands on the Mac:

| Path | What |
|---|---|
| `/usr/local/ESDaemon/` | the filter, helper scripts, `ESDaemon` binary and `bin/esdaemon` command |
| `/usr/local/ESDaemon/configs/ESDaemon.cfg` | **the config you edit** |
| `/usr/local/bin/esdaemon` | the `esdaemon` command on `PATH`, when only root can write to `/usr/local/bin` |
| `/Library/LaunchDaemons/com.esdaemon.eslogger.plist` | runs `/usr/bin/eslogger` for the event types `[modules]` needs |
| `/Library/LaunchDaemons/com.esdaemon.filter.plist` | runs the filter, which writes records to the unified log |
| `/var/log/ESDaemon/` | the two daemons' error output |

## 3. Give eslogger Full Disk Access

macOS only lets `eslogger` receive Endpoint Security events with Full Disk Access. ESDaemon's own filter needs no special permission.

- **One Mac:** System Settings → Privacy & Security → Full Disk Access → **+** → press Cmd-Shift-G, type `/usr/bin/eslogger`, add it and switch it on.
- **A fleet:** deploy [`mdm/esdaemon-eslogger-fda.mobileconfig`](../mdm/esdaemon-eslogger-fda.mobileconfig) with your MDM (Jamf, Intune, Kandji, Mosyle …). PPPC profiles only work when an MDM delivers them; replace the two `PayloadUUID` values with your own first (`uuidgen`).

No restart is needed: the eslogger daemon retries every 10 seconds and starts producing events once access is granted.

## 4. Check that events arrive

```bash
log stream --info --predicate 'subsystem == "com.apple.eslogger" AND process == "ESDaemon"'
```

In another terminal run `curl -s https://example.com -o /dev/null`. A record like this should appear:

```json
{"EventID":1,"EventType":"ProcessStart","UtcTime":"…","GlobalSeqNum":52807,"User":"alice",
 "Image":"/usr/bin/curl","CommandLine":"curl -s https://example.com -o /dev/null","ParentImage":"/bin/zsh", …}
```

Nothing shows up? See [Troubleshooting](#troubleshooting).

## 5. Ship the events to your SIEM

ESDaemon writes one record per event to the unified log under subsystem `com.apple.eslogger`, category `events`, process `ESDaemon`. Any collector that reads the unified log can ship it. With the **Bindplane agent / OpenTelemetry Collector** `macos_unified_logging` receiver:

| Setting | Value |
|---|---|
| Source | macOS Unified Logging |
| Predicate | `subsystem == "com.apple.eslogger" AND process == "ESDaemon"` |
| Log format | `ndjson` |
| Version | Bindplane agent v1.110.2 or later (OpenTelemetry Collector contrib v0.162.0 or later) |
| Max log age | 5 minutes (`max_log_age: 5m`) where your tool allows it; Bindplane's form takes whole hours, so 1 hour there. **Never 0** |

Why these values:

- The **predicate** collects only ESDaemon's records, not the whole unified log.
- **`ndjson`** gives one line per record. The receiver's `json` format prints a record over several lines and re-sends records on every poll.
- **Max log age 0 does not mean "from now":** the receiver then starts with no time limit and re-sends everything macOS still keeps (87,437 records, 176 MB on a test Mac). A Mac takes ~3 minutes from boot to the agent's first poll, so 5 minutes covers boot and login.
- **Max log age** is how far back the receiver reads when it starts: after every reboot or agent restart it re-sends that much history. At the default 24 hours one restart on a test Mac re-sent 76,302 records (158 MB) in two minutes. Keep it short.
- **Older receiver versions** re-read their whole look-back window (24 hours by default) on every poll, which multiplies every record many times over. Fixed upstream in contrib v0.162.0.

In the collector the body is the full `log show` line; ESDaemon's record is its `eventMessage` field, a JSON string. Parse `eventMessage` as JSON (a JSON parse processor in Bindplane, or your SIEM's parser) to get `EventID`, `Image`, `CommandLine` and the rest as fields.

### Alert when a Mac goes silent

A Mac whose pipeline has stopped sends nothing, just like a quiet Mac. So ESDaemon also logs a heartbeat every 5 minutes, `{"eslogger_scoped_heartbeat":300,"time":"…","records":42}`, with the number of records written since the previous one (`heartbeat` in `[settings]`, `0` = off). Set up two alerts per Mac:

- **No heartbeat for more than two intervals** (alert at 11 minutes): the pipeline is down. The filter is stopped or keeps restarting, or the writer, the unified log or the collector is stuck. A Mac that is asleep or shut down sends none either.
- **Heartbeats, but no `ProcessStart` for two intervals:** eslogger is down or lost Full Disk Access.

The record's fields, its Sysmon form and what to check for each alert: [CONFIG.md](CONFIG.md#heartbeat).

## 6. Tune what is logged

Read [DEFAULT-CONFIG.md](DEFAULT-CONFIG.md) for what the default logs and drops, and [CONFIG.md](CONFIG.md) for every option. The loop:

```bash
sudo /usr/local/ESDaemon/measure.sh 600                  # 10-minute capture: GB/hour and the noisiest sources
sudo nano "$(esdaemon config)"                           # add [exclude] rules or change [modules]
/usr/local/ESDaemon/try.sh /path/to/raw.ndjson           # optional: dry-run the edited config on that capture
sudo esdaemon reload                                     # apply; refuses an invalid config and changes nothing
```

Measure a Mac during a normal working day before rolling out: browsers, Office and vendor agents add sources an idle Mac never shows. Exclude a vendor's own binaries by `TeamId` rather than by name.

## 7. Upgrade

```bash
esdaemon update                 # installed vs latest release (exit 0 = up to date, 10 = update available)
sudo esdaemon update --install  # download and install the latest release
esdaemon version                # the installed version
```

`esdaemon update` asks GitHub for the latest release of the repository the Mac was installed from. Installing an update keeps your config; a config from an older version is migrated, with the old file saved next to it. Re-running `quick-install.sh` (or `git pull && sudo ./install.sh`) does the same. For a fleet, run the check from your MDM and act on exit code 10.

## 8. Uninstall

```bash
sudo esdaemon uninstall            # keeps a copy of your config in /var/log/ESDaemon
sudo esdaemon uninstall --purge    # removes that too
```

The `esdaemon` command removes everything it installed, itself included — nothing is left on disk and there is no separate script to download or keep. (A checkout can still use `sudo ./uninstall.sh`, or `curl -fsSL https://raw.githubusercontent.com/<owner>/ESDaemon/main/uninstall.sh | sudo bash`. Both remove the same things without running the installed command or anything else from `/usr/local/ESDaemon`: use them when `esdaemon status` says UNSAFE.) Revoke eslogger's Full Disk Access in System Settings, or remove the MDM profile.

## Troubleshooting

| Symptom | Check |
|---|---|
| No records at all | `cat /var/log/ESDaemon/eslogger.stderr`: a "not permitted" error means Full Disk Access is missing (step 3) |
| Daemons not running | `sudo launchctl print system/com.esdaemon.eslogger \| grep -E 'state\|last exit'`, same for `com.esdaemon.filter`; then `cat /var/log/ESDaemon/filter.stderr` |
| `reload.sh` refuses the config | it prints the line and the reason; nothing was changed. Fix the line and run it again |
| `install.sh` or `reload.sh` stops: "… is owned by uid …", "… is group-writable", "… is a symbolic link" | another user could change the install tree or a directory above it. Run the `fix:` command printed for each path, then run it again. If another user could write there before, remove ESDaemon with `uninstall.sh` and install it again |
| `esdaemon status` says `UNSAFE` (exit 1) | the same, found after the install: fix each path it lists. For `command … UNSAFE`, delete `/usr/local/bin/esdaemon` and use `sudo /usr/local/ESDaemon/bin/esdaemon` |
| `esdaemon: command not found` | an Intel Mac with Homebrew: use `sudo /usr/local/ESDaemon/bin/esdaemon` (step 1) |
| Records cut off or not valid JSON | a custom `subsystem` / `category`: `reload.sh` turns on large messages for it; keep `record_max` at or below 32000 |
| Same record many times in the SIEM | the collector, not ESDaemon: use `ndjson` and a receiver version from step 5. The copies have the same `GlobalSeqNum` and `UtcTime` |
| A burst of old records after a reboot | the collector replaying `max_log_age` of history on startup: set it to 1 hour (step 5) |
| `eslogger_scoped_gap` records | Endpoint Security dropped events because the reader fell behind (very high load); the record says how many, and `after_global_seq_num` is the `GlobalSeqNum` of the last event before them |
| `eslogger_scoped_restart` records | eslogger restarted (reload, crash, boot); events during the restart are not seen, and `GlobalSeqNum` starts over |
| `GlobalSeqNum` skips numbers from one record to the next | normal: events the filter leaves out (`[exclude]` rules, ESDaemon's own processes) use up numbers too. Loss shows elsewhere: as `eslogger_scoped_gap` records, or as fewer records arriving between two heartbeats than the second one's `records` ([CONFIG.md](CONFIG.md#event-numbers)) |
| No `eslogger_scoped_heartbeat` records | the filter or the collector is down, or `heartbeat = 0`: check that both daemons run (above), then the collector; see [CONFIG.md](CONFIG.md#heartbeat) |
