<p align="center">
  <img src="docs/assets/ESDaemon.png" alt="ESDaemon" width="560">
</p>

<h1 align="center">ESDaemon</h1>

<p align="center"><b>macOS endpoint telemetry for your SIEM, built on Apple's own <code>eslogger</code>.</b></p>

ESDaemon turns Endpoint Security events (process starts and logins today; file events and more are on the roadmap) into compact Sysmon-style JSON in the macOS unified log, filtered by a config you control. Any log collector that reads the unified log, such as the Bindplane / OpenTelemetry macOS receiver, ships them to your SIEM.

No kernel extension, no Apple entitlement, no agent to license: it runs `/usr/bin/eslogger`, which ships with macOS.

```
/usr/bin/eslogger ──► ESDaemon filter ([modules], [include] / [exclude]) ──► unified log ──► collector ──► SIEM
   (Apple, FDA)          (jq, Sysmon-style JSON)                          com.apple.eslogger
```

## What it enables

- **Mac visibility in the SIEM you already have.** Who logged in (with source IP for SSH) and what ran (full command line, parent, user, code signature), in Sysmon field names (`EventID`, `Image`, `CommandLine`, `ParentImage`, `User` …) that existing Windows/Sysmon detections and analysts already know. (File events use `TargetFilename` and the same scheme, once that feed ships.)
- **Proof it catches attacks.** A bundled adversary-emulation harness (`redteam/`) runs benign, self-cleaning stand-ins for real macOS techniques (LOOBins, MITRE ATT&CK) and reports which ones ESDaemon logged.
- **Investigations on macOS.** Process trees (`ProcessGuid` / `ParentProcessGuid`), persistence (LaunchAgents and login items), quarantine removal, account changes, SSH logins and failures, all searchable.
- **Control over volume.** Raw `eslogger` output is several GB per Mac per day. ESDaemon logs only the event types you choose and drops what you exclude, with Sysmon's include/exclude rules. The default config drops Apple's own housekeeping: an idle Mac goes from about 95 records per 10 minutes to about 13.
- **Fleet-friendly.** One config file, validated before anything runs, an MDM profile for the one permission it needs, and a filter that never logs itself.

## Quick start

On a Mac with macOS 15 or later (`/usr/bin/jq` ships with it):

```bash
git clone https://github.com/<owner>/ESDaemon.git && cd ESDaemon
sudo ./quick-install.sh
```

or without cloning:

```bash
curl -fsSL https://raw.githubusercontent.com/VadimV1/ESDaemon/main/quick-install.sh | sudo bash
```

Then give `/usr/bin/eslogger` **Full Disk Access** (System Settings → Privacy & Security → Full Disk Access, or the MDM profile in [`mdm/`](mdm/)), and watch events arrive:

```bash
log stream --info --predicate 'subsystem == "com.apple.eslogger" AND process == "ESDaemon"'
```

Once installed, everything is done through the `esdaemon` command (no scripts to keep around):

```bash
esdaemon status              # running? which version? where is the config?
sudo esdaemon reload         # apply config edits
esdaemon update --install    # check for / install the latest release
sudo esdaemon uninstall      # remove ESDaemon completely, the command itself included
```

`sudo esdaemon uninstall --purge` also deletes the saved config and logs. The standalone `./uninstall.sh` (or `curl -fsSL https://raw.githubusercontent.com/<owner>/ESDaemon/main/uninstall.sh | sudo bash`) still works for a checkout or a broken install.

**Full walkthrough, including collector setup: [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).**

## What a record looks like

```json
{"EventID":1,"EventType":"ProcessStart","UtcTime":"2026-10-25 11:42:06.838","User":"alice",
 "Image":"/usr/bin/curl","CommandLine":"curl -s -o /tmp/x https://example.com/a.sh",
 "CurrentDirectory":"/Users/alice","ProcessId":37700,"ProcessGuid":"{6ADDEB0E-000C-C7E9-0000-000000009344}",
 "ParentImage":"/bin/zsh","ParentCommandLine":"-zsh","ParentProcessId":37389,
 "ResponsibleProcessId":37385,"TerminalSessionId":37389,
 "SigningId":"com.apple.curl","IsPlatformBinary":true,"CDHash":"1AC507E8…"}
```

## The config in one minute

Everything lives in `/usr/local/ESDaemon/configs/ESDaemon.cfg`. Edit, then `sudo /usr/local/ESDaemon/reload.sh`.

```ini
[modules]                 # what to log (supported feeds: process + user — see note below)
process = start
user = login

[include]                 # empty = everything the modules log

[exclude]                 # Sysmon-style rules; exclude always wins
Image is /usr/local/bin/jamf AND CommandLine is "/usr/local/bin/jamf policy -event recurring"
TeamId is any UBF8T346G9;EQHXZ8M8AV
```

| Object | Operations |
|---|---|
| `process` | `start`, `exit`, `inject` |
| `file` | `read`, `write`, `create`, `delete`, `rename`, `attributes` |
| `user` | `login`, `logout`, `sudo`, `account` |
| `system` | `persistence`, `malware`, `kernel`, `mount` |

> **Supported feeds for now:** ESDaemon ships and validates the **process** (`exec`) and **user** (`login`) feeds — the default config enables exactly those. The `file` and `system` modules are recognised by the config DSL but their feeds are **not developed yet**; treat them as experimental and unsupported for now.

- **What the default config logs and drops, and why: [docs/DEFAULT-CONFIG.md](docs/DEFAULT-CONFIG.md)**
- **Every setting, rule field and condition: [docs/CONFIG.md](docs/CONFIG.md)**

## Repository layout

| Path | What |
|---|---|
| `quick-install.sh` | one-step install: fetch, build, install, check |
| `install.sh` | install from a checkout (also installs the `esdaemon` command on PATH) |
| `bin/esdaemon` | the control command (`status`, `reload`, `update`, `logs`, `uninstall`); installed to `/usr/local/bin` |
| `uninstall.sh` | standalone removal for a checkout / broken install (an install uses `esdaemon uninstall`) |
| `VERSION`, `REPO` | the release version and the GitHub repository `update.sh` checks |
| `configs/ESDaemon.cfg` | the default config |
| `src/scope.jq` | the filter: modules, include/exclude rules, Sysmon-style records |
| `src/ESDaemon.swift` | writes each record to the unified log (`os_log`, `%{public}@`) |
| `bin/` | `cfg.sh` (parse + validate), `filter.sh`, `reload.sh`, `measure.sh` (volume per source), `try.sh` (dry-run a config), `update.sh` (check / install the latest release), `migrate-cfg.sh` |
| `mdm/` | PPPC profile granting `eslogger` Full Disk Access |
| `test/` | `make test`: filter, config and format tests (macOS or Linux, needs `jq`) |
| `redteam/` | adversary-emulation harness: benign, self-cleaning macOS attack techniques that confirm ESDaemon logs them ([redteam/README.md](redteam/README.md)) |
| `docs/` | getting started, default config, config reference, testing on a Mac |

## Requirements and limits

- macOS 15 or later (for `/usr/bin/jq`), Apple silicon or Intel. Building needs Xcode Command Line Tools, unless you use a prebuilt release binary.
- `eslogger` needs Full Disk Access; ESDaemon's own filter does not.
- Network connections are not an `eslogger` event; use DNS or proxy telemetry for those.
- The filter sees every event locally (a little CPU); what it saves is the bytes shipped and stored.

## Contributing, security, license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Released under the [MIT License](LICENSE).
