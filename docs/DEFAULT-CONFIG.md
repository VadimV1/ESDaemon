# What the default config logs and drops

The shipped config ([`configs/ESDaemon.cfg`](../configs/ESDaemon.cfg)) logs **who logged in, what ran, and which files were created or deleted**, and drops only collector self-noise and Apple's own housekeeping. On an idle macOS 26 Mac that is about 13 records per 10 minutes instead of about 95, with nothing an investigation uses removed.

## What it logs

```ini
[modules]
process = start
file = create, delete
user = login
```

| Module | Record (`EventType`, `EventID`) | What you get |
|---|---|---|
| `process = start` | `ProcessStart` (1) | every program launched: `Image`, `CommandLine`, `CurrentDirectory`, `User`, `ParentImage`, `ParentCommandLine`, `ProcessGuid` / `ParentProcessGuid`, code signing (`SigningId`, `TeamId`, `IsPlatformBinary`, `CDHash`) |
| `file = create` | `FileCreate` (11) | every new file: `TargetFilename`, and the process that created it |
| `file = delete` | `FileDelete` (23) | every deleted file: `TargetFilename`, and the process that deleted it |
| `user = login` | `UserLogin` (111) | console, SSH, screen sharing and screen-unlock logins, plus authentication attempts; `Detail` carries `username`, `success`, and for SSH the `source_address` |

Not on by default: file reads and writes (very frequent), process exit and injection, account changes, persistence, XProtect, kernel extensions and mounts. Add them under `[modules]` ([CONFIG.md](CONFIG.md#what-to-log-modules)).

## What it drops, and why that is safe

Every rule names an exact binary; the file rules also name that binary's own folder. Anything else writing to the same places, or a copy of the binary somewhere else, is still logged.

| Rule | Drops | Why visibility stays |
|---|---|---|
| `Image begin with /opt/observiq-otel-collector/`, `ParentImage begin with /opt/observiq-otel-collector/` | the Bindplane agent, the `log show` it runs every poll, and the temp files those write | collector self-noise. Without it the agent's temp files are logged, which makes it poll again at once: a loop of about one poll a second |
| `Image is /usr/bin/eslogger` | `eslogger` launches (`eslogger --list-events` during a reload) | ESDaemon tooling. Full path only; a copy elsewhere stays logged. It also hides someone running `/usr/bin/eslogger` by hand |
| `xpcproxy` with an Apple service name (`com.apple.*`, `application.com.apple.*`) | launchd's start-up step for Apple services, about half of an idle Mac's process starts | the program it starts is logged as its own record under the same process ID, with path, user and signature; only the launchd job name is lost. Third-party services' `xpcproxy` stays logged |
| Spotlight's `mdworker_shared` (path **and** `SigningId`) | Apple's indexer workers | started by launchd with fixed arguments over and over; not user activity |
| `contactsd` process starts | the contacts daemon starting under each Apple service account | Apple housekeeping |
| **macOS's own daemons** (3 rules): Apple-signed, in `/System/Library`, `/usr/libexec`, `/usr/sbin` or the system cryptex, **and started by launchd** (parent pid 1 from the start) | their process starts (except `xpcproxy`), and their files in temp folders, caches, Spotlight, Apple's asset store, a list of daemon databases in `/private/var/db`, and a user's private Library areas (Metadata, Caches, Biome, Containers, Photos, CoreFollowUp) | these are macOS running itself: after a reboot and login, dozens of Apple daemons write their own state (~3,800 records in 12 minutes on a test Mac before these rules). The folders are protected by macOS, so the binaries are Apple's. The same tools started by a shell, app or script have another parent and stay logged; files written to persistence locations, `/Applications`, configuration profiles, Gatekeeper/XProtect, kext staging, preferences and background downloads (`nsurlsessiond`) stay logged whoever writes them |
| Temp copies in `TemporaryItems` by `mobileassetd`, `cfprefsd`, `duetexpertd`, `dasd`, `chronod`, `identityservicesd`, `locationd` (Apple-signed only) | macOS saving a file the safe way: write a temp copy, then swap it into place. `mobileassetd` alone writes ~670 of these in a minute when it refreshes assets, several times a day | internal state of Apple daemons; nobody chooses its content. Preference tampering such as `defaults write … LoginHook` still shows up as the `defaults` process starting |
| Apple framework helpers started by an Apple framework daemon | disk checks at boot (`apfs.util`, `fsck_apfs` … from `diskarbitrationd`), smart-card and login helpers | Apple housekeeping; a shell or script an Apple daemon starts (package install scripts) is in `/bin` or `/usr/bin` and stays logged |
| Apple app extensions and widgets (`.appex`), iOS-support and XProtect/MRT runs started by launchd | widget and extension launches at login | the apps you open (Terminal, Safari …) stay logged |
| launchd daemons writing a user's `~/Library`, except LaunchAgents, Preferences, Keychains, TCC, background tasks, Services, ScriptingAdditions, Input Methods, Application Scripts | AddressBook, CrashReporter, IdentityServices, AirDrop, Shortcuts, ContainerManager … | where persistence and secrets live stays logged, whoever writes it |
| launchd daemons' safe-save temp copies (`name.sb-xxxxxxxx-XXXXXX`) | e.g. temp copies of keychain databases while saving | the real file is logged; the same name written by anything else stays logged |
| `cfprefsd` preference saves, except loginwindow, loginitems, LaunchServices, firewall, security, SystemPolicy, Dock, Terminal, background tasks | Messages, Sharing, apsd … preferences | the persistence- and security-relevant domains stay logged |
| Apple's software-update helpers on the update volume, and launchd daemons' runtime, log and extra database files (`/private/var/run`, `/System/Volumes/Update`, ASL, analyticsd, modelcatalog …) | update staging and runtime markers | protected Apple volumes and daemon state |
| Pinned boot rewrites: kext staging (`kernelmanager_helper`, `kernelmanagerd`), XProtect (`syspolicyd`), keybag `.writing`, MDM `.createStore.lock`, `systemstats`, launchd's sockets | the same files rewritten at every boot | any other process writing these stores stays logged |
| `duetexpertd` in `~/Library/Caches/com.apple.duetexpertd/` | Siri suggestions rebuilding its model cache | an Apple daemon's cache |
| `mds`, `mds_stores` in `/.Spotlight-V100/` | Spotlight's index store | the search index writing itself |
| `BiomeAgent` in `~/Library/Biome/tmp/` | Apple's on-device activity store, temp files | internal state |

ESDaemon also never logs itself (built in, not a rule): its binary and the processes its own job starts. Someone running `sudo reload.sh` or `install.sh` by hand is logged, as an admin action should be.

## Checked on purpose: still logged

The test suite (`make test`) checks that the default config **keeps**:

- `curl` (or any other program) writing into a `TemporaryItems` folder
- `cfprefsd` or `mobileassetd` writing a LaunchAgent
- a copy of `cfprefsd` or `mdworker_shared` placed elsewhere, or not signed by Apple
- a third-party service's `xpcproxy`
- a user running `log show` (only the agent's is dropped)
- an Apple tool started from a shell (not launchd), including one writing to `$TMPDIR`
- launchd daemons writing a LaunchDaemon, `/Applications`, a configuration profile or the Gatekeeper/XProtect databases
- a process re-parented to launchd after a double fork, and a third-party launchd service

## Measured impact

Idle lab Mac, macOS 26.7, default modules:

| | Records per 10 minutes |
|---|---|
| without the Apple housekeeping excludes | ~95 (plus ~670 per `mobileassetd` burst, several a day) |
| with the default config | ~13 |
| first 12 minutes after a reboot, before the launchd-daemon rules / with them | 3,774 (with a desktop login) / 311 (without one) |

What remains on an idle Mac: Apple's metrics and Siri upload extensions starting, crash-reporter files, widget timelines, `gssd`. On a Mac in use add the user's own activity, browsers, Office and vendor agents. Measure one before rolling out (`sudo /usr/local/ESDaemon/measure.sh 600`) and exclude vendors by `TeamId`.

## Changing the defaults

Edit `/usr/local/ESDaemon/configs/ESDaemon.cfg` and run `sudo /usr/local/ESDaemon/reload.sh`. Delete a default rule to log that source again; add your own under the examples at the end of `[exclude]`. Rule syntax: [CONFIG.md](CONFIG.md#rules).
