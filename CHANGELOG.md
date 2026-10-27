# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **`esdaemon` control command** (installed on `PATH` at `/usr/local/bin/esdaemon`): `status`, `reload`, `update`, `logs`, `config`, `version`, and `uninstall [--purge]`. Uninstall is now part of the install itself — `sudo esdaemon uninstall` stops and removes both daemons, the install tree and the command itself, so nothing is left on disk and no separate script needs to be kept. `./uninstall.sh` still works and forwards to the installed command when present.

### Fixed
- **A fresh clone's quick start works again.** Every script is committed executable, so `sudo ./quick-install.sh` and `sudo ./uninstall.sh` run from a clone instead of failing with "command not found". `make lint` passes on a copy that lost its execute bits (ZIP download, Windows) and fails if a script is ever committed without the bit again.
- **A clone made on Windows installs on a Mac.** Text files check out with LF line endings on every platform, also under Git for Windows' default `core.autocrlf=true`, so the scripts in a Windows clone, or a ZIP of one, no longer fail on a Mac at `#!/bin/bash\r`. A Windows clone made before this change keeps its CRLF files until it is cloned again. `make lint` fails if a file is ever committed with CRLF line endings.
- **Pipeline no longer aborts on a single odd event.** The per-event state update (not just record building) now runs under a guard, and `procguid` no longer throws on a regex-valid-but-impossible timestamp. Before, one malformed event could kill the filter and lose every event queued behind it. (Found by review; corroborated independently.)
- **argv compute-DoS fixed and the filter made faster.** `CommandLine` is rendered once per exec and reused (was 3×), and `args_max` (default 4096) caps how many argv elements are rendered. A 200k-argument process that stalled the filter ~11 s (dropping real events) now processes in ~0.16 s.
- **`eslogger_scoped_gap` points to the right place.** `after_global_seq_num` now reports the sequence the drops followed, not the post-gap sequence.
- **`reload.sh` restart is race-safe.** It waits for each launchd label to be gone before bootstrapping and retries, so a transient launchd error can't leave the filter (or both daemons) stopped with the FIFO undrained.
- **`record_max` clamped to the 32759-byte unified-log ceiling** even at `0`, so an oversize record is always cut to valid JSON instead of being hard-truncated and dropped whole.
- **`ParentImage` is `unknown` for a reparented process whose prior exec wasn't seen**, instead of mislabelling the process's own earlier image as its parent; `launchd_child` no longer treats a `ppid==1` process with no `original_ppid` as launchd-spawned.
- **Self-exclusion hardened**: the `ppid==1` launchd-job heuristic now also requires `euid==0`, so an unprivileged user LaunchAgent can't match it.

## [0.1.0] — first public release

### Added
- `eslogger` → filter → unified log pipeline as two LaunchDaemons (`com.esdaemon.eslogger`, `com.esdaemon.filter`) connected by a FIFO; records go to subsystem `com.apple.eslogger`, category `events`, process `ESDaemon`.
- `[modules]`: choose what to log as `<object> = <operation>`: `process` (`start`, `exit`, `inject`), `file` (`read`, `write`, `create`, `delete`, `rename`, `attributes`), `user` (`login`, `logout`, `sudo`, `account`), `system` (`persistence`, `malware`, `kernel`, `mount`). `file = read` logs read-only opens; `file = write` logs a changed file once, when it is closed.
- `[include]` / `[exclude]` with Sysmon's filter semantics and vocabulary (`is`, `contains`, `begin with`, `image`, `regex` … and their negations); exclude always wins. Fields: `EventType`, `Image`, `CommandLine`, `CurrentDirectory`, `ParentImage`, `ParentCommandLine`, `User`, `TeamId`, `SigningId`, `IsPlatformBinary`, `TargetFilename`. On file and other events `ParentImage` is the parent of the acting process, so "a tool and everything it launches" covers the files they write.
- Sysmon-style records with a fixed field order: `EventID`, `EventType`, `UtcTime`, `User`, `Image`, `CommandLine`, …, `ProcessGuid` / `ParentProcessGuid` (GUID-shaped, linkable), code signing last. Output formats `sysmon`, `sysmon+extras` (default), `slim`, `raw`.
- Default config: `process = start`, `file = create, delete`, `user = login`, and excludes for collector self-noise and Apple housekeeping: Apple `xpcproxy`, Spotlight, temp copies of Apple daemons, and macOS's own launchd-started daemons (their starts and their private files); see [docs/DEFAULT-CONFIG.md](docs/DEFAULT-CONFIG.md).
- `ParentImage` is `/sbin/launchd` for anything launchd started (parent pid 1 from the start, also without having seen the parent); conditions `begin with any` / `end with any`.
- ESDaemon never logs its own processes (its binaries and the processes its launchd job starts); admin runs of `reload.sh` / `install.sh` are logged.
- Config validation before anything runs (`cfg.sh`): unknown sections, settings, modules, rule fields or conditions, bad regexes and empty values are errors; `reload.sh` and `install.sh` change nothing on an invalid config.
- Records kept under the unified log's 32 KB limit (`record_max`): the largest value is cut in the middle, marked `…[+N chars]…`; `ParentCommandLine` capped by `parent_cmdline_max`.
- Drop and restart markers (`eslogger_scoped_gap`, `eslogger_scoped_restart`) so lost events are visible.
- `quick-install.sh` (fetch, verified prebuilt binary or build, install, check), standalone `uninstall.sh` (`--purge`), `update.sh` (compare with the latest GitHub release; `--install` to update), `install.sh` that keeps a tuned config and migrates older ones (`migrate-cfg.sh`).
- `measure.sh` (volume per source), `try.sh` (dry-run a config on a capture), MDM PPPC profile for eslogger's Full Disk Access, CI on Linux and macOS, release workflow with a universal binary.
