# Changelog

## [Unreleased]
### Added
- ESDaemon: eslogger → cfg-driven filter → unified log (`com.apple.eslogger` / `events`) for Bindplane.
- `configs/ESDaemon.cfg`: events, subsystem, format, `[always]`, `[conditional]`, `[noisy_team_ids]`, `[noisy_path_prefixes]`.
- Output formats: `sysmon`, `sysmon+extras` (default), `slim`, `raw`. ParentCommandLine / ParentProcessGuid from a pid cache.
- ES drop markers (`eslogger_scoped_gap`) on `global_seq_num` jumps.
- Tests: 63 synthetic keep/drop and format cases. CI on Linux + macOS.
- `third_party = all | drop_noisy` (default all: every non-Apple-platform exec kept).
- `[download]` section: Apple binaries that fetch/move data (curl, nscurl, rsync, scp, git, mount_smbfs/webdav, hdiutil, installer, pip/gem/npm …), always kept.
- In-language download tokens (urlopen, urlretrieve, requests.get, open-uri, NSURLSession …) in the risky-argv rule.
- `[drop]` section in Sysmon filter vocabulary: `Image is … AND CommandLine begin with …`; fields Image, CommandLine, ParentImage, ParentCommandLine, User, TeamId, SigningId; all Sysmon conditions + regex; validated at parse time.
- `bin/try.sh`: dry-run a cfg against a saved capture. `docs/CONFIG.md` guide.
### Not yet verified
- Any run on a real Mac (see docs/MAC-TEST-PLAN.md).
