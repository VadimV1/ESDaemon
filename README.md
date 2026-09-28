# ESDaemon

macOS endpoint telemetry without the firehose. Runs `eslogger` as a daemon, keeps only detection-relevant events according to `ESDaemon.cfg`, and writes them to the unified log where the Bindplane agent collects them. The default subsystem is `com.apple.eslogger`, so an existing Bindplane predicate keeps working.

```
com.esdaemon.eslogger   /usr/bin/eslogger <events>  ──► FIFO
com.esdaemon.filter     FIFO ──► src/scope.jq (rules from ESDaemon.cfg) ──► uls-writer ──► unified log ──► Bindplane
```

Status: **pre-release, not yet run on a Mac** — see [docs/MAC-TEST-PLAN.md](docs/MAC-TEST-PLAN.md).

## Quick start (macOS 15+)
```bash
make build            # compiles uls-writer (Xcode CLT)
sudo bin/measure.sh 600   # optional: raw vs kept GB/hour before installing
sudo ./install.sh     # grant Full Disk Access to /usr/bin/eslogger
```
## Configure
Everything is in `/usr/local/ESDaemon/configs/ESDaemon.cfg`. **Full guide: [docs/CONFIG.md](docs/CONFIG.md).**

| To… | Do |
|---|---|
| always capture a binary | add its name under `[always]` |
| capture a chatty binary only when suspicious | put it under `[conditional]` |
| stop capturing a binary | remove it from the lists; for third-party binaries add `Image image <name>` under `[drop]` |
| drop one noisy launch | `[drop]` → `Image is /usr/bin/curl AND CommandLine begin with "curl -s https://updates.example.com/"` (Sysmon condition words: is, contains, begin with, end with, image, regex …) |
| drop a vendor's helpers | `third_party = drop_noisy` + Team ID under `[noisy_team_ids]` |
| change output fields | `format = sysmon \| sysmon+extras \| slim \| raw` |
| subscribe more event types | `events = exec create rename sudo …` |

Validate `/usr/local/ESDaemon/cfg.sh <cfg> json`, dry-run `/usr/local/ESDaemon/try.sh <capture.ndjson>`, apply `sudo /usr/local/ESDaemon/reload.sh`.

## Layout
| Path | What |
|---|---|
| `configs/ESDaemon.cfg` | default config: events, subsystem, `format`, binary lists, noise drops |
| `src/scope.jq` | the filter, formats (sysmon / sysmon+extras / slim / raw), drop markers |
| `src/uls-writer.swift` | stdin → `os_log` writer (sets subsystem, `%{public}@`) |
| `bin/` | `cfg.sh` (parser + validator), `filter.sh`, `reload.sh`, `measure.sh`, `try.sh` (dry-run a cfg on a capture) |
| `install.sh`, `uninstall.sh` | two LaunchDaemons + FIFO. Re-running never overwrites a tuned cfg |
| `test/` | synthetic keep/drop + format tests (`make test`) |
| `docs/CONFIG.md` | how to use and tune the config |
| `docs/VISIBILITY.md` | why each binary/path is in scope (curated macOS rules, LOOBins) |

## Develop
`make lint` · `make test` (Linux or macOS, needs `jq`) · `make build` (macOS). CI runs both on every push.
