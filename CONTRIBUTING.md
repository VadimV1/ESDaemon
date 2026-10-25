# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Before you open a pull request

- `make lint && make test` pass (macOS or Linux, needs `bash` and `jq`).
- Every behaviour change comes with a test in `test/` that fails without it.
- A new default `[exclude]` rule names an exact binary (and, for file events, that binary's own folder), says in a comment why it removes no investigative value, and adds a test proving that the same path written by another program, or a copy of the binary, is still logged. Include the measurement that motivated it (`measure.sh` output: records per 10 minutes, macOS version).
- Never exclude on `CommandLine` (or another field the process chooses) alone; see [docs/CONFIG.md](docs/CONFIG.md#writing-safe-rules).
- User-facing changes get a line in [CHANGELOG.md](CHANGELOG.md) and, where needed, in the docs.

## Reporting noise or a missed event

Open an issue with the macOS version, the `[modules]` you run, and the record(s) involved (remove user names, host names and anything private). For noise, attach the top of `sudo /usr/local/ESDaemon/measure.sh 600`.

## How the pieces fit

- `bin/cfg.sh` parses and validates `ESDaemon.cfg`; anything it does not understand is an error, never ignored.
- `bin/reload.sh` turns the config into the two LaunchDaemons (eslogger with the event types `[modules]` needs, and the filter).
- `src/scope.jq` decides per event (modules, `[include]`, `[exclude]`, never ESDaemon itself) and builds the Sysmon-style record.
- `src/ESDaemon.swift` writes each record to the unified log.

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
