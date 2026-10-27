# Testing

## Automated tests

```bash
make test     # filter, config, format and lifecycle tests; macOS or Linux, needs bash and jq
make lint     # shell syntax, shellcheck, default config parses, scripts committed executable
make build    # macOS: compile the ESDaemon binary
```

The tests feed synthetic and real-shaped `eslogger` events through `src/scope.jq` with real configs parsed by `bin/cfg.sh`. They run in a few seconds and touch nothing on the system. Note that on a Mac where ESDaemon is installed, the test run itself is logged (it starts thousands of short processes); run them on a Mac you are not monitoring if that matters.

`make lint` fails on a syntax error (`bash -n`) in any script, on any shellcheck finding at warning level or above, on a default config that does not parse, and on a script committed without its execute bit. CI's Linux job runs shellcheck 0.9.0; where shellcheck is not installed, lint says `shellcheck not installed, skipped` and runs the other checks. The execute bits are read from the git index, not from the files on disk, so a copy that lost them (ZIP download, Windows) still lints; outside a git checkout that check is skipped with a notice.

## Checking a real Mac

Use a test Mac. Each step checks one thing; together they take about 15 minutes.

1. **Install and permission.** `sudo ./quick-install.sh`, then give `/usr/bin/eslogger` Full Disk Access. The installer ends with "events are flowing" once both work.
2. **Both daemons running.**
   `sudo launchctl print system/com.esdaemon.eslogger | grep -E 'state|last exit'`, the same for `com.esdaemon.filter`; `cat /var/log/ESDaemon/*.stderr` should show no errors.
3. **Process start.** Run `curl -s https://example.com -o /dev/null` and look for it:
   `log show --last 1m --predicate 'subsystem == "com.apple.eslogger"' --style ndjson | grep example.com`
   Expect an `EventID 1` / `ProcessStart` record with `CommandLine`, `ParentImage` and `User`.
4. **File create and delete.** `echo x > /tmp/esd-test && rm /tmp/esd-test` gives a `FileCreate` (11) and a `FileDelete` (23) with `TargetFilename` `/private/tmp/esd-test`.
5. **Logins.** SSH in from another machine (once with a wrong user name): `UserLogin` records with `Detail.success` true / false and `Detail.source_address`. Lock and unlock the screen for a console `UserLogin`.
6. **Detection-relevant activity is logged.** `osascript -e 'do shell script "id"'`, `security find-generic-password -s x`, `xattr -d com.apple.quarantine <file>`, and a plist written to `~/Library/LaunchAgents` must each appear.
7. **ESDaemon does not log itself.** `sudo launchctl kickstart -k system/com.esdaemon.filter`, wait 30 seconds, and check that no record names `/usr/local/ESDaemon/` (a manual `sudo reload.sh` is logged by design).
8. **Recovery.** `sudo launchctl kill SIGKILL system/com.esdaemon.filter`: the filter restarts and nothing is lost. `sudo launchctl kill SIGKILL system/com.esdaemon.eslogger`: both restart and an `eslogger_scoped_restart` record appears. Reboot: events resume without any action.
9. **Heartbeat.** Five minutes after the filter starts, `log show --last 6m --predicate 'subsystem == "com.apple.eslogger" AND process == "ESDaemon"' --style ndjson | grep eslogger_scoped_heartbeat` shows a heartbeat, then one every 5 minutes. After `sudo launchctl bootout system/com.esdaemon.filter` none follow; `sudo esdaemon reload` brings them back ([CONFIG.md](CONFIG.md#heartbeat)).
10. **Volume.** `sudo /usr/local/ESDaemon/measure.sh 600` during normal use, and compare with [DEFAULT-CONFIG.md](DEFAULT-CONFIG.md#measured-impact).
11. **Collector.** Confirm the records arrive in your SIEM exactly once ([GETTING-STARTED.md](GETTING-STARTED.md#5-ship-the-events-to-your-siem)).

Stopping your own `eslogger` captures: a backgrounded `eslogger` ignores SIGINT, so stop it with `kill -TERM <pid>`; `pkill eslogger` would also kill ESDaemon's.
