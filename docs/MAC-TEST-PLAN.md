# First Mac test

Use a test Mac, not a production one. Nothing here has run on a Mac yet — each step checks one assumption.

1. **Prereqs** — macOS 15+ (`/usr/bin/jq`), Xcode CLT (`xcode-select --install`), Terminal with Full Disk Access.
2. **Build** — `make build`, then:
   `printf '{"t":"%05000d"}\n' 0 | build/ESDaemon` and
   `log show --last 1m --style ndjson --predicate 'process == "ESDaemon"'`
   → message readable (not `<private>`) and not cut off at ~1 KB.
3. **Measure before installing** — `sudo bin/measure.sh 600` → raw vs kept GB/hour, top binaries. Save the output in a field-test issue.
   Also check a few raw events match the field paths scope.jq uses (`.event.exec.target.executable.path`, `.event.exec.args`, `.process.executable.path`, `team_id`, `is_platform_binary`).
4. **Install** — `sudo ./install.sh`. Grant FDA to `/usr/bin/eslogger` (or via PPPC profile).
5. **Running?** — `sudo launchctl print system/com.esdaemon.eslogger | grep -E 'state|last exit'` (and `.filter`); `cat /var/log/ESDaemon/*.stderr`.
6. **Events flowing** — `log stream --info --predicate 'subsystem == "com.apple.eslogger" AND process == "ESDaemon" AND userIdentifier == 0'`, then run `curl -o /tmp/x https://example.com` → expect an EventID 1 with CommandLine and ParentCommandLine.
7. **Recall** — run: `osascript -e 'do shell script "id"'`, `security find-generic-password -s x`, `xattr -d com.apple.quarantine <file>`, a plist into `~/Library/LaunchAgents` (with `events = exec create rename`). Each must appear.
8. **Resilience** — `sudo launchctl kill SIGKILL system/com.esdaemon.filter` → both jobs restart, events resume.
9. **Bindplane** — confirm the events arrive, then check the SecOps parser in preview UDM.
