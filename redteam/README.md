# Adversary emulation harness

Benign, self-cleaning emulations of real macOS attacker techniques, to confirm ESDaemon logs the behaviour an intrusion produces. This is detection validation (the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) / purple-team model), **not** an exploit kit: each scenario runs the genuine living-off-the-land binary with a harmless payload, places a unique nonce so its record can be found, checks the unified log for that record, and cleans up.

> Run it on a **lab VM**, on the Mac where ESDaemon is installed. By default nothing harms the machine. Techniques that would genuinely weaken it (disable Gatekeeper, enable root, erase the log, add an account, write a system LaunchDaemon) only run their real form with `--destructive`, and are restored afterwards.

## Use

```bash
redteam/run.sh list                     # every scenario: id, tactic, LOOBin, MITRE id, technique
sudo redteam/run.sh run                 # run all, verify each against the unified log, clean up
redteam/run.sh run --tactic persistence # one ATT&CK tactic
redteam/run.sh run --id launchagent     # scenarios whose name matches
redteam/run.sh run --no-verify          # just generate the activity (watch it arrive in your SIEM)
sudo redteam/run.sh run --destructive   # also the state-changing variants (VM only; restored after)
```

`sudo` is only needed for the `sudo`/root scenarios and `--destructive`; the rest run as your user. Output is a `technique -> DETECTED / MISS` list and a count. A MISS means ESDaemon did not log that behaviour — either an `[exclude]` rule is too broad, or a real coverage gap.

## What it covers

Scenarios map to MITRE ATT&CK for macOS across execution, persistence, defense evasion, credential access, discovery, collection, exfiltration and privilege escalation, using LOOBins (`osascript`, `nscurl`, `curl`, `xattr`, `spctl`, `sqlite3`, `security`, `system_profiler`, `dscl`, `dseditgroup`, `pbpaste`, `screencapture`, `tmutil`, `ditto`, `plutil`, `log`, `ioreg`, `networksetup`, `crontab`, `base64`). Network C2 is out of scope: Endpoint Security has no network events.

## Adding a scenario

Append a function to `scenarios.sh` and register it:

```bash
sc_my_technique() { case "$1" in
  meta) echo 'T1234|what it emulates|tactic|loobin|/usr/bin/tool|ProcessStart|-';;   # mitre|name|tactic|loobin|image|type|match
  run)  /usr/bin/tool --flag "$NONCE" >/dev/null 2>&1 || true;;
  clean) :;; esac; }
RT+=(sc_my_technique)
```

`type` is `ProcessStart` (default), `FileCreate`, `FileDelete`, `FileRead`, `UserLogin` or `any`. `match` is `-` when the command carries no nonce (the runner then matches on image + type within the run window); otherwise the runner requires the nonce in the record, so put `$NONCE` in a path or argument. Put any real state change behind `destructive '<cmd>' '<description>'` and restore it in `clean`.

## Sources

[LOOBins](https://loobins.io/) · [MITRE ATT&CK macOS](https://attack.mitre.org/matrices/enterprise/macos/) · [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) · [MITRE OceanLotus plan](https://ctid.mitre.org/projects/oceanlotus-adversary-emulation-plan) · [Objective-See](https://objective-see.org/blog) · [SentinelOne Labs](https://www.sentinelone.com/labs/author/macoswriter/) · [Jamf Threat Labs](https://www.jamf.com/blog/category/threat-labs/) · [PoisonApple](https://github.com/CyborgSecurity/PoisonApple)
