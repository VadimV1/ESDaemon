# What eslogger has to see — and what it can stop sending

## Where the gigabytes come from

The current daemon runs `eslogger --oslog exec` with no filtering. eslogger then emits every exec on the box: `xpcproxy`, `mdworker_shared`, periodic `sh -c` wrappers, IDE shells running `git status`, Chrome/Teams/Zoom helpers, MDM agents calling `defaults` and `sw_vers`. Each event is about 4 KB, and most of that is stat blocks and the full environment. The detection content lives in maybe 1–5% of those events.

**eslogger has no way to scope itself.** Apple's man page lists only `--oslog`, `--format`, `--oslog-subsystem`, `--oslog-category`, `--se` and `--list-events`. There is no path, select or mute option. The EndpointSecurity mute APIs (`es_mute_path` and inverted muting) exist only for a custom, Apple-entitled ES client. So there are two ways to scope:

| Option | Cuts | Effort |
|---|---|---|
| **A. eslogger → local filter → unified log** (this folder) | wire and SIEM bytes. eslogger still sees every exec locally, which costs a little CPU. | ships today. Needs `/usr/bin/jq`, which is on macOS 15+. |
| B. Custom ES client using `es_mute_path` + `ES_MUTE_INVERSE` on target path | the event is never generated at all | needs the Apple ES entitlement and a signed, notarized system extension. Weeks of work. |
| C. Santa in MONITOR mode, or an EDR export | depends on the product | procurement or deployment work. |

Option A fixes the GB/hour problem, because the cost you are paying is the bytes shipped. Option B is only worth pursuing if endpoint CPU turns out to be a problem too.

## What the rules actually need

I read all three sources as files, not from memory:

**Google curated MacOS Threats: 75 rules** (the Google SecOps "MacOS Threats" curated rule sets, full YARA-L: 14 Mandiant Frontline + 61 Mandiant Intel Emerging Threats). Two are placeholders, which leaves 73 real rules:

| Telemetry the rule needs | Rules | Can eslogger supply it? |
|---|---|---|
| Process exec only | **57 (78%)** | yes: `exec` |
| File only | 10 | yes, with `create`/`rename` scoped to the paths below |
| Process + file | 1 | exec + file |
| Process + network | 2 | only the exec half |
| Process + file + network | 1 | only the exec and file halves |
| Network only | 2 | **no.** ES has no IP-socket event. This needs DNS/proxy feeds or a NetworkExtension. |

Binaries these rules key on (count of rules whose `events:` section names the binary): `sh` 21, `osascript` 20, `zsh` 17, `curl` 17, `bash` 13, `dash` 10, `cp` 6, `zip`/`rm`/`cat` 5, `ditto` 4, `xattr`/`wget`/`system_profiler`/`open`/`chmod`/`base64` 3, then `unzip tar ssh sqlite3 ps nohup node mv ksh find bun whoami touch sysctl softwareupdate sed security perl pax mdfind ioreg id gunzip grep dscl defaults`.

**The key point:** the rules do not only match on *which binary ran*. They also match on:
1. **Parent**: `osascript → sh`, `node → sh`, `/Volumes/* → curl`, `osascript → nohup`. The parent is already present in every exec event as `.process`, so no extra collection is needed. The filter has to keep the child when the parent is interesting.
2. **Where it ran from**: `/tmp/<12 hex>/<16 chars>` (Shlayer), `/Users/Shared`, `~/Library/Application Support/.<hidden>`, `/.com.apple.*`, `/Volumes/*`, `bun-dl-*`, and Apple binaries copied into staging directories (still `is_platform_binary=true`). This is path-based, not name-based.
3. **argv content**: `curl -o /tmp`, base64, `do shell script`, Keychains, `Login Data`, TCC.db, `-c`/`-e` one-liners. Shells, `cp`, `cat` and `zip` are only interesting with that content.

**LOOBins: 61 binaries** (live site, loobins.io). All of them are covered by `lists/`, except `disown`, which is a shell builtin and never execs.

**Other corpora checked:** Elastic prebuilt macOS rules (97) and Sigma macOS rules (69). Weighted by ATT&CK technique, exec alone covers about 21%, and adding scoped file events brings it to about 47%.

## The keep policy (`scope.jq`)

An **exec** event is kept if any of these is true:

| # | Condition | Why |
|---|---|---|
| 1 | Target runs from a staging path (`/tmp`, `/private/var/folders`, `/Users/Shared`, `/Volumes`, `Downloads`, hidden App Support dir, `/.com.apple.*`, `Library/Caches`, `bun-dl-`) | curated staging-execution rules. Payloads live here. |
| 2 | Target `is_platform_binary=true` but outside `/System /usr /bin /sbin /Applications /Library/Apple` | a copied or masqueraded Apple binary |
| 3 | Target is not a platform binary (third-party, unsigned, ad-hoc), **unless** its Team ID is in `noisy_team_ids.txt` | unsigned payloads. Known vendor helpers are dropped. |
| 4 | Target basename is in `always.txt` (~65: curl, osascript, security, sqlite3, xattr, dscl, system_profiler, tccutil, ssh…) | LOOBins/curated binaries that benign software rarely runs |
| 5 | Target basename is in `conditional.txt` (shells, python/node, launchctl, defaults, cp, cat, zip, ps…) **and** one of: risky argv, an interesting parent, or a shell fed its script on stdin (`curl … \| sh`) | the chatty tools, kept only when they are doing something worth logging |
| 6 | Parent is osascript, curl, bun, an unsigned binary, or runs from a staging path, whatever the target is | covers `osascript → anything` and `DMG → anything` |
| — | Dropped: target or parent path under `noisy_path_prefixes.txt` | Bindplane's own `log stream` exec loop |

The vendor drop applies to the **target only**. A shell or curl launched *by* Chrome or Qualys is still judged on its own. This closes the "living-off-the-vendor" blind spot that the earlier Qualys Team-ID drop created in Bindplane, because that drop matched on actor *or* target.

A **file** event (`create`/`rename`) is kept only if a path matches persistence or credential locations: LaunchAgents/Daemons, loginwindow/loginitems, `backgrounditems.btm`, shell rc files, cron/sudoers/pam, `*.ccache`, keychains, TCC.db, `/tmp`, `/Users/Shared`, hidden App Support, `.vscode-oss`, `site-packages/*.pth`, Chrome Extensions/NativeMessagingHosts, `Library/Google/Cache/.*`. That covers all 12 curated rules that need file events.

**Every other event type you subscribe to is passed through unchanged.** Only subscribe to low-volume ones, for example: `btm_launch_item_add xp_malware_detected authentication sudo su login_login screensharing_attach od_create_user od_modify_password od_group_add setextattr mount`.

**Slimming** (on by default): each kept event is reduced to identity, signing (team_id, signing_id, cdhash, flags, platform), lineage (pid/ppid/original_ppid/responsible pid), argv, cwd, fds, target birthtime, and a filtered env (PATH, USER, XPC_SERVICE_NAME, SUDO_*, DYLD_*, SSH_CONNECTION). Stat blocks, thread and mach_time are removed. Other env vars are dropped as well, which also stops tokens in env from being shipped.

## Recommended subscription

```
ESLOGGER_EVENTS="exec create rename btm_launch_item_add xp_malware_detected authentication sudo setextattr mount" sudo ./install.sh
```

Start with `exec` alone and run `measure.sh` before and after. Add `create rename` next: this is the biggest single step in coverage, and the path filter limits the volume. Never subscribe to `write`, `close` or `open`. Those are the highest-volume ES classes, and none of the curated rules need them.

## Honest limits

- **Nothing here has been run on a Mac yet.** The logic passes 46/46 fixture tests, but the fixtures are **synthetic** events built in eslogger's JSON shape (the shape from Apple's own man-page `jq` example). Run `measure.sh` on one Mac first. It prints real bytes per binary, raw vs kept GB/hour, and saves both captures, so field paths and volume can be checked against reality.
- **ES drops are visible.** Whenever `global_seq_num` jumps (EndpointSecurity dropped events because the reader fell behind), the output gets a `{"eslogger_scoped_gap":N}` record. Alert on it: without that marker a drop just looks like a quiet host.
- **Recall test before rollout:** run a handful of Atomic Red Team macOS tests (osascript do-shell-script, curl-to-tmp + chmod + exec, security dump-keychain, LaunchAgent plist drop, xattr quarantine strip) on the pilot Mac and check that each one appears in `scoped.ndjson`.
- **The FIFO two-daemon design is unverified on a device.** It relies on launchd opening `StandardOutPath` in the child (so only eslogger blocks until the reader connects) and on eslogger exiting on SIGPIPE when the reader dies. If either assumption is wrong, the fallback is a single bash wrapper, and that means granting FDA to `/bin/bash`. I don't recommend that.
- **The `noisy_team_ids.txt` values are from memory** (Google, Microsoft, Zoom, Slack, Qualys). Check each one with `codesign -dv`.
- **The path is still ULS → Bindplane, but the subsystem and body change.** Kept events are written by `uls-writer` under eslogger's own `com.apple.eslogger` / `events` (Apple's 32 KB default applies, and the Bindplane predicate doesn't change). Only the sender process (`uls-writer` instead of `eslogger`) and the body change. The body is the slimmed JSON. Re-verify the parser in rendered preview UDM; passing validation proves nothing here. `uls-writer.swift` has not been compiled yet (there's no swiftc on this box). Build it on a Mac and check with `log stream` that messages show up public, not `<private>`.
- The Tier-C "conditional" risk regex will miss some attacker one-liners. That is the recall trade-off for dropping the chatty tools. Use `measure.sh`'s "still kept" table to move binaries between lists based on data.
- The 5 network rules cannot be satisfied from ES under any configuration.
