# Security policy

ESDaemon is security tooling: a way to hide activity from it, or to make it log something false, is a vulnerability.

## Reporting

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue. Include the macOS version, your config, and steps to reproduce. We aim to reply within a week.

## In scope

- Activity that should be logged under the configured `[modules]` but can be made to disappear, for example by abusing the built-in self-exclusion, a default `[exclude]` rule, or record size limits.
- Records that can be forged or made to name the wrong process, user or file.
- Anything that lets an unprivileged user change ESDaemon's config, binaries or LaunchDaemons.
- Input that stops or stalls the filter (every later event would be lost).

## Out of scope

- A local administrator (root) disabling or changing ESDaemon: root can always do that. Such changes are themselves logged while ESDaemon runs.
- Events macOS's Endpoint Security does not provide (for example network connections).
- Exclude rules you wrote yourself that are too broad.
