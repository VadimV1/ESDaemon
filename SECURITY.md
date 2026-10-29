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

## Supply chain trust model

Installing or updating ESDaemon runs code from this GitHub repository **as root**. The sections above cover attacks on the running filter; this one covers how the bytes reach the Mac, so a fleet owner can decide how to deploy it.

### How install and update fetch code

The supported install is one command:

```bash
curl -fsSL https://raw.githubusercontent.com/VadimV1/ESDaemon/main/quick-install.sh | sudo bash
```

It fetches a script over HTTPS from `raw.githubusercontent.com` and pipes it straight into `sudo bash`: whatever the repository's `main` branch points to at that moment runs as root. `quick-install.sh` then:

- **Downloads the source** as a branch or tag tarball (`https://codeload.github.com/VadimV1/ESDaemon/tar.gz/<ref>`, where `<ref>` is `main` unless you set `ESDAEMON_REF`) and pipes it into `tar`. The tarball is **not pinned by hash** — it is whatever `<ref>` resolves to at download time, with no signature or checksum on the source.
- **Fetches the binary** from the repository's **latest** GitHub release — `ESDaemon-macos-universal`, plus the `ESDaemon-macos-universal.sha256` published beside it — and installs it only if its SHA-256 matches. If no verified release binary is available it builds from the source it just fetched, with `swiftc`.

`bin/update.sh` (`esdaemon update --install`) follows the **same path**: it reads the latest release tag from the GitHub API, downloads that tag's source tarball from `codeload.github.com` (again not hash-pinned), and re-runs `quick-install.sh`, which fetches and checks the release binary as above. Every update carries the same trust as the first install.

### The `.pkg` installer (MDM)

A prebuilt `ESDaemon-<version>.pkg` is attached to each release so a fleet can deploy ESDaemon with an MDM (Jamf, Kandji, Intune), which pushes `.pkg`s rather than `curl … | sudo bash`. The package is a thin delivery wrapper: its payload stages this repository's install sources, and its `postinstall` runs the same `install.sh` described above — ad-hoc signing and verifying the binary, keeping a tuned config, loading the daemons — and then removes the staging directory. A `.pkg` install therefore carries the **same trust and does the same work** as a script install, with the install sources and the bundled binary fixed at the release you deploy rather than tracking `main`.

The released `.pkg` is **unsigned** (no Developer ID Installer signature, not notarized). This is appropriate for MDM, which is itself the trust anchor on a managed device: the MDM server authorises what installs, so the Mac does not rely on the package's own signature. For a `.pkg` run **outside** MDM — downloaded and installed by hand — Developer ID Installer signing and notarization is the planned step, the same roadmap item as for the binary (below).

### What the checksum proves — and what it does not

`ESDaemon-macos-universal.sha256` is published in the **same release, from the same origin, as the binary it describes**. Verifying it proves the binary arrived **intact in transit** between GitHub and the Mac. It does **not** prove **authenticity**: anyone who can publish or replace that release replaces the binary and its `.sha256` together, and the check still passes. It is a transit-integrity check, not an independent anchor of who built the binary.

The binary is **ad-hoc signed only** (`codesign -s -`, in both the release workflow and `install.sh`). An ad-hoc signature gives the binary a code identity (a cdhash) but is bound to no developer and no Apple certificate, so it attests nothing about origin. ESDaemon is **not** signed with an Apple Developer ID and is **not** notarized.

### What this means

There is no trust anchor that lives off GitHub. **Whoever controls this repository or its releases controls root on every Mac that installs or updates from it** — anyone able to push to `main`, move a tag, or publish or replace a release. GitHub itself, and anyone who takes over the maintainer's account, is inside that boundary. Installing from `main` (the default) also means each Mac gets whatever `main` points to at its own install time, which can differ between machines and over time. This is a deliberate trade-off for a small, auditable, dependency-free tool, stated here so you can decide whether it fits your environment.

### Deploying to a fleet

To narrow that boundary:

- **Pin the source revision.** Set `ESDAEMON_REF` to a specific release tag (for example `v0.1.0`) or commit, so the installed scripts, filter and config are a fixed revision you have reviewed rather than a moving `main`. (The prebuilt binary is a separate artifact — the installer always pulls it from the *latest* release — so pinning the ref alone does not pin the binary; use the two points below for that.)
- **Verify the binary out of band.** Compare the release binary against a SHA-256 you obtained through a channel you control — recorded in your MDM or an internal system when you reviewed that release — not only against the `.sha256` the installer fetches from the same release. That is what turns transit integrity into authenticity relative to the build you vetted.
- **Deploy from an internal copy.** The most robust option: review a specific source revision and binary, then install from infrastructure you control. Point `ESDAEMON_REPO` at an internal mirror or fork, or place your reviewed binary at `build/ESDaemon` in a pinned checkout before running the installer — it then installs that binary and downloads nothing. Your trust anchor becomes your own review and infrastructure, not the upstream repository's live state.

Each of these also protects you if upstream is compromised after you have vetted it.

### Planned: Developer ID signing and notarization

Signing the released binary with an Apple Developer ID certificate and notarizing it — and likewise signing the `.pkg` with a Developer ID Installer certificate — would give them an anchor that does not live on GitHub, so a Mac could verify origin and integrity independently of where the file was downloaded (and `installer` / Gatekeeper would accept a hand-run `.pkg` without an MDM behind it). `bin/mkpkg.sh` already has the signing hook (`ESDAEMON_PKG_SIGN_ID`); the missing piece is a certificate and a notarization step in the release workflow. This is a **roadmap item, not a commitment**: it is not implemented today, and nothing here promises that it will be, or by when. Until it ships, the trust model above is the current state.
