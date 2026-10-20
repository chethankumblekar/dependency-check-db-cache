# Changelog

All notable changes to Checkstead are recorded here. The version matches the
package version. Snapshots are dated releases (`db-YYYY-MM-DD`) and are not
listed as product versions.

## Unreleased

Web UI:

- The timeline is redesigned around evidence. Overview opens with the newest
  scan's evidence chain (data freshness, signature, checksum, engine) and a
  Needs attention list, with exploited and critical findings first. Each scan
  has Findings, Changes, Dependencies, and Evidence tabs. See
  [docs/ui-design.md](docs/ui-design.md).
- Reports record `snapshot-authenticity` and `snapshot-key`; the history API
  returns them with each scan's policy and each finding's KEV flag.
- New `GET /api/history/summary` (scans without dependency lists) and
  `GET /api/scans/<id>`. The page no longer downloads every dependency of
  every scan on load.
- The page's Content-Security-Policy no longer allows inline script or style.
  Scripts, styles, and the vendored OFL fonts are served from a fixed
  allowlist under `/static/`, with ETags.
- Light and dark themes, keyboard navigation, and axe-checked views. The NVD
  attribution is shown wherever NVD data is.

Verification pass (pull request 25):

- The updater refuses to publish unless the new database finds
  CVE-2015-6420 in a digest-pinned jar, always queries the NVD
  (`--nvdValidForHours 0`), and has a `validate_only` mode that runs the full
  update, canary, and signing against the real NVD without a release. Its job
  runs in the `snapshot-signing` environment, limited to `main`.
- The account store closes its SQLite connections; before, the server leaked
  a file handle per session check under load.
- The timeline history is cached and gzip-compressed (42 to 940 req/s with
  204 scans), the server speaks HTTP/1.1 keep-alive, and
  `CHECKSTEAD_MAX_CONNECTIONS` (256) caps connections with a fast 503.
- A request body the handler did not read no longer corrupts the next request
  on a keep-alive connection.
- The scanner image drops root to the owner of the mounted directory with no
  capabilities. The server image is built on Ubuntu 24.04: 0 High or
  Critical findings, down from 63.
- `setup.ps1` works on real Windows: it no longer assigns the read-only
  `$HOME`, uses Windows' `tar.exe`, shows gpg's errors, works with Git for
  Windows' gpg, and judges the key import by the pinned fingerprint. A
  Windows CI job installs and scans end to end.
- `scripts/load-test.py` (load, stress, slow clients, soak with memory and
  file-handle limits) and `scripts/idp-preflight.py`, with a manual
  identity-provider test plan.

Security:

- The timeline server refuses a `Host` it was not configured for (421), which
  stops DNS rebinding, and refuses a cross-site `POST`, `PATCH`, or `DELETE`
  by `Origin` and `Sec-Fetch-Site` (403). New: `CHECKSTEAD_ALLOWED_HOSTS`.
- GitHub App pages and actions need an administrator session whenever
  `CHECKSTEAD_LOCAL` is set. Before, any loopback peer, including every user
  of a reverse proxy on the same host, could reach them.
- A strict Content-Security-Policy, `Cross-Origin-Opener-Policy`, and HSTS
  with `CHECKSTEAD_COOKIE_SECURE=1`. Requests time out after 30 s of silence.
- Microsoft Entra sign-in checks the ID token's audience and directory.
  `CHECKSTEAD_ENTRA_TENANT=<id>` or `CHECKSTEAD_ENTRA_ALLOWED_TENANTS` limits
  directories; the server warns when any directory may sign in.
- Scans of untrusted trees turn off analyzers that run yarn, pnpm, go, mix,
  bundle-audit, or swift inside the tree, which could run code from the
  repository. GitHub App scans always do; the Action does for pull requests;
  `--untrusted-source` or `CHECKSTEAD_UNTRUSTED_SOURCE=1` elsewhere. Every
  credential-like variable is removed from the engine's environment.
- Snapshots: a client refuses a snapshot older than one its cache already
  used (`CHECKSTEAD_ALLOW_SNAPSHOT_ROLLBACK=1` to override). Signatures use
  the `cryptography` package instead of the `openssl` command.
  `checkstead snapshot-key generate|public` creates keys and trust entries.
- The production snapshot key `checkstead-2026-10` is pinned. Clients refuse
  unsigned snapshots and keys that are not pinned. `CHECKSTEAD_SNAPSHOT_TRUST`
  replaces the shipped trust store for a company mirror and must pin a key.
- Zip extraction refuses archives over `CHECKSTEAD_MAX_ARCHIVE_BYTES` or
  `CHECKSTEAD_MAX_ARCHIVE_MEMBERS`. An `Authorization` header is dropped when
  a redirect changes host.
- `setup.sh` and `setup.ps1` pin the Python and JDK downloads by SHA-256, use a
  fixed JDK release instead of "latest", drop the unpinned `get-pip.py`
  fallback, and accept `CHECKSTEAD_REF=<tag>`.
- The scanner image replaces the vulnerable Jackson and jsoup jars bundled in
  Dependency-Check 13.0.0 with fixed releases pinned by SHA-256, and so do
  `setup.sh` and `setup.ps1`. The engine is no longer skipped by the image gate.
- The server image is pinned by digest, runs as uid 999, and the compose file
  drops every capability and mounts the root filesystem read-only.

Fixes:

- An NVD finding for a Java (or other namespaced) package was dropped when the
  CPE vendor differed from the Maven group, even at HIGHEST confidence.
  CVE-2015-6420 in commons-collections 3.2.1 and Log4Shell in log4j-core were
  missing from reports and could not fail a build.
- The client imported `fcntl` and could not start on Windows.
- Dependency-Check runs stop after `CHECKSTEAD_SCAN_TIMEOUT_MINUTES` (120) with
  their child processes. Parallel scans on one machine no longer extract over
  each other's database. The server runs one repository scan batch at a time.
- Snapshot downloads retry transient failures with backoff and cap the
  manifest size.
- The daily updater starts from the last verified snapshot, so it no longer
  hits the job timeout; it rebuilds from the NVD on Sundays.
- CI: Maven retries transient Central errors and caches dependencies.

Release process:

- The publish job pushes only `sha-<commit>`, runs the image gates on that
  pushed digest for every platform, attests it, and only then moves `latest`
  and the version tags to it. Release tags build without the layer cache.

## 0.1.0

- Pins OWASP Dependency-Check 13.0.0. One updater publishes a checksummed
  snapshot. A scan uses that snapshot with `--noupdate` and does not call
  `services.nvd.nist.gov`.
- Names the score a finding is judged on. The policies are `prefer-newest` and
  `highest`. A KEV finding stays visible. A finding with no score is a
  `no score` line.
- Keeps a private suppression file optional. A missing or empty file does not
  block a scan, and a URL is refused.
- Shows findings in one table on the timeline. The groups are Direct ·
  Production, Direct · Dev, Transitive · Production, and Transitive · Dev. A
  path inside `node_modules` is the package name.
- Verifies the Dependency-Check release signature in the Linux, macOS, and
  Windows setup scripts, with the same fingerprint as the image installer.
- Refuses an unsigned snapshot once a public key is pinned, and keeps
  checksummed offline scans working while `snapshot_trust.json` is empty.
- Ignores `Host` for OAuth when the TCP peer is not loopback. Set
  `CHECKSTEAD_PUBLIC_BASE` for a remote origin.
- Pins GitHub Actions by commit SHA without copying each SHA into the unit
  test. CI installs the dev extra from `pyproject.toml`.
- Signs a person in on localhost with **Sign in on this computer**. That
  sign-in does not use an OAuth app. It uses the TCP peer address.
  `CHECKSTEAD_LOCAL=1` is the Compose bootstrap. `CHECKSTEAD_LOCAL=0` turns
  the sign-in off. A `Host` or `X-Forwarded-For` header does not count as
  localhost. GitHub and Microsoft sign-in stay optional.
- Connects a personal GitHub account or an organization through a GitHub App.
  The page does not ask for a token.
- Lists recent Checkstead workflow runs for a connected repository: queued, in
  progress, success, or failure. A run on a pull request is labeled with the
  pull request number and links to that pull request. Rerun starts that same
  run again with the app credentials already stored.
