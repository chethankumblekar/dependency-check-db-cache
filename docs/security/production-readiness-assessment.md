# Production-readiness assessment

## 20 October 2026 audit

Base: `main` at `3578a2f`. Branch: `hardening/production-readiness`.
Engine pin: Dependency-Check 13.0.0.

**Verdict: not production-ready yet.** The code-level findings below are fixed
and tested, CI on this branch is green, and the production snapshot key is
pinned. Still open: the first gated and attested publish, the first snapshot
signed by the pinned key, and the incremental updater against the live NVD. They are listed under
[Not verified](#not-verified). Checkstead should not be called
production-ready until each has evidence.

### What was failing before this change

| Item | Evidence |
| --- | --- |
| CI on `main` red | Run 39312051017: Maven Central returned HTTP 502 for `junit-bom` and the build had no retry or cache. |
| Daily snapshot not publishing | Run 39294556503 refused to sign (key `checkstead-2026-10` set as a secret, not pinned; on commit `c5b1707`). 3 of the 10 scheduled runs before it were cancelled at the 180-minute timeout: every run rebuilt the whole NVD database. |
| Published images not scanned | `publish-images` built and pushed `latest` without running any Trivy gate. Gates ran only on pull-request builds, which are different images. |

### Findings and status

| Severity | Finding | Status | Regression coverage |
| --- | --- | --- | --- |
| Critical | NVD findings for Java and other namespaced packages were dropped when the CPE vendor was not the Maven group, even at HIGHEST confidence. Log4Shell (log4j-core) and CVE-2015-6420 (commons-collections 3.2.1) never reached `checkstead.txt`, SARIF, or the threshold gate. Found by an end-to-end scan against the published snapshot. | Fixed in `match.py`. HIGH/HIGHEST CPE identifications are trusted; the CVE's CPEs must name the same vendor, product, and version; LOW, fuzzy, and mismatched MEDIUM matches are still dropped. | `tests/test_match_regressions.py`; re-run end to end, threshold 7 now exits 3 on CVE-2015-6420 |
| High | DNS rebinding and CSRF on the timeline server: any `Host` was served, and cross-site form posts reached `/api/session/local` and the GitHub App endpoints. | Fixed. `Host` allowlist (421), `Origin`/`Sec-Fetch-Site` check on unsafe methods (403), strict CSP. | `tests/test_server_hardening.py` |
| High | GitHub App endpoints trusted any loopback peer, so with a reverse proxy on the same host every internet user could create apps, read Actions runs, and start scans. | Fixed. A loopback bypass applies only when `CHECKSTEAD_LOCAL` is unset. | `test_github_administration_needs_a_session_behind_a_proxy` |
| High | Scanning an installed or pull-request repository ran `yarn audit` (and could run pnpm, go, mix, bundle-audit, swift) inside it; Yarn's `yarnPath` and `mix.exs` are code from the repository. Server secrets were in that process environment. | Fixed. Untrusted-source mode disables those analyzers; credential-like variables are removed from the engine environment. | `tests/test_scan_safety.py` |
| High | Release images were not the scanned images (above). | Fixed. Push `sha-` only, gate the pushed digest on every platform, attest, then promote tags to that digest. | `tests/test_ci.py` order assertions |
| High | `setup.sh`/`setup.ps1` ran unverified downloads: JDK "latest", Python archives, and `get-pip.py`. | Fixed. Fixed releases pinned by SHA-256 (two independent sources), `get-pip.py` removed, `CHECKSTEAD_REF`. | `tests/test_setup.py` tampered-download test |
| High | Six High CVEs in jars bundled by Dependency-Check 13.0.0, excluded from the gate by `--skip-dirs`. No upstream fix. | Fixed. Jars replaced with fixed patch releases pinned by SHA-256; skip removed. | `tests/test_engine_install.py` override tests; full image scan 0 High/Critical; end-to-end scan unchanged |
| Medium | Entra multi-tenant default accepted any directory; no audience check. | Fixed. `aud` and `tid` checked; allowed-tenant list; startup warning. | `tests/test_sso.py` |
| Medium | Snapshot updater timed out a third of the time. | Fixed in code. Incremental update from the verified last snapshot, weekly full rebuild, 330-minute limit. | `tests/test_key_management.py` seed tests. Not run against the NVD. |
| Medium | Client could not start on Windows (`import fcntl`). | Fixed. Portable lock. | `tests/test_scan_safety.py`. Not run on Windows. |
| Medium | No engine timeout; concurrent scans extracted over one database; the server could run scans in parallel. | Fixed. Process-group timeout, data-directory lock, one scan batch at a time (409). | `tests/test_scan_safety.py`, `tests/test_server_hardening.py` |
| Medium | Old, validly signed snapshots could be served again (freeze/rollback). | Fixed. Newest-seen check per cache. | `tests/test_snapshot_resilience.py` |
| Medium | No retry on snapshot download; unbounded manifest read; `Authorization` forwarded on cross-host redirects; no zip-bomb limit. | Fixed. | `tests/test_snapshot_resilience.py` |
| Medium | Snapshot signatures needed the `openssl` command (absent on Windows) and wrote the private key to a temp file. | Fixed. `cryptography` library. | `tests/test_snapshot_auth.py`, `tests/test_key_management.py` |
| Low | Server image base not pinned by digest; ran as root until the entrypoint dropped privileges; compose kept default capabilities. | Fixed. Digest pin, `USER 999`, `cap_drop: ALL`, read-only root. | `scripts/smoke-image.sh` |
| Low | Account database created with the default umask; expired sessions never deleted. | Fixed. | `tests/test_accounts.py` |
| Low | Checkouts persisted the token; two empty scripts. | Fixed. | `tests/test_ci.py` |

### Evidence from this change

| Check | Result |
| --- | --- |
| `bash scripts/self-test.sh` on Ubuntu 24.04 amd64 (Python 3.12.3, GnuPG 2.4.4, Maven 3.9.16, non-root user, `CI=1`) | Exit 0. Ruff passed. **183 tests, OK, none skipped.** Wheel built. Maven `BUILD SUCCESS`. |
| Same suite on macOS (Python 3.14, no gpg) | 183 tests; the 14 that need gpg are reported as skipped, not passed. |
| `actionlint .github/workflows/*.yml` | No findings. |
| `shellcheck -S warning scripts/*.sh` | No findings. |
| `setup.ps1` | Parsed by PowerShell 7 with no errors. Not executed. |
| Every action pin re-resolved against its tag with `gh api` | All matched. |
| Server image build + `smoke-image.sh server` (local arm64) | Passed: uid 999, no capabilities, read-only root, healthy, foreign Host 421, history 401. |
| Scanner image build + `smoke-image.sh scanner` (local arm64) | Passed: pin 13.0.0, uid 10001, offline scan refused. |
| `image-gates.sh` with Trivy 0.70.0 on both local images | Both exited 0. Full scanner scan with nothing skipped: 0 High or Critical. |
| End-to-end scan in the scanner image against `db-2026-10-18` (commons-collections 3.2.1 jar, lodash 4.17.15 lockfile, untrusted mode) | CVE-2015-6420 (9.8) and six lodash advisories reported; threshold 7 exits 3. |
| Maven retry configuration | `help:evaluate` reads `aether.connector.http.retryHandler.count` = 5 under `-f integrations/maven/pom.xml`. |

### Not verified

- **CI on this branch** ran green on pull request 23: `test`, both
  `Build images` jobs (Trivy gates and smoke tests on the amd64 images), and
  CodeQL. The publish path (gating a pushed digest, `imagetools create`) only
  runs after merge.
- **First publish.** No image from this change has been pushed, gated by
  digest, attested, or promoted. The amd64 images CI builds have not been
  scanned; the local scans were arm64.
- **Snapshot signing.** The maintainer supplied the public key for
  `checkstead-2026-10` and it is pinned in `snapshot_trust.json`. No snapshot
  signed by it exists yet, so that this key pairs with the
  `CHECKSTEAD_SNAPSHOT_SIGNING_KEY` secret is not yet shown. If it does not,
  the updater refuses to publish ("does not match the pinned public key").
  Every snapshot published so far is unsigned, and a client from this branch
  refuses it: scans fail until the first signed snapshot is published. See
  [Production operations](../operations/production-operations.md#snapshot-signing-key-management).
- **Incremental updater.** Seeding and the weekly rebuild are unit-tested
  against fixture snapshots, not run against the NVD.
- **Windows.** The `msvcrt` lock path and `setup.ps1` were not executed.
- **Identity providers.** GitHub OAuth and Entra flows are tested against
  local fakes, not real tenants.
- **Load.** No load or soak test of the server.

### Required configuration

| Item | Owner | Needed for |
| --- | --- | --- |
| `NVD_API_KEY` secret | Maintainer | Present. |
| `CHECKSTEAD_SNAPSHOT_SIGNING_KEY` secret, `CHECKSTEAD_SNAPSHOT_KEY_ID` variable | Maintainer | Present. Public key pinned on 20 October 2026. |
| A signed snapshot published before or right after this change merges | Maintainer | Scans with this client. Run `update-snapshot.yml` after merge. |
| GHCR packages public, or consumers given read access | Maintainer | Pulling images |
| Branch protection requiring `test`, `Build images`, and `Analyze` | Maintainer | Gates being mandatory |
| Server `.env`: `CHECKSTEAD_PUBLIC_BASE`, `CHECKSTEAD_LOCAL=0`, `CHECKSTEAD_COOKIE_SECURE=1`, OAuth settings, `CHECKSTEAD_ENTRA_TENANT` | Operator | Any deployment beyond one laptop |

### Residual risks

- A person who holds the signing secret can publish a snapshot clients
  accept. The key lives in one repository secret; it is not in a hardware
  module, and the updater job can read it.
- A company mirror needs its own key in a trust file named by
  `CHECKSTEAD_SNAPSHOT_TRUST`; the shipped key does not verify it.
- The engine jar overrides are a patch Checkstead maintains on top of an
  upstream release. They are pinned and tested, but upstream has not tested
  that combination. The laptop installers (`setup.sh`, `setup.ps1`) do not
  apply them yet.
- The scanner image still runs as root by default so
  `docker run -v "$PWD:/work"` keeps working. The Action and Azure DevOps task
  pass `--user`.
- A scan of a trusted tree still runs `yarn audit` when yarn is installed, by
  design. A fork pull request scanned outside the Action without
  `CHECKSTEAD_UNTRUSTED_SOURCE=1` is not protected.
- `CHECKSTEAD_LOCAL=1` on a port reachable from other machines lets anyone
  become the first administrator. Compose binds `127.0.0.1` and the server
  warns.
- Entra with `organizations` and no allowed-tenant list accepts sign-in from
  any directory for logins an administrator added. The server warns.
- Unfixed operating-system findings do not fail the gate (exception
  `unfixed-os-2026-10-19`, review 2027-01-19).
- `Dockerfile.server` has no Dependency-Check engine. A scan started from
  `/github` in that image reports that the engine is missing. Scanning from
  the server needs `checkstead ui` in the scanner image.

### Production-readiness checklist

| Area | Item | Status |
| --- | --- | --- |
| Security | Host and Origin checks, CSP, session handling, admin-only GitHub App | Done, tested |
| Security | Untrusted source code never executed by a scan | Done, tested |
| Security | Secrets kept out of the engine process and the report | Done, tested |
| Supply chain | Engine signature and fingerprint; installer downloads pinned by digest | Done, tested |
| Supply chain | Images gated, attested, and tagged by one digest | Done in workflow; **not yet run** |
| Supply chain | SBOM per image and platform | Done in workflow; local SBOMs generated |
| Snapshot integrity | Checksum, signature verification, rotation, rollback and freshness checks | Done, tested |
| Snapshot integrity | A production key pinned | Done (`checkstead-2026-10`) |
| Snapshot integrity | First snapshot signed by that key, verified by a client | **Open (next updater run)** |
| Containers | Digest-pinned bases, non-root server, no capabilities, read-only root, health check | Done, smoke-tested locally |
| CI/CD | All third-party actions pinned to verified SHAs | Done, re-verified |
| CI/CD | CI green on GitHub | Done on pull request 23 |
| Reliability | Timeouts, retries with backoff, locks, one scan batch at a time | Done, tested |
| Reliability | Updater finishes inside its time limit | **Open (first scheduled run)** |
| Cross-platform | Linux and macOS | Tested |
| Cross-platform | Windows | **Open (not executed)** |
| Operations | Deployment, secrets, key management, monitoring, incident response, backup, release, rollback | Written: [Production operations](../operations/production-operations.md) |

## 19 October 2026 audit

The rest of this file is the earlier audit, kept as it was written. Where it
disagrees with the section above, the section above is current.


Date of this audit: 19 October 2026. Repository:
`chethankumblekar/dependency-check-db-cache`. Product: Checkstead. Engine pin:
Dependency-Check 13.0.0 (`engine.version`).

This file records what the code did before the change, what was confirmed,
what this change implements, and what remains. It is not a penetration test
and it does not claim an image was published or signed.

## Architecture

```text
update-snapshot.yml
  NVD_API_KEY -> dependency-check --updateonly -> zip + manifest.json + sha256
  -> GitHub release db-YYYY-MM-DD (marked latest)

checkstead scan / GitHub Action / Maven / Gradle / Azure DevOps
  HTTPS manifest -> SHA-256 zip -> ~/.cache/checkstead/<UTC date>/
  -> safe_extract -> dependency-check --noupdate -> checkstead.txt + SARIF
  -> threshold / KEV / unscored policy

Dockerfile.server + docker-compose.yml
  timeline on 0.0.0.0:8765 inside the container
  published as 127.0.0.1:8765 on the host
```

The scan path is `src/checkstead/cli.py`, `scan.py`, `snapshot.py`, `http.py`,
and `archive.py`. The updater is `scripts/update-snapshot.sh`. The engine
install is `scripts/install-engine.sh`. Image publish is the `publish-images`
job in `.github/workflows/ci.yml`, and it runs only when the event is not a
pull request.

## Existing controls that already worked

These were traced in the code and covered by tests before this change:

- Snapshot manifest format, engine pin, UTC timestamp, checksum shape, and
  single-file database name (`parse_manifest`).
- SHA-256 compared before the manifest is written on a fresh download.
- Atomic `.partial` download, and deletion of that partial file on failure.
- `flock` on the cache directory.
- `services.nvd.nist.gov` refused before a connection, including a redirect.
- Scan argv contains `--noupdate` and not `--nvdApiKey`. `NVD_API_KEY` is
  stripped from the child environment.
- A manifest built by engine 12.1.8 is refused before the zip is used.
- The first verified manifest of a UTC day is reused. A later scan that day
  does not follow a changed publication.
- Score policy `prefer-newest` and `highest` are unchanged. Private
  suppressions stay optional. Findings stay in four groups.
- Server image user is `checkstead`. Compose binds `127.0.0.1:8765:8765`.
- The last administrator cannot be removed. Session cookies are `HttpOnly`
  and `SameSite=Lax`.

## Findings

### High — legacy updater published an unchecksummed database

`.github/workflows/update-db.yml` was scheduled at 01:00 UTC, the same time
as the real updater. It downloaded Dependency-Check 12.1.8, ran
`--updateonly` with `NVD_API_KEY`, zipped the data directory, and published
that zip with `softprops/action-gh-release` and `make_latest: "false"`.
There was no manifest and no checksum. 12.1.8 predates the database schema
this client accepts.

**Status: fixed.** The workflow file is deleted. `tests/test_phase1.py`
asserts it is absent and that `update-snapshot.yml` does not pin 12.1.8.
The real updater now refuses an empty zip and a manifest checksum that does
not match the zip, before `gh release create`.

### Medium — archive extraction accepted symlink members

`safe_extract` checked `..` and then called `ZipFile.extractall`. Python
will materialize a symlink member. A symlink to a path outside the
destination is a write outside the cache. The same helper extracts GitHub
repository archives (`src/checkstead/github_app.py`).

**Status: fixed.** `src/checkstead/archive.py` rejects absolute paths, `..`,
NUL, and symlink targets that resolve outside the destination. It does not
call `extractall`. Regression coverage is in `tests/test_phase1.py`.

### Medium — cleartext HTTP was allowed to any host

`ensure_allowed` accepted `http`, `https`, and `file`. Fixture servers use
`http://127.0.0.1`. A snapshot URL of `http://` to any other host would have
been fetched.

**Status: fixed.** `http` is allowed only for `localhost`, `127.0.0.1`, and
`::1`. `file://` and URLs with userinfo are refused. `https` to other hosts
remains, because GitHub releases and the GitHub API use it. The NVD host
stays refused on `https` as well.

### Medium — the engine zip was not authenticated

`scripts/install-engine.sh` downloaded the GitHub release zip and checked
that `dependency-check.sh --version` contained the pin. It did not check a
signature. A checksum published beside the zip would not have been an
independent proof, and this repository does not invent one.

Upstream publishes `dependency-check-13.0.0-release.zip.asc`. The signing
key fingerprint is `259A55407DD6C00299E6607EFFDE55BE73A2D1ED`, uid
`Jeremy Long <jeremy.long@gmail.com>` on the Ubuntu keyserver. On 19 October
2026 the 28 MiB v13.0.0 zip from that release verified with the key now
stored at `scripts/keys/dependency-check-release.asc` (`gpg: Good signature`).
GnuPG also said the key is not certified in a local web of trust. The
fingerprint pin is the control. The zip has 85 members and no symlinks.

**Status: fixed in the installer.** The script imports only that key,
requires that fingerprint, verifies the `.asc`, extracts with `archive.py`,
and still requires `--version` to report the pin. A mismatch deletes the
install. Tests use a generated key and do not download the upstream zip.

### Medium — pull-request CI could push packages

The `images` job set `packages: write` on every event, including pull
requests. `push` was already false on pull requests, but the token
permission was broader than the job needed. Actions were pinned to moving
tags (`@v5`, `@v6`), not commit SHAs. `provenance` was false.

**Status: fixed.** Pull-request builds are a separate job with
`contents: read`, `push: false`, and `load: true`. The publish job runs
only when `github.event_name != 'pull_request'` and is the job with
`packages: write`, `id-token: write`, and `attestations: write`. It sets
`provenance: true` and `sbom: true`. Actions used by the workflows are
pinned to the SHAs in `docs/security/supply-chain-and-provenance.md`.

### Low — scanner image runs as root

`Dockerfile` has no `USER`. The documented invocation is
`docker run -v "$PWD:/work" -w /work`. That mount is owned by the host user.
Switching the default to a fixed user breaks that command when the directory
is not writable by the image user.

**Status: default unchanged, non-root path added.** The image creates
uid 10001, makes the engine and virtualenv world-executable, and the
entrypoint gives a non-root uid a writable home and cache. The secure command
is `docker run --user "$(id -u):$(id -g)"`. The GitHub Action passes that
flag on both `docker run` lines. The Azure DevOps task passes
`--user <uid>:<gid>` from `process.getuid()` and `process.getgid()` when
those functions exist, which they do on the Linux agents this task targets.
The image default stays root.

### Critical — localhost sign-in trusted the Host header

`_local_sign_in("172.17.0.1", "127.0.0.1:8765")` returned true when
`CHECKSTEAD_LOCAL` was unset. The same call with `Host: localhost` returned
true. `tests/test_sso.py` expected that. A remote peer could send a localhost
`Host` header and open the shared `local` administrator session.
`CHECKSTEAD_LOCAL=0` did not stop it: that value only skipped the
trust-every-peer branch, and the header branch still ran. The earlier note
in this file said a spoofed Host header was not the control. That description
did not match the code.

**Status: fixed in this follow-up.** The decision uses the TCP peer, or the
explicit `CHECKSTEAD_LOCAL` mode. `Host`, `X-Forwarded-For`, `Forwarded`, and
`X-Real-IP` are ignored. Unset still allows a real loopback peer, so
`checkstead ui` on `127.0.0.1` works. `CHECKSTEAD_LOCAL=1` still allows the
Docker bridge peer, which is what Compose needs while the published port is
`127.0.0.1:8765:8765`. `CHECKSTEAD_LOCAL=0` now disables localhost sign-in for
every peer, including loopback, so a reverse proxy cannot mint the local
session. Regression coverage is in `tests/test_sso.py`.

### Informational — snapshot identity is the manifest, not a second publisher

Consumers verify SHA-256 against the manifest published in the same GitHub
release. That detects corruption and a zip that does not match its manifest.
The client now also verifies an Ed25519 signature when one is present, against
keys pinned in `src/checkstead/snapshot_trust.json`. That file has no keys.
No production private key was generated for this change, because a key created
here would not be a maintainer-held secret. Published snapshots stay unsigned.
`snapshot-authenticity: unsigned` is the honest status. A signature, once a
maintainer pins a key and stores the private half as
`CHECKSTEAD_SNAPSHOT_SIGNING_KEY`, still is not a second organization. It
stops a release upload that does not have the signing secret.

### Informational — same-day cache does not refresh

A valid cache for the UTC day is reused even if `releases/latest` changes.
Offline scans keep working. The tradeoff is documented in
`docs/operations/snapshot-operations.md`. A maximum age was not added,
because it would make a previously valid offline scan depend on the network.

## Design limits that were left in place

- Two local updater processes outside the workflow concurrency group can
  race. The second `gh release create` fails. The first release remains.
- The scanner-image report of Dependency-Check jars stays `exit-code: "0"`.
  The failing language-package gate skips `/opt/dependency-check`. Fixed
  Critical operating-system findings fail both images. Unfixed operating-system
  findings do not, and they are not listed in a `.trivyignore`. `docker` and
  `trivy` are not installed in this workspace (`scripts/scan-images.sh`
  exited 2). Pull request run
  [39263737597](https://github.com/chethankumblekar/dependency-check-db-cache/actions/runs/39263737597)
  on commit `8b73a6a` ran those gates and the image jobs succeeded.
- Image provenance for commit `b460679` was inspected. BuildKit attached SPDX
  and SLSA provenance to the scanner index. `gh attestation verify` returned
  HTTP 404 for both image digests. That GitHub check did not pass. The publish
  job now runs `actions/attest-build-provenance` for later publishes. This
  change does not push an image.
- `docker` is not installed in the environment where this assessment was
  written. `scripts/scan-images.sh` was syntax-checked by `bash -n` and was
  not executed. Exit 2 from that script means "not run", not "clean".

## External settings this audit could not see

- Whether the `NVD_API_KEY` secret is present on the repository.
- Whether the GHCR packages are public.
- Whether a snapshot release `db-*` currently exists.
- The result of the next pull-request Trivy run. The workflow is in CI. It
  has not run for this commit yet.

## What this change does not do

- No release was published. No image tag was pushed. No force-push.
- `engine.version` is still `13.0.0`.
- Score policy, exit codes for policy failures, and the four finding groups
  are unchanged.
- No suppression file was added. Unit tests still do not call the NVD.
- Pull request #2 was not modified. This work is a separate branch.

## Tests

Command: `bash scripts/self-test.sh`

Result on 19 October 2026: exit 0. Ruff passed.
`python3 -m unittest discover -s tests -v` reported `Ran 94 tests` and `OK`.
Maven `integrations/maven/pom.xml` reported `BUILD SUCCESS` (1 test).
`bash -n` covered `scripts/scan-images.sh` and `scripts/check-release.sh`
as part of that command.

`gpg --verify` of the real v13.0.0 zip against the vendored key succeeded
on this machine on 19 October 2026. That download is not part of the unit
suite.

The follow-up on this branch ran `bash scripts/self-test.sh` again after the
Host-header fix. Ruff passed. Unittest reported `Ran 104 tests` and `OK`.
Maven reported `BUILD SUCCESS`. `bash scripts/scan-images.sh` exited 2
(`docker` is not installed). `python3 scripts/verify-published-images.py` on
the two digests from run 39260814721 exited 3.

## Residual risk

- The engine signing key is pinned by fingerprint. It is not in a web of
  trust on the machine that installs it. GnuPG prints that warning and the
  script still requires the fingerprint match and a good signature.
- A person who can publish a GitHub release on this repository can publish
  an unsigned snapshot whose zip matches its manifest. No snapshot signing
  key is pinned, so signature verification does not yet apply to those
  releases.
- The scanner container's default user is still root. `--user` is optional.
  Actions and Azure DevOps do not pass it.
- `CHECKSTEAD_LOCAL=1` on a publicly forwarded port lets anyone who can open
  the port sign in as the shared `local` administrator.
- Unfixed operating-system findings and Dependency-Check's bundled jars are
  not a failing gate. Fixed Critical operating-system findings are. That
  gate has not run in this workspace.
- `gh attestation verify` does not succeed for the images published by run
  39260814721. BuildKit attestations on those indexes were readable. The
  GitHub attestation step is in the publish job and has not run yet.

## Next three improvements

1. Read the pull-request `trivy-scanner` artifact and decide which
   Dependency-Check jar findings, if any, should fail the build. Do not
   clear them by moving `engine.version` without an upstream release.
2. After the next authorized image publish, record the image digest in the
   README and confirm the provenance attestation. Consumers should pin that
   digest.
3. Add a tested non-root scanner path that still supports
   `docker run -v "$PWD:/work" -w /work`, for example by documenting a
   `--user` invocation only after a build in an environment that has Docker.

## Enterprise hardening follow-up

This section is the later pass. It does not replace the findings above, and
it does not call Checkstead production-ready.

- `scripts/setup.sh` and `scripts/setup.ps1` now require the same engine
  fingerprint as `scripts/install-engine.sh`, and they extract with
  `archive.py` only after `gpg --verify`. The shell path was executed with a
  bad signature and with a throwaway key. `pwsh` was not installed, so the
  Windows script was not executed.
- An empty `snapshot_trust.json` still accepts a checksummed unsigned
  snapshot. Any pinned key, or `CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE=1`,
  refuses a missing signature. No production key was created.
- Remote OAuth uses `CHECKSTEAD_PUBLIC_BASE` and does not trust `Host`.
  Loopback peers still may. Local sign-in is unchanged: peer address only.
- CI installs `.[dev]` and checks action pin format instead of a frozen SHA.
- The server image has a health check for `/api/health`. The scanner image
  removes pip, curl, and unzip after the build. A later local
  `bash scripts/scan-images.sh` against `eclipse-temurin:25-jre-noble`
  exited 0. The report-only scanner file no longer listed the four High
  OpenSSL findings. It still listed six High Dependency-Check jar findings.
  Those were not suppressed, and `engine.version` stayed `13.0.0`.
  Checkstead is not production-ready. The attested digests to verify are in
  [Supply chain and provenance](supply-chain-and-provenance.md). The images
  from run 39260814721 still have no GitHub attestation and were not
  republished.
