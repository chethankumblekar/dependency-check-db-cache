# Verification matrix

`bash scripts/self-test.sh` is the suite CI runs before images are built. It
lints with the Ruff version pinned in `pyproject.toml`, compiles `src` and
`tests`, runs `bash -n` on `scripts/*.sh`, runs `python3 -m unittest discover
-s tests -v`, builds a wheel, and runs `mvn -B -f integrations/maven/pom.xml
verify`.

The unit tests serve fixtures on `127.0.0.1`. They do not call
`services.nvd.nist.gov`. They do not create a GitHub release or push an image.

| Behavior | Test |
| --- | --- |
| One snapshot for a UTC day, and the client does not request the NVD host | `tests/test_phase1.py` |
| Manifest engine mismatch, including 12.1.8 | `tests/test_phase1.py` |
| Checksum mismatch deletes the new zip and does not write a success | `tests/test_phase1.py` |
| A cached zip that no longer matches its manifest is refused and left in place | `tests/test_phase1.py` |
| `../` member, symlink member pointing outside, and absolute member are refused | `tests/test_phase1.py` |
| Cleartext HTTP off loopback, `file://`, userinfo, and the NVD host are refused | `tests/test_phase1.py` |
| Scan command contains `--noupdate` and not `--nvdApiKey` | `tests/test_phase1.py` |
| Updater exits when the key is missing, and does not rebuild an existing day's release | `tests/test_phase1.py` |
| Legacy `update-db.yml` is gone, and the publisher checks the manifest checksum | `tests/test_phase1.py` |
| Engine install: bad pin, failed download, bad signature, wrong `--version`, missing binary, zip slip, good signature | `tests/test_engine_install.py` |
| `checkstead doctor` does not print secret values | `tests/test_phase1.py` |
| Source CycloneDX names `certifi` and the engine pin | `tests/test_supply_chain.py` |
| `check-release.sh` and `scan-images.sh` do not push | `tests/test_supply_chain.py` |
| CI permissions, SHA pins, Trivy exit codes, image tags | `tests/test_ci.py` |
| Score policy, groups, SARIF, suppressions, accounts, SSO, pull requests | `tests/test_score.py`, `tests/test_history.py`, `tests/test_server.py`, `tests/test_accounts.py`, `tests/test_sso.py`, `tests/test_pull_request.py` |
| Remote `Host` and `X-Forwarded-For` do not grant localhost sign-in | `tests/test_sso.py` |
| Snapshot signature, tamper, missing signature, key mismatch, freshness, interrupted cache, missing snapshot | `tests/test_snapshot_auth.py` and `scripts/verify-snapshot-pin.py` |
| Image rollback by digest refuses `:latest` and does not push | `scripts/rollback-image.sh`, `tests/test_supply_chain.py` |
| Scanner entrypoint creates a home for a non-root uid | `tests/test_scanner_user.py` |
| Linux and macOS setup refuses a bad engine signature and installs a throwaway signed zip | `tests/test_engine_install.py` |
| Windows setup script pins the same fingerprint and verifies before extract | `tests/test_setup.py` (script text; `pwsh` was not run) |
| Unsigned checksummed cache works with an empty trust file and fails once a key is pinned | `tests/test_snapshot_auth.py` |
| Remote `Host` is not the OAuth origin; `CHECKSTEAD_PUBLIC_BASE` is | `tests/test_sso.py` |
| Link-local and metadata hosts are refused; a private address is not | `tests/test_phase1.py` |
| Server entrypoint skips `chown` when the uid is not root | `tests/test_supply_chain.py` |
| Release candidate tags do not move floating tags or `:latest` | `tests/test_release.py`, `.github/workflows/release.yml`, `.github/workflows/ci.yml` |
| Azure Repos thread: one closed thread, updated on later pushes, only a `Checkstead.Report` thread edited, deleted thread recreated | `tests/test_azure_devops_pr.py` |
| Azure Repos pull request lookup for a push, the build validation shortcut, and the `checkstead/score-policy` status from the job status | same |
| Azure DevOps examples use no `System.`/`Build.`/`Agent.` macro in a script body, record the origin, and send the report | `tests/test_azure_devops_pr.py`, `tests/test_upload.py` |
| Upload tokens: shown once, stored hashed, last use recorded, revoked tokens refused; administrators only | `tests/test_upload.py` |
| Upload endpoint: no token or a wrong one refused unread; over the limit refused unread; non-zip, traversal, nested, unknown files, no `checkstead.txt` refused | same |
| Report header records `repository-url` without userinfo and `build-url` with `buildId` | same (`checkstead scan --dry-run`) |
| Repositories lists pipeline-reported scans by organization, project, repository, branch; scans of checkouts stay off | `tests/test_upload.py`, `web/tests/flows.test.mjs` |
| Optional service-principal sync, the inventory keeping the last good sync, and Entra group admission and promotion | `tests/test_sources.py` |

## Azure DevOps, recorded on 22 October 2026

These runs used real Azure DevOps on Microsoft-hosted `ubuntu-latest` agents, with a throwaway orphan branch, `checkstead-test/main`. The scanner image was built from this branch in each run.

| Case | Result |
| --- | --- |
| Push before a pull request exists | Branch scanned alone; no comment |
| Pull request adds axios 1.10.0 | Scan exit 3; one closed thread with `Checkstead.Report`; status `failed` linking the build |
| Second push to the same pull request | The same thread updated |
| A person's comment containing the report marker | Left alone; only Checkstead's thread updated |
| Clean pull request | "Introduced findings: None"; status `succeeded` |
| Branch named `checkstead-test/x$(touch${IFS}/tmp/checkstead-pwned)` | Accepted by Azure DevOps; the canary file was absent and the run succeeded. The local harness also checked that the name is recorded as written. |
| Report copied to Azure Files with `az storage file upload-batch --auth-mode login` | Failed until `--enable-file-backup-request-intent` was added; then uploaded |

A local server received `checkstead upload` from a container. It listed the report under Azure DevOps: Ascertra, Proarc-Products, the repository, and the branch, with the run link. A wrong token got HTTP 401.

## Non-root execution on 19 October 2026

The current user was uid 1000. The scanner image default remains root.

| Path | Result |
| --- | --- |
| CLI | Passed. `docker run --user 1000:1000` of `checkstead@sha256:5e73042dd6b27baa4bbd541b8a7c00714676fb5d1e1bd0534301580a612c414f` ran `scan` and wrote `dependency-check-report.html` owned by uid 1000. Exit 0. Engine 13.0.0. |
| GitHub Action | Passed. `docker build -t checkstead-action` exited 0, then the non-pull-request `docker run --user "$(id -u):$(id -g)"` from `action.yml` exited 0. The report is owned by uid 1000. `act` was not used. |
| Maven | Passed. `dev.checkstead:checkstead-maven-plugin:0.1.0:scan` exited 0 as uid 1000. The executable was the installed `checkstead` command and Dependency-Check 13.0.0, not a stub. The HTML report is owned by uid 1000. |
| Gradle | Passed. Gradle 8.14.3 `checksteadScan` exited 0 as uid 1000 and wrote `dependency-check-report.html` owned by uid 1000. |
| Azure DevOps | Passed. `node integrations/azure-devops/task/index.js` with `INPUT_IMAGE` set to the candidate scanner digest exited 0. The report is owned by uid 1000. The task's default tag `checkstead:0.1.0` was not the image used. |
| Compose | Passed. `docker compose -f docker-compose.yml up -d` exited 0. `http://127.0.0.1:8765/api/health` returned `{"ok": true}`. The server process is uid 999. |

## Recorded on 19 October 2026

| Check | Result |
| --- | --- |
| `bash scripts/scan-images.sh` | Exited 0 after the operating-system gate included fixed High findings. |
| Main publish `f3731b3`, run 39297714215 | `gh attestation verify` exited 0 for `checkstead@sha256:063cde562cec605672518f5951af861b512b8df08b7f2096b930b89bb92cb740` and `checkstead-server@sha256:1a94da1ead8757e90d4df7ce4fff959f9319b1da617a4096c69186df0b301744`. `scripts/verify-published-images.py` exited 0. Fixed High and Critical OS and the failing library gates exited 0. The scanner full report still lists 6 High jars. |
| Release candidate `v0.1.1-rc.1` | `checkstead@sha256:5e73042dd6b27baa4bbd541b8a7c00714676fb5d1e1bd0534301580a612c414f` and `checkstead-server@sha256:df7ebe075c05a0e0a28d2452691c4260988dd924da097abe70627ae8f190b146`. Attestation verify exited 0. `docker pull` of the scanner digest and `write-manifest` as uid 1000 exited 0. `manifest.json` is owned by uid 1000. The tag did not publish `latest`. |
| Older scanner `sha256:e361299c823f7f8b92a2463f9a4077adc281309c9ef6f66d012c6b913bfd2272` | The fixed High OS gate exited 1. That image was not rebuilt. |
| Rollback pull | `scripts/rollback-image.sh` on the `c5b1707` scanner digest exited 0. The local image stayed untagged. `:latest` was not moved. |
| Throwaway-key failure drills | `python3 -m unittest` of the bad-signature, tampered-manifest, missing-snapshot, stale-snapshot, interrupted-cache, retired-key, and empty-trust tests in `tests/test_snapshot_auth.py` exited 0. The keys were generated in the test. The production signing key was not used. |

## Not run in this environment

| Check | Why it is not a pass |
| --- | --- |
| The real NVD update | Run 39294556503 is the updater already in progress. This suite does not start another one. No signed manifest has been published, so the public key is not pinned. |
| A full Dependency-Check analysis of this repository | That needs a published snapshot and the engine. The unit suite uses fixtures. |

Record the command and the exit code when you run one of those checks. Do not
describe a skipped image scan as clean.
