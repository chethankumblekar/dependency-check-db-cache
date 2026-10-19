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

## Non-root execution on 19 October 2026

The current user was uid 1000. The scanner image default remains root.

| Path | Result |
| --- | --- |
| CLI | Passed. `docker run --rm --user 1000:1000 -v /tmp/cs-manifest:/work -w /work checkstead:local write-manifest ...` exited 0. `manifest.json` is owned by uid 1000. `checkstead:local version` printed `13.0.0`. |
| GitHub Action | Passed for the container invocation. Both `docker run` lines in `action.yml` pass `--user "$(id -u):$(id -g)"`. The same image, user, and mount wrote a host file as uid 1000. `act` was not run, and the action's `scan` subcommand was not executed. |
| Maven | Passed for the plugin launch. `dev.checkstead:checkstead-maven-plugin:0.1.0:scan` exited 0 as uid 1000 and wrote `/tmp/cs-stub/mvn-out`. The executable was a local stub that recorded `id`, so this was not a Dependency-Check analysis. |
| Gradle | Passed for the task launch. Gradle 8.14.3 `checksteadScan` exited 0 as uid 1000. The report files are owned by uid 1000. The executable was the same stub. |
| Azure DevOps | Passed for the argument builder and the container user. `buildArgs` includes `--user 1000:1000`. The image write above is the same `docker run --user` shape. The task's `scan` subcommand was not executed. |
| Compose | Passed. `docker compose -f docker-compose.yml` with the image set to `checkstead-server:local` started, and `http://127.0.0.1:8765/api/health` returned `{"ok": true}`. The server process is uid 999. `su` stays root only long enough to drop privileges. |

## Not run in this environment

| Check | Why it is not a pass |
| --- | --- |
| `bash scripts/scan-images.sh` | Trivy 0.70.0 gates matching this script were run on the local images. Fixed High and Critical OS exited 0 for `checkstead:local` and `checkstead-server:local`. The published scanner digest `sha256:e361299c823f7f8b92a2463f9a4077adc281309c9ef6f66d012c6b913bfd2272` exited 1 on that same OS gate. |
| A pushed image digest and its GitHub attestation | `gh attestation verify` of `checkstead@sha256:e361299c823f7f8b92a2463f9a4077adc281309c9ef6f66d012c6b913bfd2272` and `checkstead-server@sha256:0ed118f344789cea7b5e4dc90dee219581fae5397fb4fc538def433341962cf7` (commit `c5b1707`) exited 0. The older digests from run 39260814721 still return HTTP 404. Do not republish those images. |
| The real NVD update | The updater needs `NVD_API_KEY` and is not part of the unit suite. |
| A full Dependency-Check analysis of this repository | That needs a published snapshot and the engine. The unit suite uses fixtures. |

Record the command and the exit code when you run one of those checks. Do not
describe a skipped image scan as clean.
