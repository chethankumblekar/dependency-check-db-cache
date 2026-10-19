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
| Snapshot signature, tamper, missing signature, key mismatch, freshness | `tests/test_snapshot_auth.py` |
| Scanner entrypoint creates a home for a non-root uid | `tests/test_scanner_user.py` |
| Linux and macOS setup refuses a bad engine signature and installs a throwaway signed zip | `tests/test_engine_install.py` |
| Windows setup script pins the same fingerprint and verifies before extract | `tests/test_setup.py` (script text; `pwsh` was not run) |
| Unsigned checksummed cache works with an empty trust file and fails once a key is pinned | `tests/test_snapshot_auth.py` |
| Remote `Host` is not the OAuth origin; `CHECKSTEAD_PUBLIC_BASE` is | `tests/test_sso.py` |
| Link-local and metadata hosts are refused; a private address is not | `tests/test_phase1.py` |
| Server entrypoint skips `chown` when the uid is not root | `tests/test_supply_chain.py` |

## Not run in this environment

| Check | Why it is not a pass |
| --- | --- |
| `bash scripts/scan-images.sh` | `docker` and `trivy` are not installed here. The script exits 2 in that case. Pull-request CI builds the images and runs Trivy. Exit 2 is not a pass. |
| A pushed image digest and its GitHub attestation | `gh attestation verify` of `checkstead@sha256:e361299c823f7f8b92a2463f9a4077adc281309c9ef6f66d012c6b913bfd2272` and `checkstead-server@sha256:0ed118f344789cea7b5e4dc90dee219581fae5397fb4fc538def433341962cf7` (commit `c5b1707`) exited 0. The older digests from run 39260814721 still return HTTP 404. Do not republish those images. |
| The real NVD update | The updater needs `NVD_API_KEY` and is not part of the unit suite. |
| A full Dependency-Check analysis of this repository | That needs a published snapshot and the engine. The unit suite uses fixtures. |

Record the command and the exit code when you run one of those checks. Do not
describe a skipped image scan as clean.
