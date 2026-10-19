# Verification matrix

`bash scripts/self-test.sh` is the suite CI runs before images are built. It
lints with Ruff 0.14.2, compiles `src` and `tests`, runs `bash -n` on
`scripts/*.sh`, runs `python3 -m unittest discover -s tests -v`, builds a
wheel, and runs `mvn -B -f integrations/maven/pom.xml verify`.

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

## Not run in this environment

| Check | Why it is not a pass |
| --- | --- |
| `bash scripts/scan-images.sh` | `docker` is not installed here. The script exits 2 in that case. Pull-request CI builds the images and runs Trivy. |
| A pushed image digest and its provenance attestation | This change does not push an image. `provenance: true` is set on the publish job only. |
| The real NVD update | The updater needs `NVD_API_KEY` and is not part of the unit suite. |
| A full Dependency-Check analysis of this repository | That needs a published snapshot and the engine. The unit suite uses fixtures. |

Record the command and the exit code when you run one of those checks. Do not
describe a skipped image scan as clean.
