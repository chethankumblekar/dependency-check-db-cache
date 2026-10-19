# Supply chain and provenance

## Actions

Workflow `uses` lines are commit SHAs. The comment after the SHA is the
release tag that was resolved when the pin was written. Resolve a new tag
with:

```bash
gh api repos/actions/checkout/commits/v5 --jq .sha
```

Replace the SHA and the tag comment in the same change. Dependabot
(`.github/dependabot.yml`) opens weekly pull requests for GitHub Actions,
pip, Docker base images, and `integrations/maven`.

The workflow file is the pin. CI checks that every `uses` line is a 40-character
commit SHA with a tag comment. It does not freeze that SHA in a unit test, so a
reviewed Dependabot SHA update does not fail for a second hardcoded copy.
Actions stay pinned. A floating `@v1` tag still fails CI.

Pins recorded on 19 October 2026, after the setup-python 7.0.0 and setup-node
7.1.0 bumps. This table can lag a later Dependabot merge. Read the workflow
for the SHA that CI actually runs:

| Action | Tag | Commit |
| --- | --- | --- |
| `actions/checkout` | v5 | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` |
| `actions/setup-python` | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/setup-java` | v5 | `b6effb05e454b25005698d916606bdc6ffcbf961` |
| `actions/setup-node` | v7.1.0 | `949feb2413d6458794dcd2491c4babbbce0c15c1` |
| `actions/upload-artifact` | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `docker/setup-qemu-action` | v3 | `c7c53464625b32c7a7e944ae62b3e17d2b600130` |
| `docker/setup-buildx-action` | v3 | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` |
| `docker/login-action` | v3 | `c94ce9fb468520275223c153574b00df6fe4bcc9` |
| `docker/metadata-action` | v5 | `c299e40c65443455700f0fdfc63efafe5b349051` |
| `docker/build-push-action` | v7.4.0 | `c3c9e263c25d99ce0380d002d59b67737d91b0dc` |
| `github/codeql-action/upload-sarif` | v3 | `ce5e7eeac396d720fe2d802714996c8ce561e311` |
| `github/codeql-action/init` | v3 | `ce5e7eeac396d720fe2d802714996c8ce561e311` |
| `github/codeql-action/analyze` | v3 | `ce5e7eeac396d720fe2d802714996c8ce561e311` |
| `aquasecurity/trivy-action` | v0.36.0 | `ed142fd0673e97e23eac54620cfb913e5ce36c25` |
| `actions/attest-build-provenance` | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |

## Engine

`engine.version` is `13.0.0`. The installer downloads

`https://github.com/dependency-check/DependencyCheck/releases/download/v13.0.0/dependency-check-13.0.0-release.zip`

and the sibling `.asc`. The public key is stored in this repository at
`scripts/keys/dependency-check-release.asc`. `scripts/install-engine.sh`,
`scripts/setup.sh` (Linux and macOS, including `curl | bash`), and
`scripts/setup.ps1` (Windows) refuse the key unless its fingerprint is
`259A55407DD6C00299E6607EFFDE55BE73A2D1ED`. A missing `gpg` refuses the
install. The zip is extracted with `archive.py` only after the signature
verifies. The Windows script was not executed in this workspace (`pwsh` is
not installed). The Linux script was.

That fingerprint was taken from the Ubuntu keyserver copy of Jeremy Long's
key (`Jeremy Long <jeremy.long@gmail.com>`), not from a checksum published
beside the zip. On 19 October 2026 the v13.0.0 zip from that GitHub release
verified with this key (`gpg: Good signature`). GnuPG also reported that the
key is not certified in the local web of trust. The pin is the check this
repository can make. It is not a claim of a broader trust path.

The release also publishes `dependency-check-13.0.0-release.zip.asc` and a
Maven `buildinfo`. The buildinfo was not used as an independent checksum.

Tests cover a bad version file, a failed download, a signature that does not
verify, a signed archive whose binary reports another version, a signed
archive with no `dependency-check.sh`, a signed archive that path-escapes,
and a signed archive that reports the requested version. They use a test key.
They do not download the upstream zip.

## Source SBOM

`python3 scripts/write-sbom.py build/checkstead-sbom.cdx.json` writes a
CycloneDX 1.5 document for this checkout: Checkstead, the installed `certifi`,
and the engine pin. It is not an image SBOM and it does not say the image
was signed.

`bash scripts/check-release.sh` runs the release unit tests, writes that
SBOM, and prints `checkstead doctor`. It does not create a GitHub release or
push an image.

## Image provenance

`publish-images` runs on the default branch and on `v*` tags. It does not
run on a pull request. The pull-request job sets `provenance: false`,
`push: false`, and `contents: read`.

The publish job sets BuildKit `provenance: true` and `sbom: true`, then runs
`actions/attest-build-provenance` on the pushed digest with
`push-to-registry: true`. That input is not the action default. Without it,
the statement is not attached to the image. `gh attestation verify` checks
the GitHub attestation for that same digest.

### Digests to verify

Use the index digests from commit `f3731b37f3033191eda7d6211de8e51f94dfc79f`,
publish run [39297714215](https://github.com/chethankumblekar/dependency-check-db-cache/actions/runs/39297714215).
`:latest` on that run is this pair. Do not move `:latest` back onto an older image.

```bash
gh attestation verify \
  oci://ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead@sha256:063cde562cec605672518f5951af861b512b8df08b7f2096b930b89bb92cb740 \
  --repo chethankumblekar/dependency-check-db-cache

gh attestation verify \
  oci://ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server@sha256:1a94da1ead8757e90d4df7ce4fff959f9319b1da617a4096c69186df0b301744 \
  --repo chethankumblekar/dependency-check-db-cache
```

Both commands exited 0 on 19 October 2026. Each statement is
`https://slsa.dev/provenance/v1`, signed by `.github/workflows/ci.yml` on
`refs/heads/main` for commit `f3731b3`. `python3 scripts/verify-published-images.py`
on the same two digests also exited 0. The registry indexes include
`https://spdx.dev/Document` and `https://slsa.dev/provenance/v1`. The server
index lists those predicates twice, once per platform.

The release candidate `v0.1.1-rc.1` is the same commit and a different build.
Its images are `checkstead@sha256:5e73042dd6b27baa4bbd541b8a7c00714676fb5d1e1bd0534301580a612c414f`
and `checkstead-server@sha256:df7ebe075c05a0e0a28d2452691c4260988dd924da097abe70627ae8f190b146`.
`gh attestation verify` and `scripts/verify-published-images.py` exited 0 on
both. That tag did not publish `latest` or a floating minor tag. The GitHub
release is a pre-release:
[v0.1.1-rc.1](https://github.com/chethankumblekar/dependency-check-db-cache/releases/tag/v0.1.1-rc.1).

The previous default-branch images, from commit `c5b1707` and run
[39288176898](https://github.com/chethankumblekar/dependency-check-db-cache/actions/runs/39288176898),
still verify: `checkstead@sha256:e361299c823f7f8b92a2463f9a4077adc281309c9ef6f66d012c6b913bfd2272`
and `checkstead-server@sha256:0ed118f344789cea7b5e4dc90dee219581fae5397fb4fc538def433341962cf7`.
They are not `:latest`.

The images from run
[39260814721](https://github.com/chethankumblekar/dependency-check-db-cache/actions/runs/39260814721)
(`checkstead@sha256:0a3dc8ca37960361af32b69d3fc5495568495b777a193793ac9dd79287ced4f6`
and `checkstead-server@sha256:5cace37da275c16fa02f60db1b3cb4b9c64202ee8aed480345f68d169c806361`)
have no GitHub attestation. `gh attestation verify` on those digests returned
HTTP 404. Do not republish them and do not point a current tag at them.
Their registry indexes do have BuildKit SPDX and SLSA predicates.
`scripts/verify-published-images.py` exited 3 for them. Exit 3 is not a pass.

`scripts/verify-published-images.py` exits 0 only when both the registry
predicates and `gh attestation verify` succeed. Pin the digest above. A
moving tag such as `latest` is not that pin.

## Permissions

Pull-request image builds have `contents: read` only. The publish job is the
one with `packages: write`, and only on the default branch or a `v*` tag.
Snapshot publishing stays in `update-snapshot.yml`, which is the only
workflow that reads `NVD_API_KEY`. The snapshot signing secret, when one
exists, is also limited to that workflow. It is not a key in this repository.
