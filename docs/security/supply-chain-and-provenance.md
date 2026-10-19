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

Pins recorded with this change:

| Action | Tag | Commit |
| --- | --- | --- |
| `actions/checkout` | v5 | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` |
| `actions/setup-python` | v5 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/setup-java` | v5 | `b6effb05e454b25005698d916606bdc6ffcbf961` |
| `actions/setup-node` | v4 | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `actions/upload-artifact` | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `docker/setup-qemu-action` | v3 | `c7c53464625b32c7a7e944ae62b3e17d2b600130` |
| `docker/setup-buildx-action` | v3 | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` |
| `docker/login-action` | v3 | `c94ce9fb468520275223c153574b00df6fe4bcc9` |
| `docker/metadata-action` | v5 | `c299e40c65443455700f0fdfc63efafe5b349051` |
| `docker/build-push-action` | v6 | `10e90e3645eae34f1e60eeb005ba3a3d33f178e8` |
| `github/codeql-action/upload-sarif` | v3 | `ce5e7eeac396d720fe2d802714996c8ce561e311` |
| `aquasecurity/trivy-action` | v0.36.0 | `ed142fd0673e97e23eac54620cfb913e5ce36c25` |
| `actions/attest-build-provenance` | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |

## Engine

`engine.version` is `13.0.0`. The installer downloads

`https://github.com/dependency-check/DependencyCheck/releases/download/v13.0.0/dependency-check-13.0.0-release.zip`

and the sibling `.asc`. The public key is stored in this repository at
`scripts/keys/dependency-check-release.asc`. Install refuses the key unless
its fingerprint is `259A55407DD6C00299E6607EFFDE55BE73A2D1ED`.

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
`actions/attest-build-provenance` on the pushed digest. That second step is
what `gh attestation verify` checks. It has not run yet for the images below.
Do not describe those images as verified by GitHub's attestation API.

### What was checked on 19 October 2026

CI run [39260814721](https://github.com/chethankumblekar/dependency-check-db-cache/actions/runs/39260814721)
published commit `b4606799145963d99f9837dbea953cf6dd3b77ae`. The registry
accepted an anonymous pull. These commands were run from this workspace:

```bash
# Index digest recorded by that publish job.
# checkstead        sha256:0a3dc8ca37960361af32b69d3fc5495568495b777a193793ac9dd79287ced4f6
# checkstead-server sha256:5cace37da275c16fa02f60db1b3cb4b9c64202ee8aed480345f68d169c806361

gh attestation verify \
  oci://ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead@sha256:0a3dc8ca37960361af32b69d3fc5495568495b777a193793ac9dd79287ced4f6 \
  --repo chethankumblekar/dependency-check-db-cache

gh attestation verify \
  oci://ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server@sha256:5cace37da275c16fa02f60db1b3cb4b9c64202ee8aed480345f68d169c806361 \
  --repo chethankumblekar/dependency-check-db-cache

python3 scripts/verify-published-images.py \
  ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead@sha256:0a3dc8ca37960361af32b69d3fc5495568495b777a193793ac9dd79287ced4f6 \
  ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server@sha256:5cace37da275c16fa02f60db1b3cb4b9c64202ee8aed480345f68d169c806361
```

`gh attestation verify` returned HTTP 404 for both digests. The GitHub
attestation API has no statement for them. That check did not pass.

The same indexes do contain BuildKit attestation manifests. Reading the
registry blobs showed:

| Image index | Attached in-toto predicate types |
| --- | --- |
| `checkstead` `sha256:0a3dc8ca37960361af32b69d3fc5495568495b777a193793ac9dd79287ced4f6` | `https://spdx.dev/Document`, `https://slsa.dev/provenance/v1` |
| `checkstead-server` `sha256:5cace37da275c16fa02f60db1b3cb4b9c64202ee8aed480345f68d169c806361` | The same two predicate types, once for `linux/amd64` and once for `linux/arm64` |

`python3 scripts/verify-published-images.py` on both digests exited 3. Each
`gh attestation verify` exited 1 with HTTP 404. Exit 3 is not a pass.

`scripts/verify-published-images.py` exits 0 only when both the registry
predicates and `gh attestation verify` succeed. Exit 3 means the registry
predicates are present and the GitHub API check did not succeed. Record the
exit code. Do not call exit 3 a pass.

After the next default-branch publish, the new digest should verify with:

```bash
gh attestation verify \
  "oci://ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead@sha256:<digest>" \
  --repo chethankumblekar/dependency-check-db-cache
```

The signer workflow for that statement is the reusable
`actions/attest-build-provenance` workflow, not `ci.yml` by itself. Pin the
digest from the publish log. A moving tag such as `latest` is not that pin.

## Permissions

Pull-request image builds have `contents: read` only. The publish job is the
one with `packages: write`, and only on the default branch or a `v*` tag.
Snapshot publishing stays in `update-snapshot.yml`, which is the only
workflow that reads `NVD_API_KEY`. The snapshot signing secret, when one
exists, is also limited to that workflow. It is not a key in this repository.
