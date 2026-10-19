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

On a push, `publish-images` sets `provenance: true` and `sbom: true`. GitHub
Actions will attach a build provenance attestation and an image SBOM when
that job runs. Pull requests set `provenance: false` and `push: false`.

This change does not push an image and does not verify an attestation. Do
not describe the images as signed on the strength of this document. After a
later publish, record the image digest:

```bash
docker buildx imagetools inspect ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:sha-<commit>
```

## Permissions

Pull-request image builds have `contents: read` only. The publish job is the
one with `packages: write`. Snapshot publishing stays in
`update-snapshot.yml`, which is the only workflow that reads `NVD_API_KEY`.
