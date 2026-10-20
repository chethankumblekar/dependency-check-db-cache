# Security gates

A gate fails the job. A report records findings and does not fail the job.
Nothing in this repository uses `continue-on-error` to turn a failed gate into
a green check. There is no `.trivyignore`. A CVE is not suppressed to make a
build green.

The image gate policy lives in one file, `scripts/image-gates.sh`. Pull
requests, the publish job, and the local `scripts/scan-images.sh` all call it,
so they cannot drift apart. Trivy is pinned to one release (`TRIVY_VERSION` in
`.github/workflows/ci.yml`, installed by `aquasecurity/setup-trivy` at a commit
SHA).

## Pull request

| Check | Result when it fails | Where |
| --- | --- | --- |
| Ruff, unit tests, wheel, Maven plugin | The `test` job fails | `bash scripts/self-test.sh` |
| High or Critical language packages, both images, including the Dependency-Check engine | The image job fails | `image-gates.sh`: `--pkg-types library --severity CRITICAL,HIGH --exit-code 1`, no skipped path |
| Fixed High or Critical operating-system packages, both images | The image job fails | `image-gates.sh`: `--pkg-types os --ignore-unfixed --exit-code 1` |
| Full High and Critical report and a CycloneDX SBOM per image | Report only, uploaded as `trivy-<image>` | `image-gates.sh` writes `*-report.json` and `*-sbom.cdx.json` |
| Image behaviour | The image job fails | `scripts/smoke-image.sh`: engine pin, non-root uid, offline scan refused (scanner); uid 999, no capabilities, read-only root, healthy, foreign `Host` refused, history needs a session (server) |
| Image push | Does not run on a pull request | `images` job has `push: false` and `contents: read` only |
| CodeQL | The `Analyze` job fails, and the main ruleset rejects the merge when a High alert or an error alert is open | `.github/workflows/codeql.yml` |

Language packages are dependencies this repository chooses, and since
20 October 2026 that includes the jars inside the pinned Dependency-Check
release. Upstream 13.0.0 ships Jackson 2.22.1 and jsoup 1.23.1 with six High
CVEs and no newer release exists. `scripts/install-engine.sh` replaces those
three jars with the fixed patch releases from Maven Central, each pinned by
SHA-256 in `scripts/engine-overrides.txt`, after the upstream signature
verifies. The earlier `--skip-dirs /opt/dependency-check` exception is
removed: a new engine CVE now fails the gate until it gets an override or a
dated exception in this file.

Operating-system findings are the base image. Fixed High and Critical
findings fail so a base-image bump can clear them. Unfixed operating-system
findings do not fail the job (exception below). They stay in the report.

## Push to the default branch and version tags

`publish-images` runs only when the event is not a pull request and the ref
is the default branch or a `v*` tag. In order, it:

1. Builds and pushes only the immutable tag `sha-<commit>`, with BuildKit
   `provenance: mode=max` and `sbom: true`. A version tag build uses
   `no-cache`, so nothing a branch build left in the layer cache reaches a
   release image.
2. Runs `image-gates.sh` against the pushed digest
   (`image@sha256:...`) for every platform in the index
   (`linux/amd64,linux/arm64` for the server). This is the exact artifact the
   tags will name.
3. Uploads the reports and SBOMs as `trivy-<image>-<commit>`.
4. Attests build provenance for that digest with
   `actions/attest-build-provenance` (`push-to-registry: true`) and verifies it
   with `gh attestation verify`.
5. Only then moves `latest`, the version tags, the branch tag, and
   `engine-<pin>` to the same digest with `docker buildx imagetools create`,
   and checks that every tag resolves to that digest.

A failed gate or a failed attestation stops the job before step 5, so a
floating tag never names an image that did not pass. The `sha-` candidate tag
stays in the registry for investigation.

## Snapshot publish

`update-snapshot.yml` is the only scheduled database publisher. It has
`contents: write` because it creates a GitHub release. It is the only
workflow that receives `NVD_API_KEY` and `CHECKSTEAD_SNAPSHOT_SIGNING_KEY`.
The concurrency group `checkstead-snapshot` does not cancel an in-progress
run. The script refuses to publish when the zip is empty, the manifest
checksum does not match, or a configured signing key does not match its
pinned public key or is retired. The seed it updates from is verified the way
a scan verifies a snapshot (checksum, and the signature when a key is pinned);
a seed that fails is discarded and the database is rebuilt from the NVD.

## Exceptions

There is no `.trivyignore` in this repository. A future exception needs a CVE
id, the image or package it applies to, why it cannot be fixed, and a review
date, in this file and in the pull request. Do not add a Checkstead
suppression file to clear a finding in Checkstead's own dependencies.

Exception `unfixed-os-2026-10-19` is the operating-system gate's
`--ignore-unfixed`. It is written next to that command in
`scripts/image-gates.sh`.

| Field | Value |
| --- | --- |
| Findings | Unfixed operating-system packages. On `checkstead-server@sha256:1a94da1ead8757e90d4df7ce4fff959f9319b1da617a4096c69186df0b301744` this was 61 High findings and 2 Critical findings: `CVE-2025-7458` in `libsqlite3-0` (status `affected`, no fixed version) and `CVE-2023-45853` in `zlib1g` (status `will_not_fix`, no fixed version). |
| Scope | Server and scanner image OS packages that have no fixed version. A fixed High or Critical OS package still fails the job. |
| Why it cannot be fixed here | The distribution has not published a fixed version. Failing the job would not point at a package upgrade. |
| Review | 2027-01-19. If a fixed version appears before then, the gate fails on it. |

On 20 October 2026 the images built from this change had no High or Critical
finding at all, fixed or unfixed, in the Trivy v0.70.0 report (server on
`python:3.14-slim-bookworm@sha256:48b13b00…`, scanner on
`eclipse-temurin:25-jre-noble@sha256:3f2223fe…` with the engine overrides).
Those were local arm64 builds. The amd64 images CI builds have not been
scanned yet. The exception is kept because unfixed findings come and go with
the vulnerability database.

The engine-jar exception recorded on 19 October 2026 (six High findings in
Jackson 2.22.1 and jsoup 1.23.1) is closed by the overrides above.

`scripts/rollback-image.sh` pulls one image by digest. It refuses a reference
that names `:latest` or that is not `image@sha256:<64 hex>`. It does not tag
`:latest` and it does not push.

## Local commands

```bash
bash scripts/self-test.sh
bash scripts/check-release.sh
bash scripts/scan-images.sh
bash scripts/smoke-image.sh server checkstead-server:local
```

`scan-images.sh`, `image-gates.sh`, and `smoke-image.sh` exit 2 when
`docker` or `trivy` is not installed. That exit code means the check did not
run. It is not a pass.
