# Security gates

A gate fails the job. A report records findings and does not fail the job.
Nothing in this repository uses `continue-on-error` to turn a failed gate into
a green check. There is no `.trivyignore`. A CVE is not suppressed to make a
build green.

## Pull request

| Check | Result when it fails | Where |
| --- | --- | --- |
| Ruff, unit tests, wheel, Maven plugin | The `test` job fails | `bash scripts/self-test.sh` |
| Server image, High or Critical language packages | The image job fails | Trivy `vuln-type: library`, `severity: CRITICAL,HIGH`, `ignore-unfixed: false`, `exit-code: "1"` |
| Server image, fixed Critical operating-system packages | The image job fails | Trivy `vuln-type: os`, `severity: CRITICAL`, `ignore-unfixed: true`, `exit-code: "1"` |
| Scanner image, High or Critical language packages outside `/opt/dependency-check` | The image job fails | Trivy `skip-dirs: /opt/dependency-check`, `vuln-type: library`, `severity: CRITICAL,HIGH`, `exit-code: "1"` |
| Scanner image, fixed Critical operating-system packages | The image job fails | Trivy `vuln-type: os`, `severity: CRITICAL`, `ignore-unfixed: true`, `exit-code: "1"` |
| Scanner image, including Dependency-Check jars | Report only. The artifact is `trivy-scanner` | Trivy `exit-code: "0"`, `severity: CRITICAL,HIGH` |
| Image push | Does not run on a pull request | `images` job has `push: false` and `contents: read` only |

Language packages are dependencies this repository chooses (`certifi` and the
image's Python packages). High and Critical findings fail, including unfixed
ones, because an upgrade may be available and hiding them would not be a
review.

Operating-system findings are the base image. Fixed Critical findings fail so
a base-image bump can clear them. Unfixed Critical and High operating-system
findings do not fail the job: there is no patch to take, and a suppression
file would only hide that. They still appear in the scanner report artifact.

`/opt/dependency-check` is the pinned engine distribution. Failing the build
on a jar inside it would mean changing `engine.version` or carrying a
suppression. This repository does not do either to make the check green. The
report is the record. The skip is limited to that directory and to the
failing language-package scan. It is not a CVE id exception.

`scripts/scan-images.sh` runs the same gates locally. It exits 2 when
`docker` or `trivy` is not installed. That exit means the scan did not run.
On 19 October 2026 that local command exited 2. The same gates then ran in
pull request
[39263737597](https://github.com/chethankumblekar/dependency-check-db-cache/actions/runs/39263737597)
and the image jobs succeeded.

Pull-request runs set `cancel-in-progress` so a newer push replaces the
previous one. A push to the default branch, including image publish, does not
cancel an in-progress run.

Action `uses` lines are commit SHAs. The unit test checks the pin format and
that both image jobs share one `docker/build-push-action` SHA. It does not
copy a SHA into the test, so a reviewed Dependabot update of qemu, CodeQL
upload-sarif, ruff, or build does not fail for a stale hardcoded pin. Ruff
and build versions are the pins in `pyproject.toml`. CI installs `.[dev]`.

## Push and workflow dispatch

`publish-images` runs only when the event is not a pull request and the ref
is the default branch or a `v*` tag. It has `packages: write`,
`id-token: write`, and `attestations: write`. It pushes the tags, sets
`provenance: true` and `sbom: true` on the BuildKit build, and then runs
`actions/attest-build-provenance` with `push-to-registry: true` so
`gh attestation verify` can check the digest. The action defaults that input
to false, which does not attach the statement to the image. The verify step
in that job has not run for this change, because a pull request does not
publish.

BuildKit attestations on the image index are a different store from GitHub's
attestation API. Both are described in
[Supply chain and provenance](supply-chain-and-provenance.md).

## Snapshot publish

`update-snapshot.yml` is the only scheduled database publisher. It has
`contents: write` because it creates a GitHub release. It is the only
workflow that receives `NVD_API_KEY` and, when the maintainer has created
them, `CHECKSTEAD_SNAPSHOT_SIGNING_KEY`. The concurrency group
`checkstead-snapshot` does not cancel an in-progress run. The script exits
before NVD when `db-YYYY-MM-DD` already exists, and it exits before
`gh release create` when the zip is empty, the manifest checksum does not
match, or a configured signing key does not match a current pinned public
key.

## Exceptions

There is no `.trivyignore` in this repository. A future exception needs a CVE
id, the image or package it applies to, why it cannot be fixed, and a review
in the pull request. Do not add a Checkstead suppression file to clear a
finding in Checkstead's own dependencies.

The Dependency-Check directory skip above is the only standing exception. It
is scoped to `/opt/dependency-check` and it does not hide the findings from
the report artifact.

## Local commands

```bash
bash scripts/self-test.sh
bash scripts/check-release.sh
bash scripts/scan-images.sh
```

`scan-images.sh` exits 2 when `docker` or `trivy` is not installed. That exit
code means the scan did not run. It is not a pass.
