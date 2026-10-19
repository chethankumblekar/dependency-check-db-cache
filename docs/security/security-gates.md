# Security gates

A gate fails the job. A report records findings and does not fail the job.
Nothing in this repository uses `continue-on-error` to turn a failed gate into
a green check.

## Pull request

| Check | Result when it fails | Where |
| --- | --- | --- |
| Ruff, unit tests, wheel, Maven plugin | The `test` job fails | `bash scripts/self-test.sh` |
| Server image, Critical vulnerabilities in language packages | The image job fails | Trivy `vuln-type: library`, `severity: CRITICAL`, `exit-code: "1"` |
| Scanner image vulnerabilities | Report only. The artifact is `trivy-scanner` | Trivy `exit-code: "0"` |
| Image push | Does not run on a pull request | `images` job has `push: false` and no `packages: write` |

The server gate is Critical language packages in the image Checkstead builds
(the timeline and `certifi`). It does not fail on operating-system packages in
the base image. Those are not in this gate because they were not baselined
here. They are also not hidden: the scanner-image job is a separate report,
and `scripts/scan-images.sh` writes both results locally.

The scanner image contains the pinned Dependency-Check distribution. Failing
the build on a Critical jar inside that distribution would require changing
`engine.version` or carrying a suppression. This repository does not do either
to make the check green. The report is the record until someone reviews it
and decides which upstream findings block a publish.

## Push and workflow dispatch

The `publish-images` job runs only when the event is not a pull request. It
has `packages: write`, `id-token: write`, and `attestations: write`. It pushes
the tags and sets `provenance: true` and `sbom: true` on the build. Those
attestations are produced by that job. This change does not push an image, so
those attestations are not verified here.

## Snapshot publish

`update-snapshot.yml` is the only scheduled database publisher. It has
`contents: write` because it creates a GitHub release. The concurrency group
`checkstead-snapshot` does not cancel an in-progress run. The script exits
before NVD when `db-YYYY-MM-DD` already exists, and it exits before
`gh release create` when the zip is empty or the manifest checksum does not
match.

## Exceptions

There is no `.trivyignore` in this repository. A future exception needs a CVE
id, the image or package it applies to, and a reason in the pull request.
Do not add a Checkstead suppression file to clear a finding in Checkstead's
own dependencies.

## Local commands

```bash
bash scripts/self-test.sh
bash scripts/check-release.sh
bash scripts/scan-images.sh
```

`scan-images.sh` exits 2 when `docker` or `trivy` is not installed. That exit
code means the scan did not run. It is not a pass.
