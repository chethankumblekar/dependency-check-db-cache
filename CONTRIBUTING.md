# Contributing

Checkstead is licensed under the Apache License, Version 2.0. Contributors keep
their copyright. Inbound contributions are licensed the same way. There is no
copyright assignment.

The community standard is [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report a
vulnerability through [SECURITY.md](SECURITY.md), not through a public issue.

## Developer Certificate of Origin

Commits use the Developer Certificate of Origin. Add a `Signed-off-by` line with
`git commit -s`. By doing so you certify that you can submit the change under
the project license:

```text
Signed-off-by: Your Name <your.email@example.com>
```

## What to change

Defects and ideas are public issues. A pull request should keep the current
product: one pinned Dependency-Check release, one snapshot, and scans that do
not call `services.nvd.nist.gov`.

A private suppression file is not a contribution. Do not open a pull request
that publishes one. `privateSuppressions` stays optional. Do not add a
suppression file that a scan requires.

A public suppression rule needs a reason a stranger can verify, an owner, and
an end date. Do not add one without that confirmation. Checkstead does not ship
a confirmed public rule in this version.

Questions about a CVE score, a CPE match, or NVD enrichment belong with NVD,
the CVE Numbering Authority, or the analyzer that produced them.

## Develop

From a checkout:

```bash
python3 -m pip install '.[dev]'
bash scripts/self-test.sh
```

That is the lint, package build, unit tests, and Maven plugin tests that CI
runs. The tests publish no database and do not call the NVD. See the Develop
section of [README.md](README.md).

`bash scripts/check-release.sh` checks the release contract and writes a source
SBOM without publishing. Image scans need Docker and Trivy, which
`bash scripts/scan-images.sh` refuses to pretend it ran when those tools are
absent.

GitHub Actions are pinned to commit SHAs. The comment on the `uses` line is the
release tag. Update a pin with `gh api repos/<owner>/<name>/commits/<tag> --jq .sha`,
and change the SHA and the comment together. Dependabot opens weekly update
requests for pip, GitHub Actions, Docker, and the Maven plugin.

## Pull requests

Describe what changed and how you checked it. Use the pull request template.
Keep commits signed off. The maintainer is Chethan K
([@chethankumblekar](https://github.com/chethankumblekar)).
