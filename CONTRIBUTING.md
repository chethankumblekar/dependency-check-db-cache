# Contributing

Checkstead is licensed under the Apache License, Version 2.0. Contributors keep
their copyright. Inbound contributions are licensed the same way. There is no
copyright assignment.

Commits use the Developer Certificate of Origin. Add a `Signed-off-by` line with
`git commit -s`. By doing so you certify that you can submit the change under
the project license.

Defects and ideas are public issues. A private suppression file is not a
contribution. Do not open a pull request that publishes one.

A public suppression rule needs a reason a stranger can verify, an owner, and an end date. Do not add one without that confirmation.

## Tests

```bash
python3 -m pip install ruff==0.14.2 build==1.3.0 certifi
bash scripts/self-test.sh
```

The suite does not call the NVD and does not publish a release or an image.
`bash scripts/check-release.sh` checks the release contract and writes a source
SBOM without publishing. Image scans need Docker and Trivy, which
`bash scripts/scan-images.sh` refuses to pretend it ran when those tools are
absent.

GitHub Actions are pinned to commit SHAs. The comment on the `uses` line is the
release tag. Update a pin with `gh api repos/<owner>/<name>/commits/<tag> --jq .sha`,
and change the SHA and the comment together. Dependabot opens weekly update
requests for pip, GitHub Actions, Docker, and the Maven plugin.
