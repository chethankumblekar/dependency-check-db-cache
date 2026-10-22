# Checkstead

Checkstead scans a repository with pinned OWASP Dependency-Check and a published database snapshot. The scan does not use an NVD API key and does not call `services.nvd.nist.gov`.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

Checkstead is not an OWASP project and does not speak for OWASP or NIST.

## Pipeline task

The task runs the Checkstead scanner image on a Linux agent that has Docker. It writes `checkstead-report/` in the sources directory.

```yaml
- task: ChecksteadScan@0
  inputs:
    scan: .
    project: $(Build.Repository.Name)
```

## Pull requests

[`pull-request.yml`](https://github.com/chethankumblekar/dependency-check-db-cache/blob/main/integrations/azure-devops/pull-request.yml) scans an Azure Repos pull request against its target branch and keeps one Checkstead thread on it. Run it as a Build validation branch policy. The build service needs "Contribute to pull requests" on the repository.

No branch policy? [`pr-ci.yml`](https://github.com/chethankumblekar/dependency-check-db-cache/blob/main/integrations/azure-devops/pr-ci.yml) runs on a push, finds the branch's active pull request, comments, and posts a `checkstead/score-policy` status.

## Marketplace

The extension is public. An organization that already uses Azure Pipelines installs it from the Visual Studio Marketplace. The publisher does not need an Azure DevOps organization.

The task does not take an NVD API key. Set `NVD_API_KEY` only on the Checkstead repository that publishes the snapshot.
