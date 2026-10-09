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

The extension is public. An organization that already uses Azure Pipelines installs it from the Visual Studio Marketplace. The publisher does not need an Azure DevOps organization.

The task does not take an NVD API key. Set `NVD_API_KEY` only on the Checkstead repository that publishes the snapshot.
