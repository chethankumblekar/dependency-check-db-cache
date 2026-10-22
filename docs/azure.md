# Checkstead on Azure

Ubuntu and Windows both scan with Checkstead. The timeline server is a Linux container on Azure App Service. A build copies each report folder onto the directory that server reads, or sends it with `checkstead upload`.

For Azure Repos pull requests, upload tokens, the **Repositories** page, and sign-in, start with [Checkstead with Azure DevOps](azure-devops.md). This page has the platform steps.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

A scan does not use an NVD API key and does not call `services.nvd.nist.gov`.

The Marketplace extension is not published yet. There is no `v0.1.0` release. The pipelines below run the scan without that extension. When the listing exists, an organization admin chooses **Get it free** and can switch the Ubuntu job to `ChecksteadScan@0`.

## Scan on Ubuntu

One command. No sudo. Python, Java, and Dependency-Check that already run stay in place.

```bash
curl -fsSL https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.sh | bash
```

Open a new terminal. The working directory can be any directory.

```bash
checkstead scan --scan . --project my-service
checkstead ui
```

Reports are written to `checkstead-report/`. The local timeline listens on http://127.0.0.1:8765/.

## Scan on Windows

In PowerShell. No administrator rights. Python, Java, and Dependency-Check that already run stay in place.

```powershell
irm https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.ps1 | iex
```

Open a new terminal. The working directory can be any directory. `checkstead.cmd` is on the user PATH.

```powershell
checkstead scan --scan . --project my-service
checkstead ui
```

Reports are written to `checkstead-report/`. The local timeline listens on http://127.0.0.1:8765/.

## Score policy and suppressions

Put `checkstead.yml` in the project you scan. The score policy is `prefer-newest` unless that file sets `highest`. `prefer-newest` uses an NVD score when the report has one, otherwise a CNA score, otherwise another analyzer in the report. The newer CVSS version from that source is the one that counts. `highest` uses the largest base score from any source. The report names the version, the score, and the source.

`privateSuppressions` is optional. Omit it, leave it blank, or name a file that is missing or empty, and the scan runs with no private rules.

## App Service

The server image is Linux. Create a Linux Web App for Containers whether you work from Ubuntu or Windows.

1. Create a storage account and a file share named `checkstead`.
2. Create the Web App from `ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server:latest`. If the pull is denied, open that package on GitHub and set it to public.
3. Mount the file share at `/scans`.
4. Set these application settings:
   - `WEBSITES_PORT` = `8765`
   - `CHECKSTEAD_COOKIE_SECURE` = `1`
   - `CHECKSTEAD_ENTRA_CLIENT_ID` = the Entra application id
   - `CHECKSTEAD_ENTRA_CLIENT_SECRET` = the Entra client secret
   - `CHECKSTEAD_ENTRA_TENANT` = your tenant id
5. Set the startup command to:

```bash
checkstead ui --host 0.0.0.0 --port 8765 --scans /scans --data /var/lib/checkstead
```

The image entrypoint serves two sample scans baked into the image. This command points the timeline at the share. Accounts stay on the container disk and are created again when the container is replaced.

6. In Microsoft Entra, register an app. Add the redirect URI `https://<your-app>.azurewebsites.net/api/sso/entra/callback`.
7. Open `https://<your-app>.azurewebsites.net/`. Sign in with the work account. The first person to sign in is the administrator.

Give the pipeline identity **Storage File Data Privileged Contributor** on the storage account.

## Azure DevOps on Ubuntu

Use a Microsoft-hosted `ubuntu-latest` agent. It has Docker and can run the Linux scanner image.

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - script: |
      docker run --rm \
        --user "$(id -u):$(id -g)" \
        -v "$(Build.SourcesDirectory):/work" \
        -w /work \
        ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:latest \
        scan \
        --scan . \
        --project "$(Build.Repository.Name)" \
        --revision "$(Build.SourceVersion)" \
        --out checkstead-report
    displayName: Checkstead scan

  - publish: checkstead-report
    artifact: checkstead-report
    displayName: Keep the report on the build
    condition: succeededOrFailed()

  - task: AzureCLI@2
    displayName: Copy the report to the timeline
    condition: succeededOrFailed()
    inputs:
      azureSubscription: checkstead-azure
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: |
        az storage file upload-batch \
          --account-name <storage-account> \
          --auth-mode login \
          --enable-file-backup-request-intent \
          --source "$(Build.SourcesDirectory)/checkstead-report" \
          --destination checkstead \
          --destination-path "$(Build.BuildId)"
```

Replace `<storage-account>` and `checkstead-azure` with your storage account and service connection.

After the extension is published, the scan step on this Ubuntu agent can be:

```yaml
- task: ChecksteadScan@0
  inputs:
    scan: .
    project: $(Build.Repository.Name)
    output: checkstead-report
    image: ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:latest
```

That task requires Docker. It does not pass `--revision`, so the timeline names the commit only when the Docker step above is the one that scans.

## Azure Repos pull requests

[`integrations/azure-devops/pull-request.yml`](../integrations/azure-devops/pull-request.yml) scans the pull request head and the target branch with the same snapshot. Only findings the pull request adds count against the score policy. It then writes one Checkstead thread on the pull request and updates that thread on later pushes.

1. Create a pipeline from that file in the repository.
2. Add it as a **Build validation** branch policy on the target branch.
3. Give the project build service **Contribute to pull requests** on the repository.

The comment step maps `System.AccessToken` into the step as `SYSTEM_ACCESSTOKEN`. It reads nothing else for a token. Outside a pull request build, or without that mapping, it does nothing. The thread is created closed, so a "check for comment resolution" policy does not block completion. The score policy is what fails the build.

The comment script ships in the scanner image as `/usr/local/bin/checkstead-ado-comment`. An image built before it was added does not have it.

### Without a branch policy

Use [`integrations/azure-devops/pr-ci.yml`](../integrations/azure-devops/pr-ci.yml) when you cannot or do not want to add a Build validation policy. A push to a branch runs it on the CI trigger.

- `checkstead-ado-comment --find` looks up the active pull request whose source is the pushed branch. It sets `CHECKSTEAD_PR_ID` and `CHECKSTEAD_PR_TARGET`.
- With a pull request, the scan compares the push with that pull request's target branch. The comment step keeps the one thread and posts a `checkstead/score-policy` status. The status is `succeeded` or `failed` from `Agent.JobStatus` and links to the build.
- With no active pull request, the branch is scanned alone. Nothing is posted.

The status shows on the pull request but does not block completion. To make it required, add a **Status check** policy for `checkstead/score-policy`. A push made before the pull request was opened has no pull request to comment on. The next push does.

The build service needs **Contribute to pull requests** on the repository, the same as the policy pipeline.

## Azure DevOps on Windows

Use a Microsoft-hosted `windows-latest` agent and the PowerShell setup. That agent runs Windows containers, and the Checkstead scanner image is Linux, so this job does not call Docker.

```yaml
trigger:
  - main

pool:
  vmImage: windows-latest

steps:
  - powershell: |
      irm https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.ps1 | iex
      $env:Path = "$env:USERPROFILE\checkstead\bin;" + $env:Path
      checkstead scan --scan . --project "$(Build.Repository.Name)" --revision "$(Build.SourceVersion)" --out checkstead-report
    displayName: Checkstead scan

  - publish: checkstead-report
    artifact: checkstead-report
    displayName: Keep the report on the build
    condition: succeededOrFailed()

  - task: AzureCLI@2
    displayName: Copy the report to the timeline
    condition: succeededOrFailed()
    inputs:
      azureSubscription: checkstead-azure
      scriptType: ps
      scriptLocation: inlineScript
      inlineScript: |
        az storage file upload-batch `
          --account-name <storage-account> `
          --auth-mode login `
          --enable-file-backup-request-intent `
          --source "$(Build.SourcesDirectory)\checkstead-report" `
          --destination checkstead `
          --destination-path "$(Build.BuildId)"
```

A self-hosted Windows agent with Docker Desktop set to Linux containers can use the Ubuntu Docker step instead of `setup.ps1`.

## What the server shows

A score-policy failure exits 3 after the report is written. The build fails, and the copy step still runs because its condition is `succeededOrFailed()`.

Each build becomes one folder on the share: `/scans/<build id>/checkstead.txt` and `dependency-check-report.json`. The timeline lists only folders directly under `/scans`.

Refresh `https://<your-app>.azurewebsites.net/`. Each folder is a row. Open a row for the project, Dependency-Check 13.0.0, the snapshot time, and each finding’s version, score, and source. Two builds show the drift between them: dependencies and findings that arrived, left, or changed.

## Organization repositories and branches

The **Repositories** page lists repositories and branches by organization and project. Each branch shows its newest Checkstead result, with a link to the scan and to the pipeline run.

It works the way SonarQube works with Azure DevOps. The server never reads the organization. Each pipeline sends its report, and the report names the repository and the build:

1. An administrator opens **Access > Upload tokens** and creates a token. The token is shown once. The server keeps its hash, shows when it was last used, and can revoke it.
2. In the pipeline, store the token as the secret variable `CHECKSTEAD_UPLOAD_TOKEN`. Set the variable `CHECKSTEAD_SERVER` to the server origin, for example `https://checkstead.example`. A variable group shares both across pipelines.
3. Use [`pr-ci.yml`](../integrations/azure-devops/pr-ci.yml) or [`pull-request.yml`](../integrations/azure-devops/pull-request.yml). The scan step passes:
   - `--repository-url "$BUILD_REPOSITORY_URI"`. Any credentials in the URL, such as `https://Ascertra@dev.azure.com/...`, are dropped.
   - `--build-url`, built from the agent's variables.

   The **Send the report to Checkstead** step runs `checkstead upload`. That step does nothing when either variable is unset.

The organization, project, and repository come from the repository URL. Both `dev.azure.com/<org>/<project>/_git/<repo>` and `<org>.visualstudio.com/...` URLs are understood. A repository appears after its first upload, and a branch after its first scan. A scan without a repository URL, such as one from a laptop checkout, is listed under **Scans** only.

`POST /api/scans/upload` accepts a zip of the report folder, at most `CHECKSTEAD_MAX_UPLOAD_MB` (default 64). The server checks the upload token before it reads the body. It keeps only the files a scan writes, at the top level of the zip, and refuses anything else.

```bash
CHECKSTEAD_UPLOAD_TOKEN=cks_... checkstead upload --server https://checkstead.example --report checkstead-report
```

### Optional: list every branch with a service principal

Pipeline reports list the branches that were scanned. To list every repository and branch, including unscanned ones, the server can also read the organization as its own Microsoft Entra application:

1. An organization administrator opens **Organization settings > Users > Add users**. They search for the application by name, give it **Basic** access, and add it to each project to show as a **Reader**. Stakeholder access cannot read repositories.
2. Set these on the server:
   - `CHECKSTEAD_AZURE_DEVOPS_ORG`: the organization name, as in `dev.azure.com/<org>`.
   - `CHECKSTEAD_ENTRA_TENANT`: a tenant id. `organizations` cannot issue the application's own token.
   - `CHECKSTEAD_AZURE_DEVOPS_PROJECTS` (optional): a comma-separated list of project names. Empty means every project the application can read.
3. Restart the server. It prints `source Azure DevOps: <org>` and syncs once, then every `CHECKSTEAD_SYNC_MINUTES` (default 15). An administrator can press **Sync now**.

A sync reads three things:

- every repository, with its default branch;
- every branch, with its commit;
- recent runs of pipelines whose name matches `CHECKSTEAD_AZURE_DEVOPS_PIPELINES` (default `*checkstead*`).

**CI runs** shows those runs. A failed sync keeps the last good list and says why on the page. A service principal the organization does not know gets "is not a user in the … organization".

For a synced organization, a branch's result is the newest scan for it:

- the scan's project is the repository name, or `<project>/<repository>`;
- the scan's branch is that branch.

The pipeline examples set both from `Build.Repository.Name` and the branch. An organization that is both synced and reported is shown once, from the sync.

The result applies that scan's own score policy to all of its findings.

`checkstead doctor` prints the organization, the projects, and the sync interval, without secrets.

## Who can sign in

An administrator can add each person on **Access**. To skip that, let an Entra security group decide:

- `CHECKSTEAD_ENTRA_ALLOWED_GROUPS`: group object ids whose members sign in as members.
- `CHECKSTEAD_ENTRA_ADMIN_GROUPS`: group object ids whose members sign in as administrators. Joining an admin group promotes an existing member. Leaving it does not demote, so a group change cannot lock out the last administrator.

The app registration has to send the groups in the ID token:

```bash
az ad app update --id <application-id> --set groupMembershipClaims=SecurityGroup
```

Someone in more than 200 groups gets a link in place of the list. Checkstead does not follow it. That person sees "Microsoft Entra did not send your groups", and an administrator adds them on **Access**.
