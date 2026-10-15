# Checkstead

Checkstead runs [OWASP Dependency-Check](https://owasp.org/projects/dependency-check) once, the same way, for every build. One updater publishes a database snapshot. Scans use that snapshot. A scan does not use an NVD API key and does not call `services.nvd.nist.gov`.

[![CI](https://github.com/chethankumblekar/dependency-check-db-cache/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/chethankumblekar/dependency-check-db-cache/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Dependency-Check](https://img.shields.io/badge/Dependency--Check-13.0.0-blue.svg)](https://github.com/dependency-check/DependencyCheck/releases/tag/v13.0.0)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

This product uses data from the NVD API but is not endorsed or certified by the NVD.

Checkstead is not an OWASP project and does not speak for OWASP or NIST.

## Setup

One command. No sudo. Python, Java, and Dependency-Check that already run stay in place. The command works from any directory and puts `checkstead` on your user PATH.

macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.sh | bash
```

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.sh | bash
```

Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.ps1 | iex
```

Run the command for your system again when a finished scan still exits 14.

## Run

Open a new terminal. The working directory can be any directory. `checkstead scan` and `checkstead ui` do not have to be started from the install directory.

```bash
checkstead scan --scan . --project my-service
```

Reports are written to `checkstead-report/`. Checkstead reads `checkstead.yml` from the current directory. When that file is absent, it uses `checkstead.yml` beside the project you scan.

The score policy is `prefer-newest` unless that file sets `highest`. `prefer-newest` uses an NVD score when the report has one, otherwise a CNA score, otherwise another analyzer in the report. The newer CVSS version from that source is the one that counts. `highest` uses the largest base score from any source. The report names the version, the score, and the source.

`privateSuppressions` is optional. Omit it, leave it blank, or name a file that is missing or empty, and the scan runs with no private rules.

```bash
checkstead ui
```

The local server listens on http://127.0.0.1:8765/. Scans are read from `./ui/scans` when that directory exists, otherwise from the user install.

A project virtualenv has its own `checkstead`. Install into that environment, then run the same command:

```bash
python -m pip install --upgrade --force-reinstall --no-cache-dir https://github.com/chethankumblekar/dependency-check-db-cache/archive/refs/heads/main.tar.gz
checkstead scan --scan . --project my-service
```

| | |
| --- | --- |
| Name | Checkstead |
| Repository | [chethankumblekar/dependency-check-db-cache](https://github.com/chethankumblekar/dependency-check-db-cache) |
| Maintainer | Chethan K ([@chethankumblekar](https://github.com/chethankumblekar)) |
| License | [Apache-2.0](LICENSE) |
| Engine | OWASP Dependency-Check 13.0.0 |
| Version | 0.1.0 |

## GitHub

One command installs anything Checkstead still needs, then starts the local server. Python, Java, and Dependency-Check that are already present stay in place.

```bash
curl -fsSL https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/local.sh | bash
```

The server listens on http://127.0.0.1:8765/. Open http://127.0.0.1:8765/github.

github.com is the default. For GitHub Enterprise Server, set the API base before that command:

```bash
export CHECKSTEAD_GITHUB_API=https://github.example.com/api/v3
```

The website address is taken from that API URL. `https://api.github.com` uses `https://github.com`. A GitHub Enterprise Server API at `https://<host>/api/v3` uses `https://<host>`. Set `CHECKSTEAD_GITHUB_OAUTH` only when the website host differs from the host in the API URL.

A personal account or an organization owner connects GitHub from that page. The page has no token field. Choose **Personal account** or **Organization**. Checkstead creates the GitHub App, sends you to GitHub to approve the install, and stores the app id, private key, and client credentials GitHub returns. A personal account installs the app on that user and scans that user's repositories. An organization does the same for the organization.

1. Run the local server from any directory. When that directory contains `checkstead.yml`, these scans use its score policy. A scan of a project uses the `checkstead.yml` beside that project when the server's directory has none.
2. For GitHub Enterprise Server, export `CHECKSTEAD_GITHUB_API` first. Leave it unset for github.com.
3. Open http://127.0.0.1:8765/github.
4. Choose **Personal account** and type the user login, which is the GitHub username. For the account chethankumblekar, type `chethankumblekar`. Choose **Organization** and type the organization login when the account is an organization. Checkstead opens GitHub with the app filled in. Continue on that page. The app asks to read repository contents and metadata.
5. On the installation page, click **Install** to approve the app on that account. Checkstead stores the credentials GitHub returns and accepts the installation.
6. Scan from that page. Each repository is scanned with the current score policy. A private suppression file stays optional. The scan uses the published snapshot. The report is written into the server's scan directory and the timeline groups it by branch.

With no `checkstead.yml` in that directory, the policy is `prefer-newest`, with no score threshold and no private suppression file.

## Contents

- [Setup](#setup)
- [Run](#run)
- [GitHub](#github)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [What this release does](#what-this-release-does)
- [Pinned engine](#pinned-engine)
- [Scan](#scan)
- [What a scan still contacts](#what-a-scan-still-contacts)
- [The updater secret](#the-updater-secret)
- [Container images](#container-images)
- [Maven](#maven)
- [Gradle](#gradle)
- [GitHub Action](#github-action)
- [Azure DevOps](#azure-devops)
- [Azure on Ubuntu and Windows](docs/azure.md)
- [Release](#release)
- [Timeline](#timeline)
- [Server](#server)
- [Develop](#develop)
- [License and security](#license-and-security)

## Screenshots

On localhost, the first person uses **Sign in on this computer**. That button is enabled. GitHub and Microsoft stay inactive until their variables are set. An OAuth app only signs a person in. The GitHub App from `/github` reads and scans repositories. GitLab is not connected.

![Sign-in page. Sign in on this computer is enabled. GitHub and Microsoft are inactive.](docs/screenshots/sign-in.png)

The first scan on a branch is the scan view. This one records branch `main`. Each finding is one row: score, vulnerability id, package, direct or transitive, production or dev, and score source. The rows in each group are sorted by score, highest first. The description stays closed until the row is opened. Direct, transitive, production, and dev stay as groups, and the list can be narrowed to one relationship and one scope.

![Scan of billing on branch main. Findings are closed rows sorted by score.](docs/screenshots/scan.png)

The next scan on that branch is the drift. The branch is `main`. Guava moved from 31.1-jre to 32.1.3-jre, commons-text moved from 1.9 to 1.10.0, and gson arrived. The drift list says no findings were added or removed between the two scans. The same row list sits under that line.

![Drift on branch main. The finding rows stay under the dependency changes.](docs/screenshots/drift.png)

The first person to sign in is the administrator. Administration is where that person adds later accounts.

![Administration, with GitHub and Microsoft Entra accounts](docs/screenshots/administration.png)

## Architecture

A scan and the timeline server are separate. The scan never holds an NVD API key. The updater is the only job that talks to `services.nvd.nist.gov`.

```mermaid
flowchart TB
  subgraph daily [Once a day]
    secret[Repository secret NVD_API_KEY]
    updater[Update database snapshot]
    nvd[services.nvd.nist.gov]
    release["GitHub release db-YYYY-MM-DD"]
    secret --> updater
    updater --> nvd
    updater --> release
  end

  subgraph build [Every build]
    maven[Maven goal]
    gradle[Gradle task]
    action[GitHub Action]
    cli[checkstead scan]
    scanner[Scanner image]
    engine["Dependency-Check 13.0.0 with --noupdate"]
    maven --> cli
    gradle --> cli
    action --> scanner
    scanner --> engine
    cli --> engine
    release --> engine
  end

  engine --> report[checkstead-report]

  subgraph portal [Timeline server]
    reports[Directories of scan reports]
    ui[Web UI]
    accounts[Account store]
    github[GitHub]
    entra[Microsoft Entra]
    azure[Azure DevOps]
    report --> reports --> ui
    github --> accounts
    entra --> accounts
    azure --> accounts
    accounts --> ui
  end
```

Pushing this repository runs [CI](.github/workflows/ci.yml). That workflow lints, builds, and tests. After those pass, it publishes the scanner image and the server image. A pull request builds the images and does not push them.

| Path | Role |
| --- | --- |
| `src/checkstead` | Scan client, account store, and timeline server |
| `engine.version` | The Dependency-Check pin |
| `checkstead.yml` | Snapshot URL, plus fields reserved for later |
| `Dockerfile` | Scanner image |
| `Dockerfile.server` | Timeline server image |
| `action.yml` | GitHub Action that runs the scanner image |
| `integrations/azure-devops` | Azure DevOps extension and pipeline task |
| `integrations/maven` | Maven goal that calls `checkstead scan` |
| `integrations/gradle` | Gradle task that calls `checkstead scan` |
| `ui/scans` | Two fixture scans for a checkout. They have no findings and no branch line. |
| `.github/workflows/ci.yml` | Lint, test, build, and image publish |
| `.github/workflows/update-snapshot.yml` | Daily snapshot |

## What this release does

| In this release | Later |
| --- | --- |
| Pinned scan, checksummed snapshot, `--noupdate` | Public suppression rules confirmed by more than one user |
| Named score policy, threshold, KEV flag, and a no-score line | |
| Private suppression file, kept local | |
| Timeline of scans and the drift between them | Suppression and false-positive records |
| Git author on a scan when that commit is in the tree | |
| Server accounts: GitHub, Microsoft Entra, Azure DevOps | GitLab and other Git hosts |

`scorePolicy` chooses the one score a finding is judged on. `threshold` fails the build when that score is at or above the number. An empty threshold does not fail on score. `failOnKev` fails on a CISA KEV finding even when the score is below the threshold. `failUnscored` fails when a finding has no score. `privateSuppressions` is a local file passed to the engine. A URL is refused, and the file is not published. The timeline does not invent suppression or false-positive records.

## Pinned engine

The pin is Dependency-Check **13.0.0**, the current upstream release on 6 October 2026 ([v13.0.0](https://github.com/dependency-check/DependencyCheck/releases/tag/v13.0.0), published 3 August 2026). Release 12.2.2 changed the database schema, so a database built by an older engine is not usable here. The pin is the single line in [`engine.version`](engine.version). Move it when upstream changes behavior or the database schema.

A snapshot manifest names the engine that built it. If that version is not the pin, the scan stops and does not run Dependency-Check.

## Scan

[Setup](#setup) installs only what is missing, without sudo, under `$HOME/checkstead`. [Run](#run) is the scan. The first scan downloads the published snapshot. Setup does not call the NVD and does not ship a database.

From a checkout, the same script is `bash scripts/setup.sh`. `checkstead version` prints `13.0.0`.

Put [`checkstead.yml`](checkstead.yml) in the project you scan, or use the copy in this repository.

```yaml
snapshot: https://github.com/chethankumblekar/dependency-check-db-cache/releases/latest/download/manifest.json
scorePolicy: prefer-newest
threshold: 7
failOnKev: false
failUnscored: false
privateSuppressions:
```

`snapshot` is the manifest URL. `releases/latest` on this repository is the Checkstead snapshot, the release that contains `manifest.json`. The daily updater publishes `db-YYYY-MM-DD` and marks that release latest.

`prefer-newest` uses an NVD score when the report has one. Otherwise it uses a CNA score, and otherwise another analyzer in the report. The newer CVSS version from that source is the one that counts. `highest` uses the largest base score from any source. The report names the version, the score, the vector, and the source. A KEV finding stays in the report when its score is below the threshold. A finding with no score is a `no score` line, not a pass that hides a missing NVD record.

`privateSuppressions` is optional. Omit it, leave it blank, or name a file that is missing or empty, and the scan runs with no private rules. When that local file contains rules, those rules are applied. A URL is refused. Expired rules and CVE rules that matched nothing are listed in `checkstead.txt`. Checkstead does not ship a confirmed public rule. Upstream hosted suppressions stay the ones in the snapshot.

When a dependency already has a package URL, or a name and version from its ecosystem, that identity is what Checkstead reports. A CPE match is a confirmed finding only when it names that same package. A fuzzy CPE match, which Dependency-Check records at low confidence, is not a confirmed finding. No suppression file is required to drop it.

Each finding in `checkstead.txt` is direct or transitive, and production or dev. Dev is not the production bucket. A devDependency, or a lockfile entry marked dev, is dev. The timeline shows the same classification. `checkstead scan` also writes `checkstead.sarif` beside that report. The result includes the classification and the score source.

```bash
checkstead scan --scan . --project my-service
```

The report directory is `checkstead-report/`. `checkstead.txt` names the engine and the snapshot:

```text
engine: 13.0.0
snapshot: 2026-10-06T01:00:00Z
checksum: sha256:…
notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.
score-policy: prefer-newest
threshold: 7
```

Pass `--revision` when the scan should name a git commit. If that commit is in the tree you scanned, the report also names the author git recorded.

The same directory receives Dependency-Check's HTML and JSON reports. The command is the pinned `dependency-check.sh` with that snapshot's data directory and `--noupdate`. It does not receive `--nvdApiKey`.

The first scan of a UTC day downloads the manifest and the database zip, checks the engine version and the SHA-256 checksum, and caches them under `~/.cache/checkstead/<UTC date>/`. A later scan that day uses the cache, so both scans name the same snapshot even if the published manifest changes. Set `CHECKSTEAD_CACHE` to put that cache somewhere else.

The public URL above is that latest manifest. This project does not ship a made-up database.

## What a scan still contacts

`--noupdate` turns off Dependency-Check 13.0.0's update phase. That phase is what calls `services.nvd.nist.gov`. It is also what refreshes CISA KEV, the hosted suppressions file, the RetireJS repository, and the engine version check. Those copies are whatever the snapshot already contains.

Analysis can still open other connections when the files you scan need them:

- Maven Central (`search.maven.org`), when a jar has no POM metadata beside it
- npm, yarn, and pnpm audit (`registry.npmjs.org`), when those manifests are in the scan
- the other ecosystem audit analyzers, when their manifests are in the scan

OSS Index is on in the engine defaults and turns itself off when no Sonatype token is configured. Checkstead does not set one.

The Maven goal and the Gradle task pass the coordinates and the jars the build already resolved, which is the path that needs Central less often.

## The updater secret

Scans do not use an NVD API key. The daily updater does. It is the only place the key is read.

Add one repository secret:

| Name | What to put there |
| --- | --- |
| `NVD_API_KEY` | An NVD API key for this requestor. Request one at <https://nvd.nist.gov/developers/request-an-api-key>. |

Do not copy a key out of another repository. Do not put this secret in a scan, a `checkstead.yml`, or an application repository.

Until the secret is set, [Update database snapshot](.github/workflows/update-snapshot.yml) fails on purpose and publishes nothing. After it is set, run that workflow once, or wait for the schedule at 01:00 UTC. The job installs Dependency-Check 13.0.0, refuses the binary if it does not report that version, runs `--updateonly` with the key, and publishes a GitHub release tagged `db-YYYY-MM-DD`, marked latest. The release contains:

- `manifest.json` — engine version, UTC timestamp, SHA-256 checksum
- `checkstead-db.zip` — the data directory
- `checkstead-db.zip.sha256`

A second run on the same UTC day leaves that release in place and does not call NVD again. The workflow allows three hours. The first database load is large.

## Container images

The scanner image contains the pinned engine and the `checkstead` command. It does not contain a database. The server image is the timeline only.

You can build them from this checkout:

```bash
docker build -t checkstead .
docker run --rm -v "$PWD:/work" -w /work checkstead scan --scan . --project my-service
```

[CI](.github/workflows/ci.yml) publishes both images to GitHub Container Registry after the tests pass.

| Image | What it is |
| --- | --- |
| `ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead` | Scanner. The pinned engine and the `checkstead` command. |
| `ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server` | Timeline server. |

| Tag | When it is published |
| --- | --- |
| `sha-<commit>` | Every push. The commit is the full git SHA, so this tag stays on that build. |
| `<branch>` | Pushes to that branch. The default branch tag is `main`. |
| `latest` | Pushes to the default branch. |
| `engine-13.0.0` | Pushes to the default branch, scanner image only. The number is the pin in `engine.version`. |
| `0.1.0`, `0.1`, and `v0.1.0` | A git tag named `v0.1.0`. |

```bash
docker pull ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:latest
docker pull ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server:latest
```

The first publish creates the packages. If a pull is denied, open the package on GitHub and set its visibility to public.

## Maven

The goal shells out to `checkstead scan` and passes `group:artifact:version` plus the resolved jar files. Install it from this repository:

```bash
mvn -f integrations/maven/pom.xml install
```

`checkstead` must be on `PATH` where the build runs.

```xml
<plugin>
  <groupId>dev.checkstead</groupId>
  <artifactId>checkstead-maven-plugin</artifactId>
  <version>0.1.0</version>
  <executions>
    <execution>
      <goals>
        <goal>scan</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

The goal is `checkstead:scan`, bound to `verify`. Override the scan path with `-Dcheckstead.scan=...` or the config file with `-Dcheckstead.config=...`.

## Gradle

Apply the script plugin. It registers `checksteadScan`, which calls the same command with the project coordinates and the runtime classpath.

```groovy
apply from: "integrations/gradle/checkstead.gradle"
```

From another repository, copy `integrations/gradle/checkstead.gradle` or apply the raw file from a tag of this repository. `checkstead` must be on `PATH`.

## GitHub Action

`action.yml` in this repository builds the scanner image and runs `checkstead scan`. It has no API key input and no token input. The report is written to `checkstead-report/` in the workspace.

```yaml
name: Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: chethankumblekar/dependency-check-db-cache@main
        with:
          scan: .
          project: my-service
```

The Action passes `GITHUB_REF_NAME` and `GITHUB_SHA` into the scan. `checkstead.txt` records them as `branch:` and `revision:`, and records `author:` and `author-email:` for that commit. Git inside the container is run with `safe.directory`, so a different user on the runner workspace does not drop the branch, the commit, or the author. The timeline groups scans by the `branch:` line in `checkstead.txt`. It does not read a side file for that metadata.

On a pull request the Action fetches the head commit and the base commit, then scans both trees in one run. Both scans use the same snapshot and `--noupdate`. A finding is introduced only when its package identity and vulnerability id are on the head and absent on the base.

Findings in `checkstead.txt` are separate groups: direct and transitive, and production and dev. Each vulnerability has a `description:` line, plus the score, the score source, and the package. The timeline keeps those groups and lists each finding as one row, sorted by score. The description stays closed until the row is opened. The SARIF result carries the same description, score, score source, and package.

### Pull requests

The Action posts one comment on the pull request and updates that same comment in place on later pushes. The comment is sent with the workflow `GITHUB_TOKEN`. `pull-requests: write` is the permission that allows it. The report is tagged to the pull request: `checkstead.txt` records `pull-request:`, and the timeline uses that line in the scan name.

The build fails only when the pull request introduces a finding the score policy would fail (`threshold`, `failOnKev`, `failUnscored`). Findings already on the base are listed and do not fail the build. An empty threshold does not fail on score.

### SARIF

The Action writes `checkstead-report/checkstead.sarif` and uploads it. GitHub shows those findings on the repository Security tab. The workflow needs `security-events: write`.

Pin a commit SHA when the scan should stay on one build. `@main` follows this repository. After a version tag, `v0` follows the newest 0.x release. See [Release](#release).

## Azure DevOps

The extension in [`integrations/azure-devops`](integrations/azure-devops) adds the pipeline task `ChecksteadScan`. It runs the same scanner image. It does not take an NVD API key. The agent needs Docker.

```yaml
- task: ChecksteadScan@0
  inputs:
    scan: .
    project: $(Build.Repository.Name)
```

A full example is [`integrations/azure-devops/example.yml`](integrations/azure-devops/example.yml). GitHub builds use the Action above. The [Release](#release) workflow publishes this extension, and an Azure Pipelines organization installs that public listing before it uses the task.

Ubuntu and Windows steps for a local scan, the App Service timeline, and an Azure DevOps build are in [Azure on Ubuntu and Windows](docs/azure.md).

## Release

Push a tag `v0.1.0`. [Release](.github/workflows/release.yml) runs on tags that look like `v1.2.3`.

It creates the GitHub release, moves the floating tags `v0` and `v0.1` to that commit, attaches the Azure DevOps extension package, and publishes that package to the Azure DevOps Marketplace. CI on the same tag publishes the scanner image `ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:0.1.0`.

GitHub Marketplace has no API for its listing checkbox. On the first release, edit it, select **Publish this Action to the GitHub Marketplace**, and set the primary category to **Security**. The account needs the Marketplace Developer Agreement and two-factor authentication. Later tags stay on that listing.

The Release workflow publishes the extension. Set both of these on the repository before the first tag. The manifest already has `"public": true`.

| Name | Kind | What to put there |
| --- | --- | --- |
| `AZURE_MARKETPLACE_TOKEN` | Secret | Marketplace (Publish) credential for this extension. Organization: All accessible organizations. Create it at [the Azure DevOps credential page](https://dev.azure.com/_usersSettings/tokens). |
| `AZURE_MARKETPLACE_PUBLISHER` | Variable | The publisher id from [the Marketplace publisher hub](https://marketplace.visualstudio.com/manage). Create that publisher with a Microsoft account. |

That credential page can offer to create an organization so the publisher has a home. The Release workflow on GitHub is what publishes. Teams that already use Azure Pipelines open the listing and choose **Get it free**, then use `ChecksteadScan@0`. Their agent pulls the scanner image, so the GHCR package has to be public. See [Container images](#container-images).

Microsoft lists a public extension when the publisher is verified. On the publisher **Details** tab, verify a domain you control if the page asks for that. Microsoft may also review the listing.

If the secret or the variable is missing, the publish step fails.

## Timeline

```bash
python3 -m checkstead ui
```

Open http://127.0.0.1:8765/. The page reads `ui/scans`. Pass `--scans` to point it at another directory of scan reports.

The two reports already in `ui/scans` are a pair of fixture scans on the same snapshot (`2026-10-06T01:02:03Z`, engine 13.0.0). Dependency-Check 13.0.0 identified the jars in evidence-collection mode: guava 31.1-jre and commons-lang3 3.12.0, then guava 32.1.3-jre and gson 2.10.1. Those jars are the published Maven Central artifacts. Finding analysis did not run, because that needs the NVD snapshot and this checkout does not contain one. The findings list and the score-source field are empty. Suppressions and false positives are empty on purpose.

A scan records a revision when you pass `--revision`, and the GitHub Action passes `GITHUB_SHA`. When that revision is a commit git can see, the report also names the author. The sample reports use the commits of the fixture trees. Both were committed by Cursor Agent.

A scan records the git branch of the tree it scanned, the branch you pass with `--branch`, or `GITHUB_REF_NAME` from the Action. The timeline reads `branch:` from `checkstead.txt` and groups scans into one section per branch. Drift is the change from the previous scan on that same branch. Each finding is one row in its direct or transitive group and its production or dev group: score, vulnerability id, package, and score source. The description stays closed until the row is opened. The rows are sorted by score, highest first. The list can be narrowed to one relationship and one scope without dropping those groups.

## Server

The timeline is a server you can run on a laptop or deploy as a container. The first person to sign in is the administrator. Variable names for the optional sign-in buttons are in [`.env.example`](.env.example).

### Localhost timeline

The first person signs in and opens the timeline with no `CHECKSTEAD_GITHUB_CLIENT_ID`, no `CHECKSTEAD_GITHUB_CLIENT_SECRET`, and no Entra app. The enabled control is **Sign in on this computer**. That sign-in does not use an OAuth app.

On a laptop, from this checkout:

```bash
PYTHONPATH=src python3 -m checkstead ui
```

Open http://127.0.0.1:8765/. Accounts are stored under `~/.local/share/checkstead`, or in the directory you pass with `--data`.

The container is the same server. `Dockerfile.server` listens on every interface inside the container and turns localhost sign-in on. The published port in [`docker-compose.yml`](docker-compose.yml) is `127.0.0.1:8765`.

```bash
docker build -f Dockerfile.server -t checkstead-server .
docker run --rm -p 127.0.0.1:8765:8765 -v checkstead-data:/var/lib/checkstead -v checkstead-scans:/var/lib/checkstead/scans checkstead-server
```

The published server image is the same container. CI publishes it for `linux/amd64` and `linux/arm64`, so an Apple Silicon Mac does not emulate it.

```bash
docker pull ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server:latest
docker run --rm -p 127.0.0.1:8765:8765 -v checkstead-data:/var/lib/checkstead -v checkstead-scans:/var/lib/checkstead/scans ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server:latest
```

### Optional GitHub and Microsoft sign-in

GitHub and Microsoft sign-in work only when the server variables are set. Leave them unset and those buttons stay on the page, marked not configured. **Sign in on this computer** stays enabled.

| Variable | What it is |
| --- | --- |
| `CHECKSTEAD_GITHUB_CLIENT_ID` | GitHub OAuth app client id. This app only signs a person in. |
| `CHECKSTEAD_GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret |
| `CHECKSTEAD_ENTRA_CLIENT_ID` | Microsoft Entra client id. This app only signs a person in. |
| `CHECKSTEAD_ENTRA_CLIENT_SECRET` | Microsoft Entra client secret |
| `CHECKSTEAD_ENTRA_TENANT` | Optional. Defaults to `organizations`, which is work and school accounts. Set a tenant id to lock one organization. |

The callback for a local GitHub OAuth app is `http://127.0.0.1:8765/api/sso/github/callback`. The Microsoft callback is `http://127.0.0.1:8765/api/sso/entra/callback`. On another host the same paths are `https://<host>/api/sso/github/callback` and `https://<host>/api/sso/entra/callback`. Copy [`.env.example`](.env.example) to `.env` when you set the variables. Set `CHECKSTEAD_COOKIE_SECURE=1` when the server is behind TLS.

`CHECKSTEAD_GITHUB_ORG` is optional. When set, only members of that GitHub organization can use the GitHub button.

### GitHub App

The GitHub App is created from `/github`. It reads and scans repositories. It is not the OAuth app above, and it does not ask for a token. A personal account is supported, not only an organization. Choose **Personal account** and type the user login. For the account chethankumblekar, type `chethankumblekar`. Choose **Organization** and type the organization login for an organization. See [GitHub](#github).

### Scans

The timeline is empty until a scan report is in the server's scan directory. In the container that directory is `/var/lib/checkstead/scans`. A scan started from `/github` is stored there and grouped by branch. [`docker-compose.yml`](docker-compose.yml) keeps that directory on the `checkstead-scans` volume, and keeps accounts on `checkstead-data`.

```bash
docker compose up -d
```

Open http://127.0.0.1:8765/.

The scan image can start the server too, with `docker run --rm -p 8765:8765 checkstead ui --host 0.0.0.0`. That image also contains the scanner. `Dockerfile.server` is only the server. A checkout of this repository, started with `python3 -m checkstead ui`, reads `ui/scans` instead. See [Timeline](#timeline).

The first person to sign in becomes the administrator. After that, Administration is where that person adds logins and chooses who is a user and who is an administrator. Someone who has not been added cannot sign in. The last administrator cannot be removed.

GitLab and other Git hosts are not connected. Adding one is a new identity provider beside GitHub and Azure DevOps. The server does not pretend they are available.

Put the server behind TLS when it is not on your own machine, and set `CHECKSTEAD_COOKIE_SECURE=1` so the session cookie is marked Secure. Do not bake a token into the image or the repository.

## Develop

```bash
python3 -m pip install ruff==0.14.2 build==1.3.0 certifi
bash scripts/self-test.sh
```

That is the same lint, package build, unit tests, and Maven plugin tests that CI runs before it publishes images. The tests publish no database. They serve a tiny zip, run two scans on the same UTC day, and record every URL the scan client requests. Both reports name the same snapshot. None of the requests are to `services.nvd.nist.gov`. A manifest built by engine 12.1.8 is refused before the zip is downloaded.

## License and security

Checkstead is [Apache-2.0](LICENSE). Contributions use the Developer Certificate of Origin. See [CONTRIBUTING.md](CONTRIBUTING.md).

Maintainer: Chethan K ([@chethankumblekar](https://github.com/chethankumblekar)). Report a vulnerability through [SECURITY.md](SECURITY.md). You can email chethan.kumblekar@ascertra.com, or open a private advisory:

https://github.com/chethankumblekar/dependency-check-db-cache/security/advisories/new
