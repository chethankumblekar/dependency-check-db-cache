# Checkstead

Checkstead runs [OWASP Dependency-Check](https://owasp.org/projects/dependency-check) once, the same way, for every build. One updater publishes a database snapshot. Scans use that snapshot. A scan does not use an NVD API key and does not call `services.nvd.nist.gov`.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

Checkstead is not an OWASP project and does not speak for OWASP or NIST.

## Pinned engine

The pin is Dependency-Check **13.0.0**, the current upstream release on 6 October 2026 ([v13.0.0](https://github.com/dependency-check/DependencyCheck/releases/tag/v13.0.0), published 3 August 2026). Release 12.2.2 changed the database schema, so a database built by an older engine is not usable here. The pin is the single line in [`engine.version`](engine.version). Move it when upstream changes behavior or the database schema.

A snapshot manifest names the engine that built it. If that version is not the pin, the scan stops and does not run Dependency-Check.

## Scan

Install the command from a checkout. A virtual environment keeps it off the system Python:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
checkstead version
```

`checkstead version` prints `13.0.0`.

Put [`checkstead.yml`](checkstead.yml) in the project you scan, or use the copy in this repository. The file is four keys:

```yaml
snapshot: https://github.com/chethankumblekar/checkstead/releases/latest/download/manifest.json
scorePolicy:
threshold:
privateSuppressions:
```

`snapshot` is the manifest URL. Point it at the public manifest, or at a manifest your own updater published. `scorePolicy`, `threshold`, and `privateSuppressions` are reserved for later. This release reads them and does not apply them.

```bash
checkstead scan --scan . --project my-service
```

The report directory is `checkstead-report/`. `checkstead.txt` names the engine and the snapshot:

```text
engine: 13.0.0
snapshot: 2026-10-06T01:00:00Z
checksum: sha256:…
notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.
```

The same directory receives Dependency-Check's HTML and JSON reports. The command is the pinned `dependency-check.sh` with that snapshot's data directory and `--noupdate`. It does not receive `--nvdApiKey`.

The first scan of a UTC day downloads the manifest and the database zip, checks the engine version and the SHA-256 checksum, and caches them under `~/.cache/checkstead/<UTC date>/`. A later scan that day uses the cache, so both scans name the same snapshot even if the published manifest changes. Set `CHECKSTEAD_CACHE` to put that cache somewhere else.

There is no snapshot until the updater below has published one. A 404 from the public URL means that step has not happened. This project does not ship a made-up database.

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

Until the secret is set, [Update database snapshot](.github/workflows/update-snapshot.yml) fails on purpose and publishes nothing. After it is set, run that workflow once, or wait for the schedule at 01:00 UTC. The job installs Dependency-Check 13.0.0, refuses the binary if it does not report that version, runs `--updateonly` with the key, and publishes a GitHub release tagged `db-YYYY-MM-DD`. The release contains:

- `manifest.json` — engine version, UTC timestamp, SHA-256 checksum
- `checkstead-db.zip` — the data directory
- `checkstead-db.zip.sha256`

A second run on the same UTC day leaves that release in place and does not call NVD again. The workflow allows three hours. The first database load is large.

## Container

The image contains the pinned engine and the `checkstead` command. It does not contain a database.

```bash
docker build -t checkstead .
docker run --rm -v "$PWD:/work" -w /work checkstead scan --scan . --project my-service
```

The image publishes to `ghcr.io/chethankumblekar/checkstead` when the [Publish image](.github/workflows/image.yml) workflow runs. The tag is the engine pin, plus `latest`.

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

```yaml
name: Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: chethankumblekar/checkstead@v0.1.0
        with:
          scan: .
          project: my-service
```

The action builds the container and runs `checkstead scan`. It has no API key input. The report is written to `checkstead-report/` in the workspace.

## Timeline

```bash
python3 -m checkstead ui
```

Open http://127.0.0.1:8765/. The page reads `ui/scans`. Pass `--scans` to point it at another directory of scan reports.

The two reports already in `ui/scans` are a pair of fixture scans on the same snapshot (`2026-10-06T01:02:03Z`, engine 13.0.0). Dependency-Check 13.0.0 identified the jars in evidence-collection mode: guava 31.1-jre and commons-lang3 3.12.0, then guava 32.1.3-jre and gson 2.10.1. Those jars are the published Maven Central artifacts. Finding analysis did not run, because that needs the NVD snapshot and this checkout does not contain one. The findings list and the score-source field are empty. Suppressions and false positives are empty on purpose.

A scan records a revision when you pass `--revision`. When that revision is a commit in the tree you scanned, the report also names the person git recorded as the author. The sample reports use the commits of the fixture trees. Both were committed by Cursor Agent.

## Server

The timeline is a server you can run on a laptop or deploy as a container. People can sign in with GitHub, with a Microsoft Entra work or school account, or with a GitHub or Azure DevOps personal access token. The server asks that host who the person is, then discards the token. It does not keep a copy.

On a laptop, from this checkout:

```bash
PYTHONPATH=src python3 -m checkstead ui
```

Open http://127.0.0.1:8765/. Accounts are stored under `~/.local/share/checkstead`, or in the directory you pass with `--data`.

The container is the same server, listening on every interface so it can be deployed on a host you choose:

```bash
docker build -f Dockerfile.server -t checkstead-server .
docker run --rm -p 8765:8765 -v checkstead-data:/var/lib/checkstead checkstead-server
```

The scan image can start it too, with `docker run --rm -p 8765:8765 checkstead ui --host 0.0.0.0`. That image also contains the scanner. `Dockerfile.server` is only the server.

Single sign-on needs an app registration. Leave the variables unset and the buttons stay on the page, marked not configured, and a personal access token still works.

| Variable | What it is |
| --- | --- |
| `CHECKSTEAD_GITHUB_CLIENT_ID` | GitHub OAuth app client id |
| `CHECKSTEAD_GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret |
| `CHECKSTEAD_GITHUB_ORG` | Optional. When set, only members of this GitHub organization can use the GitHub button. |
| `CHECKSTEAD_ENTRA_CLIENT_ID` | Entra app registration client id |
| `CHECKSTEAD_ENTRA_CLIENT_SECRET` | Entra app registration client secret |
| `CHECKSTEAD_ENTRA_TENANT` | Optional. Defaults to `organizations`, which is work and school accounts. Set a tenant id to lock one organization. |

The redirect URLs are `https://<host>/api/sso/github/callback` and `https://<host>/api/sso/entra/callback`. On a laptop without TLS they are `http://127.0.0.1:8765/...`. Set `CHECKSTEAD_COOKIE_SECURE=1` when the server is behind TLS.

Create a token for the host you use:

| Host | What to create | What the server asks |
| --- | --- | --- |
| GitHub | A personal access token that can read your user. A classic token needs the `read:user` scope. | `https://api.github.com/user` |
| Azure DevOps | A personal access token for the organization, and the organization name on the sign-in form. | `https://dev.azure.com/{organization}/_apis/connectionData` |

The first person to sign in becomes the administrator. After that, Administration is where that person adds logins and chooses who is a user and who is an administrator. Someone who has not been added cannot sign in. The last administrator cannot be removed.

GitLab and other Git hosts are not connected. Adding one is a new identity provider beside GitHub and Azure DevOps. The server does not pretend they are available.

Put the server behind TLS when it is not on your own machine, and set `CHECKSTEAD_COOKIE_SECURE=1` so the session cookie is marked Secure. Do not bake a token into the image or the repository.

## Develop

```bash
python3 -m unittest discover -s tests -v
mvn -B -f integrations/maven/pom.xml test
```

The tests publish no database. They serve a tiny zip, run two scans on the same UTC day, and record every URL the scan client requests. Both reports name the same snapshot. None of the requests are to `services.nvd.nist.gov`. A manifest built by engine 12.1.8 is refused before the zip is downloaded.

Contributions are Apache-2.0 and use the Developer Certificate of Origin. See [CONTRIBUTING.md](CONTRIBUTING.md). Report a vulnerability in Checkstead through [SECURITY.md](SECURITY.md).
