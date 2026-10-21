# Architecture

Checkstead is a thin layer in front of a pinned OWASP Dependency-Check release.
It does not reimplement CPE matching, and it is not an OWASP project.

One updater, on a schedule, is the only job that talks to
`services.nvd.nist.gov`. It publishes a snapshot that names the engine, the UTC
time, and a checksum. Every scan downloads that snapshot, checks the engine
pin, and runs Dependency-Check with `--noupdate`. A scan does not receive an
NVD API key.

`checkstead scan` is the command. The Maven goal, the Gradle task, the GitHub
Action, and the Azure DevOps task call that same command. The scanner image is
that command plus the pinned engine. It does not contain a database.

The timeline server is separate. It reads scan reports from a directory and
does not run the updater. Findings are one table. Each row is direct or
transitive, and production or dev. The four groups are Direct · Production,
Direct · Dev, Transitive · Production, and Transitive · Dev. A path
inside `node_modules` is shown as the package name. The selected row's
description is one line under the table.

On localhost, **Sign in on this computer** opens the timeline. That sign-in
does not use an OAuth app. GitHub and Microsoft sign-in are optional and stay
inactive until their variables are set. Azure DevOps sign-in takes an
organization name and an access token (PAT), checks it once against that
organization's `connectionData` API, and does not store it. The form appears
only after an administrator has added an Azure DevOps login.

A personal GitHub account or an organization can install the GitHub App from
`/github`. The app reads repository contents and metadata, and it reads and
reruns Actions workflows. The page stores the credentials GitHub returns. There
is no token field. For a connected repository, the timeline lists recent
Checkstead workflow runs as queued, in progress, success, or failure. A run on
a pull request is labeled with the pull request number and links to that pull
request. Rerun starts that same workflow run again through the GitHub API.

`privateSuppressions` is optional. The public project does not require a
suppression file, and it does not publish a private one.

This product uses data from the NVD API but is not endorsed or certified by the NVD.
