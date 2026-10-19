# Changelog

All notable changes to Checkstead are recorded here. The version matches the
package version. Snapshots are dated releases (`db-YYYY-MM-DD`) and are not
listed as product versions.

## 0.1.0

- Pins OWASP Dependency-Check 13.0.0. One updater publishes a checksummed
  snapshot. A scan uses that snapshot with `--noupdate` and does not call
  `services.nvd.nist.gov`.
- Names the score a finding is judged on. The policies are `prefer-newest` and
  `highest`. A KEV finding stays visible. A finding with no score is a
  `no score` line.
- Keeps a private suppression file optional. A missing or empty file does not
  block a scan, and a URL is refused.
- Shows findings in one table on the timeline. The groups are Direct ·
  Production, Direct · Dev, Transitive · Production, and Transitive · Dev. A
  path inside `node_modules` is the package name.
- Signs a person in on localhost with **Sign in on this computer**. That
  sign-in does not use an OAuth app. It uses the TCP peer address.
  `CHECKSTEAD_LOCAL=1` is the Compose bootstrap. `CHECKSTEAD_LOCAL=0` turns
  the sign-in off. A `Host` or `X-Forwarded-For` header does not count as
  localhost. GitHub and Microsoft sign-in stay optional.
- Connects a personal GitHub account or an organization through a GitHub App.
  The page does not ask for a token.
- Lists recent Checkstead workflow runs for a connected repository: queued, in
  progress, success, or failure. A run on a pull request is labeled with the
  pull request number and links to that pull request. Rerun starts that same
  run again with the app credentials already stored.
