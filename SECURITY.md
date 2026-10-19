# Security

Maintainer: Chethan K ([@chethankumblekar](https://github.com/chethankumblekar)).

Report a vulnerability in Checkstead privately:

https://github.com/chethankumblekar/dependency-check-db-cache/security/advisories/new

You can also email chethan.kumblekar@ascertra.com. Please do not open a public
issue for an unpublished vulnerability in this project.

Include the Checkstead version or commit, the command you ran, and the impact
you can already see. The engine pin from `checkstead version`, and whether the
scan used the public snapshot or a manifest you host, are useful. Do not include
an NVD API key, a private suppression file, a GitHub App private key, an OAuth
client secret, or a session cookie.

The maintainer reviews the report and coordinates a fix before any public
discussion. There is no bug-bounty program.

This policy covers Checkstead: the scan command, the timeline server, the
GitHub App integration, and the published images. Questions about a CVE score,
a CPE match, or NVD enrichment belong with NVD, the CVE Numbering Authority, or
the analyzer that produced them. Checkstead does not assign those identifiers.

## Boundaries

A scan does not call `services.nvd.nist.gov`. It downloads the snapshot manifest
and zip over HTTPS, checks the engine pin and the SHA-256, and runs
Dependency-Check with `--noupdate`. Cleartext HTTP is accepted only for
loopback, which is how the tests serve fixtures.

The database snapshot is integrity-checked against its manifest. That check
does not prove a second party published the zip. If the manifest carries a
signature, the client checks it against `src/checkstead/snapshot_trust.json`.
That file pins no key yet, so current snapshots are unsigned. Set
`CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE=1` only after a key is pinned and the
publisher is signing. The Dependency-Check CLI zip is checked with the
vendored release key in `scripts/keys/dependency-check-release.asc` before it
is installed. The fingerprint pinned in `scripts/install-engine.sh` is
`259A55407DD6C00299E6607EFFDE55BE73A2D1ED`.

The timeline's localhost sign-in uses the TCP peer address. `Host`,
`X-Forwarded-For`, `Forwarded`, and `X-Real-IP` are not proof that the client
is local. With `CHECKSTEAD_LOCAL` unset, only a loopback peer can sign in
that way. With `CHECKSTEAD_LOCAL=1`, anyone who can open the listening port
can open a session as the shared `local` administrator. Compose publishes
`127.0.0.1:8765` and sets that mode so the Docker bridge address still works.
Put a remote server behind TLS, set `CHECKSTEAD_COOKIE_SECURE=1`, and set
`CHECKSTEAD_LOCAL=0`. That last setting turns localhost sign-in off, including
for a reverse proxy on the same machine.

The scanner image defaults to root so `docker run -v "$PWD:/work" -w /work`
can write reports into the mount. Run `--user "$(id -u):$(id -g)"` when the
report should be owned by the host user. The server image runs as `checkstead`.

More detail is in [the threat model](docs/security/threat-model.md),
[the gates](docs/security/security-gates.md), and
[the production-readiness assessment](docs/security/production-readiness-assessment.md).
