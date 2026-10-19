# Threat model

Checkstead runs OWASP Dependency-Check 13.0.0 against one published database
snapshot. Scans do not use an NVD API key. This note is the trust boundary for
that design. It is not a claim that every boundary has been penetration tested.

## Assets

- The published snapshot (`manifest.json`, `checkstead-db.zip`, and the
  checksum file) and the local cache under `~/.cache/checkstead/`.
- The pinned Dependency-Check install.
- Scan reports, including SARIF and pull-request comments.
- Timeline accounts, sessions, and GitHub App private keys stored by the server.
- `NVD_API_KEY`, used only by the updater.

## Actors

- A developer or CI job that runs `checkstead scan` against a project.
- The maintainer workflow that publishes the daily snapshot.
- A person who can open the timeline port.
- A person who can change a workflow on this repository.

## Trust boundaries

```text
NVD API  --only the updater, with NVD_API_KEY-->  Dependency-Check data
                                                      |
                                                      v
                                            GitHub release db-YYYY-MM-DD
                                            manifest + zip + sha256 file
                                                      |
                                                      v
                         consumer HTTPS download -> local cache -> --noupdate scan
```

The updater is `.github/workflows/update-snapshot.yml` and
`scripts/update-snapshot.sh`. Ordinary scan workflows do not receive
`NVD_API_KEY`.

A consumer trusts the GitHub release on this repository for the bytes of the
snapshot. The client checks the manifest schema, the engine pin, the timestamp
shape, the database file name, and the SHA-256 of the zip before a scan uses
it. That proves the zip matches the manifest. It does not prove a second party
signed the snapshot.

The Dependency-Check CLI zip is a different download. `scripts/install-engine.sh`
verifies the detached signature with the public key in
`scripts/keys/dependency-check-release.asc` and requires fingerprint
`259A55407DD6C00299E6607EFFDE55BE73A2D1ED` (Jeremy Long
`<jeremy.long@gmail.com>` on the Ubuntu keyserver). The installed
`dependency-check.sh --version` must report the pin. A checksum file sitting
next to the zip is not treated as that proof.

## What the client refuses

- Any URL whose host is `services.nvd.nist.gov`, including after a redirect
  (`src/checkstead/http.py`).
- Cleartext HTTP to a host other than `localhost`, `127.0.0.1`, or `::1`.
- `file://` and any URL that contains userinfo.
- A manifest whose format, engine, timestamp, checksum, or database name is
  wrong (`src/checkstead/snapshot.py`).
- A zip member that is absolute, contains `..` or NUL, or is a symlink whose
  target leaves the destination (`src/checkstead/archive.py`).
- A cached zip whose bytes no longer match the cached manifest. The scan stops
  and names the day directory to remove. It does not replace that cache by
  itself.

## Cache and freshness

The first successful manifest of a UTC day is the snapshot later scans that
day will name, even if the published manifest changes. That is deliberate:
two jobs on the same day compare the same database. A scan with a valid cache
does not need the network. There is no maximum age that would turn an offline
scan into a failure. A stale snapshot is therefore a policy choice of the
publisher's schedule (01:00 UTC), not a silent refresh.

## Scanner image

`Dockerfile` does not set `USER`. The documented command is
`docker run -v "$PWD:/work" -w /work`. The mount is owned by the host user.
A fixed user inside the image cannot write that mount unless the host
directory is writable by that user. The process is root. Treat the scanner
image as a build tool, not as a multi-tenant service.

## Timeline server

`Dockerfile.server` runs as `checkstead`. The process listens on `0.0.0.0`
inside the container because Docker port publishing does not reach a listener
on the container loopback. `docker-compose.yml` publishes
`127.0.0.1:8765:8765`. That host binding is the control that keeps the port
off the network.

`CHECKSTEAD_LOCAL=1` makes `_local_sign_in` accept any client. The first
account becomes the administrator. The entrypoint and `checkstead ui` warn
when the process is reachable beyond loopback. A host header is not that
control. For a remote deployment, set `CHECKSTEAD_LOCAL=0`, terminate TLS,
and set `CHECKSTEAD_COOKIE_SECURE=1`.

Session cookies are `HttpOnly` and `SameSite=Lax`. They are marked `Secure`
only when `CHECKSTEAD_COOKIE_SECURE=1`.

## What this project does not guarantee

- That a CVE, CPE match, or score from Dependency-Check is correct.
- That a fuzzy CPE match is a confirmed finding. Checkstead drops those from
  its own report. It does not hide them with a required suppression file.
- That a snapshot is newer than the last successful publish.
- That a GitHub tag such as `latest` on the container image is immutable.
  Pin a digest after you have inspected a published image.
- That the scanner image has no vulnerabilities in the jars Dependency-Check
  ships. The pull-request report records them and does not fail the build on
  those upstream jars. See [Security gates](security-gates.md).
