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

The client can also verify an Ed25519 signature over those manifest fields
when `signature` is present and a trust root is configured. The trust root is
the public keys in `src/checkstead/snapshot_trust.json`. That file currently
pins no keys. With an empty trust file, a checksummed snapshot still scans.
A signature the client cannot check is reported as `unsigned`. It does not
fail the scan, and it is not treated as verified. Pinning any public key, or
setting `CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE=1`, refuses a missing
signature and refuses a key id that is not pinned. A bad signature from a
pinned key is a failure. A signature made by a key pinned in this repository
is still the same publisher: someone who can change the pinned key and the
release can sign. Someone who can only upload a release, and does not have
`CHECKSTEAD_SNAPSHOT_SIGNING_KEY`, cannot. The updater can sign before the
public key is pinned. Pin that key only after a signed `db-YYYY-MM-DD`
release exists. Pinning first refuses the unsigned caches already in use.
Rotation adds the new public key as `current` and marks the old key
`retired` with `notAfter`. Ship that pin before signing with the new key.
Do not commit the private key. Older unsigned caches are refused once the
pin is in the client.

The Dependency-Check CLI zip is a different download. `scripts/install-engine.sh`,
`scripts/setup.sh`, and `scripts/setup.ps1` verify the detached signature with
the public key in `scripts/keys/dependency-check-release.asc` and require
fingerprint `259A55407DD6C00299E6607EFFDE55BE73A2D1ED` (Jeremy Long
`<jeremy.long@gmail.com>` on the Ubuntu keyserver). The installed
`dependency-check.sh` or `dependency-check.bat` must report the pin. A checksum
file sitting next to the zip is not treated as that proof. The Linux and macOS
script was executed against a bad signature and against a throwaway signed
zip. The Windows script was reviewed and not executed here.

## What the client refuses

- Any URL whose host is `services.nvd.nist.gov`, including after a redirect
  (`src/checkstead/http.py`).
- Link-local addresses (including `169.254.169.254` and an IPv4-mapped form),
  multicast, unspecified addresses, all-digit hosts, and
  `metadata.google.internal`. Private addresses stay allowed for a GitHub
  Enterprise host.
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
does not need the network. A failed download is reported as unavailable and
does not invent a database.

Freshness is printed on every scan:

- `current` — the manifest timestamp is the scan's UTC day or the day before
- `aging` — older than that, up to `CHECKSTEAD_SNAPSHOT_MAX_AGE_DAYS` (default 7)
- `stale` — older than the maximum

A stale snapshot prints a warning and the scan continues, including offline.
`CHECKSTEAD_FAIL_STALE_SNAPSHOT=1` turns that warning into `SnapshotRefused`.
The default does not, because an offline scan of a verified cache must not
start depending on the network. `cache=hit` means this UTC day's directory
was reused and the client did not contact the publisher again.

## Scanner image

`Dockerfile` does not set `USER`. The default process is root so
`docker run -v "$PWD:/work" -w /work` can write a mount owned by the host
user. The image also creates `checkstead` (uid 10001). The engine and the
virtualenv are readable and executable by any uid. A non-root process gets a
writable `HOME` and cache from `scripts/docker-entrypoint.sh`.

To keep the report owned by the host user:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
  ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:latest \
  scan --scan . --out checkstead-report
```

That path was checked by running the entrypoint with a fake non-root `id`.
The GitHub Action and the Azure DevOps task pass the host uid and gid
(`--user "$(id -u):$(id -g)"`, or `process.getuid()` and `process.getgid()`
on the task). A host-mounted report is then owned by the user who started
the container. The image default stays root for a direct `docker run` that
does not pass `--user`. Do not add `--privileged`. Treat the scanner image
as a build tool, not as a multi-tenant service.

## Timeline server

`Dockerfile.server` runs as `checkstead`. The process listens on `0.0.0.0`
inside the container because Docker port publishing does not reach a listener
on the container loopback. `docker-compose.yml` publishes
`127.0.0.1:8765:8765`. That host binding is the control that keeps the port
off the network.

`_local_sign_in` looks at the TCP peer address. It does not look at `Host`,
`X-Forwarded-For`, `Forwarded`, or `X-Real-IP`. A remote client that sends
`Host: 127.0.0.1:8765` or `Host: localhost` is not local.

- `CHECKSTEAD_LOCAL` unset: only a loopback peer (`127.0.0.0/8`, `::1`, or
  an IPv4-mapped loopback address). This is the laptop command, which binds
  `127.0.0.1`.
- `CHECKSTEAD_LOCAL=1`: every peer that can open the port. Compose sets this
  because the process inside the container sees the Docker bridge
  (`172.17.0.1` or similar), not `127.0.0.1`. That is safe only while the
  published port stays `127.0.0.1:8765:8765`. The `local` account is one
  shared administrator: anyone who passes this check gets a session for it,
  not only the first visitor.
- `CHECKSTEAD_LOCAL=0`: localhost sign-in is off for every peer, including
  loopback. Use this when a reverse proxy accepts remote traffic. The proxy's
  connection from `127.0.0.1` must not become the administrator, and a
  forwarded header must not either. Sign in with GitHub or Entra, terminate
  TLS, and set `CHECKSTEAD_COOKIE_SECURE=1`.

The entrypoint and `checkstead ui` warn when `CHECKSTEAD_LOCAL=1` and the
listen address is not loopback.

Session cookies are `HttpOnly` and `SameSite=Lax`. They are marked `Secure`
only when `CHECKSTEAD_COOKIE_SECURE=1`. Responses set `X-Content-Type-Options`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
`Content-Security-Policy: frame-ancestors 'none'`.

OAuth and the GitHub App manifest use `CHECKSTEAD_PUBLIC_BASE` when it is set,
and ignore `Host`. When it is unset, only a loopback peer may supply `Host`.
A remote peer without that variable gets an error instead of a redirect.
`/api/health` returns `{"ok": true}` with no session. It does not expose
accounts. The account database file is mode `0600`.

The server image starts as root so the entrypoint can `chown` a new volume
and `su` to `checkstead`. A process that is already non-root skips `chown`.
`docker-compose.yml` sets `no-new-privileges:true` and still publishes
`127.0.0.1:8765:8765`. That Compose file was not started in this workspace.

## What this project does not guarantee

- That a CVE, CPE match, or score from Dependency-Check is correct.
- That a fuzzy CPE match is a confirmed finding. Checkstead drops those from
  its own report. It does not hide them with a required suppression file.
- That a snapshot is newer than the last successful publish.
- That a GitHub tag such as `latest` on the container image is immutable.
  Pin a digest after you have inspected a published image.
- That the scanner image has no vulnerabilities in the jars Dependency-Check
  ships. The pull-request report records them. The failing gate skips
  `/opt/dependency-check` so those upstream jars do not fail the build by
  themselves. See [Security gates](security-gates.md).
- That a snapshot signature is an independent publisher. No signing key is
  pinned until `snapshot_trust.json` lists one.
