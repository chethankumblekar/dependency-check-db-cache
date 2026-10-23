# Production operations

How to run Checkstead for a team: the scan client in CI, the snapshot
updater, and the timeline server. Each section names the setting or script
that does the work. Read [Production-readiness assessment](../security/production-readiness-assessment.md)
for what has and has not been verified.

## Components

| Component | Where it runs | State it keeps |
| --- | --- | --- |
| Scan client (`checkstead scan`, the GitHub Action, Maven, Gradle, Azure DevOps task) | CI runners and laptops | Snapshot cache, `~/.cache/checkstead` or `CHECKSTEAD_CACHE` |
| Snapshot updater (`update-snapshot.yml`, `scripts/update-snapshot.sh`) | GitHub Actions, daily | GitHub releases `db-YYYY-MM-DD` |
| Timeline server (`checkstead ui`, `checkstead-server` image) | One host or container | `CHECKSTEAD_DATA` (accounts, sessions, GitHub App key) and `CHECKSTEAD_SCANS` |

## Deploy the server

1. Take the server digest from the CI run summary of the commit you are
   deploying. Verify it:

   ```bash
   gh attestation verify oci://ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server@sha256:<digest> \
     --repo chethankumblekar/dependency-check-db-cache
   ```

2. Put that digest in `docker-compose.yml` in place of `:latest`.
3. Copy `.env.example` to `.env` and set what you use (below). `chmod 600 .env`.
4. `docker compose up -d`, then `docker compose ps` shows `healthy`.

The compose file runs the server as uid 999 with every Linux capability
dropped, `no-new-privileges`, a read-only root filesystem, a 256 MB `/tmp`,
and a process limit. It publishes the port on `127.0.0.1` only. To serve other
machines, put a TLS reverse proxy in front and change the settings below; do
not publish `0.0.0.0:8765` with `CHECKSTEAD_LOCAL=1`.

Behind a reverse proxy:

| Setting | Value |
| --- | --- |
| `CHECKSTEAD_LOCAL` | `0`. Localhost sign-in is off, and GitHub App pages need an administrator session even from a loopback peer. |
| `CHECKSTEAD_PUBLIC_BASE` | The origin users type, `https://checkstead.example`. OAuth callbacks and the Origin check use it. |
| `CHECKSTEAD_ALLOWED_HOSTS` | Any other host name the proxy forwards, comma separated. Other `Host` values get 421. |
| `CHECKSTEAD_COOKIE_SECURE` | `1`. Cookies get `Secure` and responses send HSTS. |

An existing volume or bind mount that uid 999 does not own: start the
container once with `--user 0`. The entrypoint hands the directory to uid 999
and drops to it. Or `chown -R 999:999` the host directory.

## Configuration reference

Scan client:

| Variable | Default | Effect |
| --- | --- | --- |
| `CHECKSTEAD_CACHE` | `~/.cache/checkstead` | Snapshot cache. Shared safely by parallel scans on one machine. |
| `CHECKSTEAD_UNTRUSTED_SOURCE` | unset | `1` turns off analyzers that run yarn, pnpm, go, mix, bundle-audit, or swift in the scanned tree. Set it for fork pull requests. The Action sets it in pull-request mode. The GitHub App scan always uses it. |
| `CHECKSTEAD_SCAN_TIMEOUT_MINUTES` | `120` | Stops Dependency-Check and its child processes after this long. `0` means no limit. Exit code 124. |
| `CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE` | unset | `1` refuses an unsigned snapshot even with an empty trust file. Any pinned key already requires a signature, and the shipped store pins one. |
| `CHECKSTEAD_SNAPSHOT_TRUST` | shipped store | Path to a trust file that replaces the shipped keys, for a company mirror. Must pin at least one key. |
| `CHECKSTEAD_SNAPSHOT_MAX_AGE_DAYS` | `7` | Age after which a snapshot is `stale`. |
| `CHECKSTEAD_FAIL_STALE_SNAPSHOT` | unset | `1` fails a scan on a stale snapshot. Use it in CI when a missed update must stop builds. |
| `CHECKSTEAD_ALLOW_SNAPSHOT_ROLLBACK` | unset | `1` accepts a snapshot older than one this cache already used. Only for a deliberate withdrawal. |
| `CHECKSTEAD_HTTP_ATTEMPTS` | `4` | Attempts for a transient network failure (5xx, 429, timeout), with 1, 2, 4 s backoff. |
| `CHECKSTEAD_MAX_ARCHIVE_BYTES` | 8 GiB | Largest uncompressed size of a snapshot or repository zip. |
| `CHECKSTEAD_MAX_ARCHIVE_MEMBERS` | 500000 | Most entries in one zip. |

Server, in addition to the reverse-proxy settings above:

| Variable | Effect |
| --- | --- |
| `CHECKSTEAD_DATA`, `CHECKSTEAD_SCANS` | Data and scan directories. The data directory is set to mode 0700, the account database to 0600. |
| `CHECKSTEAD_GITHUB_CLIENT_ID`, `CHECKSTEAD_GITHUB_CLIENT_SECRET`, `CHECKSTEAD_GITHUB_ORG` | GitHub sign-in, optionally limited to one organization's members. |
| `CHECKSTEAD_ENTRA_CLIENT_ID`, `CHECKSTEAD_ENTRA_CLIENT_SECRET` | Microsoft Entra sign-in. |
| `CHECKSTEAD_ENTRA_TENANT` | Your directory (tenant) id. Only that directory may sign in. With `organizations` (the default), any directory may, and the server warns at start. |
| `CHECKSTEAD_ENTRA_ALLOWED_TENANTS` | With `organizations`, the directory ids that may sign in. |

Every account still has to be added by an administrator before it can sign
in, except the first one.

## Secrets

| Secret | Where | Scope | Rotation |
| --- | --- | --- | --- |
| `NVD_API_KEY` | Secret of the `snapshot-signing` environment (see custody) | `update-snapshot.yml` only. Scans strip it from the engine environment. | Request a new key from NVD, replace the secret, the next run uses it. |
| `CHECKSTEAD_SNAPSHOT_SIGNING_KEY` | Secret of the `snapshot-signing` environment, Ed25519 PKCS#8 PEM | `update-snapshot.yml` on `main` only | See key management. |
| `CHECKSTEAD_SNAPSHOT_KEY_ID` | Repository variable | Names the key in each manifest | Changes with the key. |
| `AZURE_MARKETPLACE_TOKEN` | Repository secret | `release.yml`, Marketplace publish only | Azure DevOps PAT expiry. |
| OAuth client secrets | Server `.env` | Server process only. The scan engine never receives them: every variable named like a secret, token, password, or key is removed from its environment. | Rotate at the identity provider, update `.env`, `docker compose up -d`. |
| GitHub App private key | `CHECKSTEAD_DATA/github-app/private-key.pem`, mode 0600 | Server | Generate a new key on the app's GitHub settings page, replace the file, delete the old key on GitHub. |

`checkstead doctor` prints which of these are set, never their values.

### Signing key custody

A repository secret can be read by any workflow file on any branch that a
person with write access pushes, so a branch could print it. The updater job
runs in the `snapshot-signing` environment; once the environment is limited
to `main` and holds the secrets, a workflow on another branch cannot read
them. Set it up once:

```bash
# Allow only the default branch to use the environment.
gh api -X PUT repos/chethankumblekar/dependency-check-db-cache/environments/snapshot-signing \
  -F 'deployment_branch_policy[protected_branches]=false' \
  -F 'deployment_branch_policy[custom_branch_policies]=true'
gh api -X POST repos/chethankumblekar/dependency-check-db-cache/environments/snapshot-signing/deployment-branch-policies \
  -f name=main -f type=branch
# Move the secrets into it (the key is read from your offline copy).
gh secret set CHECKSTEAD_SNAPSHOT_SIGNING_KEY --env snapshot-signing < snapshot-signing.pem
gh secret set NVD_API_KEY --env snapshot-signing
# Then remove the repository-level copies.
gh secret delete CHECKSTEAD_SNAPSHOT_SIGNING_KEY
gh secret delete NVD_API_KEY
```

On 20 October 2026 the key was rotated this way: `checkstead-2026-10b` lives
only in the environment secret, and `checkstead-2026-10` is retired with
`notAfter` 2026-10-20. The online key has no offline copy, by design: it
never leaves the environment. Recovery from losing it is the standby key
below, not a backup of the online key. Never copy a key out of a workflow. After the move, `validate_only` runs dispatched
from a branch run without the secrets: they test the update and the canary,
not signing. Do not add required reviewers to the environment: the daily run
would wait for an approval every night.

What remains: the key is software-held. A maintainer with admin on the
repository can still change the environment's rules. A hardware or cloud KMS
signer would remove the private key from GitHub entirely; the client's trust
format does not need to change for that.

## Snapshot signing key management

A signature means something only when clients pin the public key.
`src/checkstead/snapshot_trust.json` pins `checkstead-2026-10b` as `current`
and `checkstead-2026-10` as `retired` (`notAfter` 2026-10-20), so clients
refuse an unsigned snapshot, a signature that does not verify, and a key that
is not pinned. Clients carry the trust file inside the release, so any change
to it reaches clients only through a new release.

The first release with that pin needs a snapshot signed by that key. Run the
updater right after merging (`gh workflow run update-snapshot.yml`). Its seed
is the last unsigned snapshot, which the pinned client refuses, so that first
run rebuilds from the NVD and takes longer.

A company that runs its own updater and mirror pins its own key: write a
trust file in the same format and set `CHECKSTEAD_SNAPSHOT_TRUST=/path/to/trust.json`
on every client. It replaces the shipped keys, and a file with no keys is
refused. `checkstead doctor` prints which trust file and keys are in use.

Create and pin a key:

```bash
checkstead snapshot-key generate --id checkstead-2026-10 --out snapshot-signing.pem
```

The command writes the private key with mode 0600 and prints the trust entry.
Then:

1. Store the file's contents as the `snapshot-signing` environment secret
   and the id as that environment's variable, then delete the file:

   ```bash
   gh secret set CHECKSTEAD_SNAPSHOT_SIGNING_KEY --env snapshot-signing < snapshot-signing.pem
   gh variable set CHECKSTEAD_SNAPSHOT_KEY_ID --env snapshot-signing --body checkstead-2026-10
   ```
2. Run the updater once (`gh workflow run update-snapshot.yml`). Its job
   summary shows the same trust entry and says the key is not pinned yet.
3. Add the entry to `keys` in `src/checkstead/snapshot_trust.json` in a
   reviewed pull request, and release Checkstead.

From that release on, clients refuse an unsigned snapshot, a signature that
does not verify, and a key that is not pinned. A key that already exists as a
secret: `checkstead snapshot-key public --id <id>` with the secret in
`CHECKSTEAD_SNAPSHOT_SIGNING_KEY` prints its trust entry.

Rotate:

1. Generate the new key and add its entry as `current` next to the old one.
   Release that client.
2. Set `notAfter` on the old entry to the last day it signs, and change its
   status to `retired`. A retired key still verifies snapshots it signed up to
   `notAfter`, and the updater refuses to sign with it.
3. Switch the environment secret and variable to the new key.

### Standby key

Pin a second `current` key whose private half never touches GitHub or CI.
Every client release then already trusts it, so losing the online key does
not need a client release (`tests/test_key_management.py`,
`test_an_offline_standby_key_takes_over_without_a_client_release`). The
nightly job summary says "No standby key is pinned" until one is.

1. On a machine you trust, write the key straight to the offline medium (an
   encrypted USB drive, or a password manager's file attachment):

   ```bash
   checkstead snapshot-key generate --id checkstead-standby-2026-10 --out /Volumes/<offline>/checkstead-standby-2026-10.pem
   ```

   The command prints only the public trust entry. Keep a second offline
   copy in a different place; two people should know where both are.
2. Add the printed entry to `keys` in `src/checkstead/snapshot_trust.json`
   with `"status": "current"`, in a reviewed pull request, and release.
3. Once a year, check that both offline copies still open and that
   `checkstead snapshot-key public --key <file> --id <id>` prints the pinned
   entry.

### Lost online key

The environment secret was deleted or overwritten, or GitHub lost it.

1. Put the standby in the environment from its offline copy:
   `gh secret set CHECKSTEAD_SNAPSHOT_SIGNING_KEY --env snapshot-signing < <file>`
   and `gh variable set CHECKSTEAD_SNAPSHOT_KEY_ID --env snapshot-signing --body <standby id>`.
2. Run `gh workflow run update-snapshot.yml` and check the release with
   `scripts/verify-snapshot-pin.py`. Clients accept it with no upgrade.
3. The standby is now the online key. Generate a new standby, pin it, and
   release, then remove the lost key's entry in the same release.

Without a standby, clients refuse snapshots signed by a new key until they
upgrade; they keep scanning against their cached snapshot and report it as
stale.

### Compromise

Retiring is not enough. `notAfter` is compared with `snapshotTime`, a field
the signer writes, so whoever holds a stolen key can backdate a manifest that
a `retired` entry still accepts (`test_a_compromised_key_is_removed_not_retired`).

1. Remove the stolen key's entry from `snapshot_trust.json` and release.
   Snapshots it signed, including good ones, stop verifying in that release.
2. Sign with the standby (Lost online key, step 1), or rotate as above if the
   standby could also be exposed. Run the updater with `full_rebuild` so no
   seed signed by the stolen key is reused.
3. Delete the suspicious `db-*` releases. Clients with a cache of one keep it
   for the rest of that UTC day; tell teams to clear
   `~/.cache/checkstead/<day>`.

## Snapshot updater

The updater runs at 01:00 UTC. It starts from the last published snapshot,
verified like a scan verifies one, and fetches only what changed, which takes
minutes. On Sundays, or when dispatched with `full_rebuild`, it rebuilds from
the NVD, which can take more than two hours; the job allows 330 minutes.

```bash
gh workflow run update-snapshot.yml
gh workflow run update-snapshot.yml -f full_rebuild=true
```

A run that finds today's `db-*` release exits without doing anything. A run
that fails publishes nothing, and clients keep the previous snapshot.

Before publishing, every run scans a digest-pinned `commons-collections`
3.2.1 jar with the new database and refuses to publish unless
`CVE-2015-6420` is found. An empty, truncated, or wrongly migrated database
stops there. `--nvdValidForHours 0` makes the NVD query happen even when the
seed was checked recently.

To exercise the whole path against the real NVD without publishing:

```bash
gh workflow run update-snapshot.yml -f validate_only=true
```

The job summary shows where it started from, how many NVD records and
batches it applied, the canary result, and the zip checksum. On 20 October
2026 run [39401035176](https://github.com/chethankumblekar/dependency-check-db-cache/actions/runs/39401035176)
seeded from the signed `db-2026-10-20`, applied 48 changed NVD records in one
batch (10 s), found the canary, and signed with `checkstead-2026-10`; the job
took 51 s.

## Capacity

Measured on 20 October 2026 with `scripts/load-test.py` against `checkstead ui`
on an Apple Silicon laptop (Python 3.14), 204 scans in the timeline, keep-alive
clients, a mix of `/api/health`, `/api/history`, `/`, and `/api/session`:

| Test | Result |
| --- | --- |
| Load, 16 clients, 20 s | 940 to 1,160 req/s, 0 errors, p95 57 to 64 ms. Before the history cache: 42 req/s, p95 1,476 ms. |
| Stress, doubling from 16 | 0 errors up to 256 clients (1,130 req/s, p95 508 ms). At 512, past the 256-connection cap, extra connections get 503 by design. Recovery afterwards: 0 errors. |
| Slow clients, 50 half-sent requests | All 50 dropped after the 30 s socket timeout; normal traffic meanwhile 1,678 req/s, 0 errors. |
| Soak, 32 clients, 20 min, before the leak fix | 1,130,698 requests, 0 errors, p95 103 to 143 ms, but open files rose from 231 to 1,396 and memory to 470 MB: one SQLite handle per session check. |
| Soak, 32 clients, 20 min, fixed | 871,666 requests, 0 errors, 467 to 997 req/s, p95 109 to 248 ms. Open files flat at 38. Memory flat at about 34 MB. |

The server is one process. Throughput is bound by Python's GIL, not by
threads, so add replicas behind the proxy for more. `CHECKSTEAD_MAX_CONNECTIONS`
(default 256) caps concurrent connections; past it a client gets 503 with
`Retry-After: 1`. Run the tests against a loopback test server:

```bash
python3 scripts/load-test.py load --base http://127.0.0.1:8765
python3 scripts/load-test.py stress --base http://127.0.0.1:8765
python3 scripts/load-test.py slow --base http://127.0.0.1:8765
python3 scripts/load-test.py soak --base http://127.0.0.1:8765 --seconds 3600 --pid <server pid>
```

## Monitoring

| Signal | Where | Alert when |
| --- | --- | --- |
| Snapshot freshness | `update-snapshot.yml` run history; `gh release list` | No new `db-*` release for 2 days. Clients print `snapshot-freshness: stale` after 7. |
| Snapshot integrity | Each scan prints `snapshot-authenticity` | A pinned client prints `unsigned`, or a scan fails with "signature does not verify". |
| Server health | `GET /api/health`, the image `HEALTHCHECK` | Not `healthy` for 2 minutes. |
| Server refusals | 421 (unknown host) and 403 (cross-site) responses at the proxy | A burst: a misconfigured proxy, or a rebinding or CSRF attempt. |
| Scan timeouts | Exit code 124 in CI | Repeated timeouts on one repository. |
| Image gates | `images` and `publish-images` jobs | Any failure. The publish job stops before moving tags. |
| Dependabot | Pull requests | A security update left unmerged for 7 days. |

## Incident response

| Event | First steps |
| --- | --- |
| A published image is vulnerable or suspect | Find the last good digest in an earlier CI summary. `bash scripts/rollback-image.sh ghcr.io/...@sha256:<digest>`, pin that digest in compose, `docker compose up -d`. Then fix forward; the next publish moves `latest`. |
| A snapshot is wrong or tampered | Delete the `db-*` release. Run `update-snapshot.yml` with `full_rebuild`. If clients already used it, they refuse an older replacement; tell them to set `CHECKSTEAD_ALLOW_SNAPSHOT_ROLLBACK=1` for one scan or wait for the next day's snapshot. If the signing key is involved, follow the compromise steps above. |
| `NVD_API_KEY` leaked | Request a new key, replace the secret. Scans never held it. |
| OAuth secret or GitHub App key leaked | Rotate at the provider (table above). Delete all sessions: stop the server, `sqlite3 $CHECKSTEAD_DATA/accounts.sqlite 'DELETE FROM sessions'`, start it. |
| A user account is compromised | An administrator removes it in the UI. Its sessions are deleted with it. |
| A scan ran untrusted code | It should not: GitHub App scans and pull-request scans turn the tool-running analyzers off. If a CI scan of a fork ran without `CHECKSTEAD_UNTRUSTED_SOURCE=1`, treat the runner as compromised and rotate what it could read. |

Report vulnerabilities in Checkstead as described in `SECURITY.md`.

## Backup and recovery

Back up both volumes: `checkstead-data` (accounts, sessions, profile
pictures, GitHub App files) and `checkstead-scans` (the timeline's history;
reports can be pulled again from CI artifacts, but not their order). Run the
scripts in the directory that holds `docker-compose.yml`. They find the
volumes from compose, so the project name does not matter, and they use the
server's own image, so nothing else is pulled.

```bash
bash scripts/backup-server.sh /secure/backups
```

It stops the server for the few seconds the archives take, writes
`checkstead-checkstead-data-<time>.tgz` and `checkstead-checkstead-scans-<time>.tgz`
with mode 0600, and starts the server again. The data archive holds the
GitHub App private key and live session hashes; store it encrypted, with the
same access as the key itself.

Restore on a new host, or after losing the volumes, before anyone can reach
the server (with an empty data volume, the first person to sign in becomes
the administrator):

```bash
bash scripts/restore-server.sh /secure/backups/checkstead-*-<time>.tgz
```

It refuses a volume that already holds files, so it never mixes two
servers' accounts; a server that has already started once has written an
empty account database, so use `--force` there. Owners (uid 999) and modes
(0600 for `accounts.sqlite`) come back as they were, sessions stay valid, and
it waits until the server is healthy.

`scripts/deploy-recovery-test.sh <image>` runs this whole cycle in a clean
directory with the shipped `docker-compose.yml`: deploy, sign in, add a user
and a scan, back up, `docker compose down -v`, restore, and check that the
session, the user, the scan, and the file modes survived and that a second
restore is refused. CI runs it on every pull request against the image it
built.

## Release

1. CI is green on `main`, and `bash scripts/check-release.sh` passes locally.
2. Update `CHANGELOG.md`. Tag `vX.Y.Z-rc.N`, check the release candidate
   images in the CI summary, then tag `vX.Y.Z`.
3. The tag build publishes images without the layer cache, gates the pushed
   digests, attests them, and only then moves `X.Y.Z` and `X.Y`.
   `release.yml` creates the GitHub release, moves the `vX` and `vX.Y` Action
   tags, and publishes the Azure DevOps extension.
4. Record the two digests from the run summary in the release notes.

An `engine.version` change needs a snapshot built by the new engine first;
clients refuse a snapshot from another engine. Remove lines from
`scripts/engine-overrides.txt` that the new engine already fixes; the
installer refuses an override whose jar is gone.

## Rollback

Images: pull and pin the previous digest (above). Nothing in this repository
moves `latest` backwards; the next good publish moves it forward.

Action and integrations: users pinned to `vX.Y.Z` are unaffected. To withdraw
a release, move `vX` and `vX.Y` back with `scripts/move-release-tags.sh` on the
previous tag and mark the bad GitHub release as a pre-release.

Snapshots: see incident response.
