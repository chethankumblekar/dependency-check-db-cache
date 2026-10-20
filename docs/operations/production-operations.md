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
| `CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE` | unset | `1` refuses an unsigned snapshot even with an empty trust file. Any pinned key already requires a signature. |
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
| `NVD_API_KEY` | Repository secret | `update-snapshot.yml` only. Scans strip it from the engine environment. | Request a new key from NVD, replace the secret, the next run uses it. |
| `CHECKSTEAD_SNAPSHOT_SIGNING_KEY` | Repository secret, Ed25519 PKCS#8 PEM | `update-snapshot.yml` only | See key management. |
| `CHECKSTEAD_SNAPSHOT_KEY_ID` | Repository variable | Names the key in each manifest | Changes with the key. |
| `AZURE_MARKETPLACE_TOKEN` | Repository secret | `release.yml`, Marketplace publish only | Azure DevOps PAT expiry. |
| OAuth client secrets | Server `.env` | Server process only. The scan engine never receives them: every variable named like a secret, token, password, or key is removed from its environment. | Rotate at the identity provider, update `.env`, `docker compose up -d`. |
| GitHub App private key | `CHECKSTEAD_DATA/github-app/private-key.pem`, mode 0600 | Server | Generate a new key on the app's GitHub settings page, replace the file, delete the old key on GitHub. |

`checkstead doctor` prints which of these are set, never their values.

## Snapshot signing key management

A signature means something only when clients pin the public key. With an
empty `src/checkstead/snapshot_trust.json`, a signed snapshot is recorded as
`snapshot-authenticity: unsigned`. That is the state on 20 October 2026.

Create and pin a key:

```bash
checkstead snapshot-key generate --id checkstead-2026-10 --out snapshot-signing.pem
```

The command writes the private key with mode 0600 and prints the trust entry.
Then:

1. Store the file's contents as the repository secret
   `CHECKSTEAD_SNAPSHOT_SIGNING_KEY` and the id as the repository variable
   `CHECKSTEAD_SNAPSHOT_KEY_ID`. Keep an offline copy, then delete the file.
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
3. Switch the secret and the variable to the new key.

Compromise: set the old key's `notAfter` to the day before the earliest
suspicious snapshot, release the client, and rotate as above. Delete the
suspicious `db-*` releases. Clients with a cache of one keep it for the rest of
that UTC day; tell teams to clear `~/.cache/checkstead/<day>`.

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

Back up `CHECKSTEAD_DATA` (accounts, sessions, GitHub App files). Scan reports
in `CHECKSTEAD_SCANS` can be pulled again from CI artifacts but are the
timeline's history, so back them up too.

```bash
docker compose stop checkstead
docker run --rm -v checkstead_checkstead-data:/data -v "$PWD":/backup alpine \
  tar -C /data -czf /backup/checkstead-data-$(date -u +%Y%m%d).tgz .
docker compose start checkstead
```

Restore into an empty volume with `tar -xzf` the same way, then
`docker compose up -d`. The archive holds the GitHub App private key; store it
encrypted, with the same access as the secret itself. Losing `CHECKSTEAD_DATA`
loses accounts and the app key, not scan data: the first person to sign in
becomes the administrator again, so restore before you expose the server.

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
