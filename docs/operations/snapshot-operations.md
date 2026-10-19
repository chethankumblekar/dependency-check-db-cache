# Snapshot operations

## Publish

Workflow: `.github/workflows/update-snapshot.yml`. Schedule: 01:00 UTC.
Manual: the same workflow, `workflow_dispatch`.

The job checks out this repository, installs the pinned engine, and runs
`scripts/update-snapshot.sh`.

1. Refuse when `NVD_API_KEY` is missing. The key is not written into the
   snapshot and the script does not echo it.
2. If the GitHub release `db-YYYY-MM-DD` already exists, exit 0 and do not
   call NVD.
3. Install Dependency-Check. The signature must verify and `--version` must
   report `engine.version`.
4. Run `--updateonly` with the key and `--nvdApiDelay 6000`. A non-zero exit
   stops the script before a release is created.
5. Zip the data directory, write `manifest.json` from those bytes, and write
   `checkstead-db.zip.sha256`.
6. Refuse to publish when the zip is empty or the manifest checksum does not
   match the zip.
7. If `CHECKSTEAD_SNAPSHOT_SIGNING_KEY` and `CHECKSTEAD_SNAPSHOT_KEY_ID`
   are set, sign the manifest with that Ed25519 key. The key id must be a
   `current` key in `src/checkstead/snapshot_trust.json`, and the private key
   must match the pinned public key. The private key is not written into the
   release. If those variables are unset, the manifest stays unsigned.
8. `gh release create db-YYYY-MM-DD --latest` with the manifest, the zip, and
   the checksum file.

The workflow concurrency group is `checkstead-snapshot` with
`cancel-in-progress: false`. Two workflow runs do not overlap. Two copies of
the script started outside that group can both pass the "release does not
exist" check. The second `gh release create` then fails. The first release
stays. That race is acceptable. Do not delete the day's release to "retry"
unless the published zip is known to be wrong.

There is no second updater. The old `update-db.yml` workflow, which published
an unchecksummed database built by Dependency-Check 12.1.8, is not in this
repository.

## Consume

`checkstead scan` reads the manifest URL from `checkstead.yml` or the default
in `src/checkstead/config.py`. The default is the `releases/latest` asset
`manifest.json` on this repository.

For the UTC day in `CHECKSTEAD_TODAY` or the real UTC date:

- Cache hit: parse the cached manifest and hash the cached zip. A mismatch
  raises `SnapshotRefused` and tells you to remove
  `~/.cache/checkstead/<UTC date>/`. The previous files are left in place so
  a failed comparison does not destroy them silently, and the scan does not
  pretend the cache is valid.
- Cache miss: download the manifest, download the zip to a `.partial` file,
  replace the destination only after the stream finishes, compare the
  SHA-256, then write the manifest. A checksum mismatch deletes the new zip
  and does not write the manifest. An interrupted download deletes the
  partial file.
- A lock file `~/.cache/checkstead/.lock` is held with `flock` for the
  resolution, so two scans on one machine do not write the same day directory
  at once.

Extraction happens when the scan is not a dry run, into `<day>/data`, through
`safe_extract`. Members that escape the directory, including symlink members
that point outside it, are refused.

The engine then runs with that data directory and `--noupdate`. The command
does not receive `--nvdApiKey`. `NVD_API_KEY` is removed from the child
environment.

## Failure messages

| Condition | What you see |
| --- | --- |
| Manifest HTTP 404 | The public snapshot has not been published yet. Set `NVD_API_KEY` and run the updater. |
| Manifest is not JSON, or the format, time, or checksum is wrong | `SnapshotRefused`. Nothing is scanned. |
| Manifest engine is not the pin | The scan stops before Dependency-Check starts. |
| Zip checksum does not match | The new zip is removed. The scan stops. |
| Cached zip no longer matches | Remove that UTC day directory and scan again. |
| Archive path or symlink escapes | `SnapshotRefused`. The escaped file is not written. |
| Engine is missing or not executable | The scan stops before analysis. |
| Dependency-Check exits non-zero | Checkstead exits with that status. It does not turn the failure into a pass. |

## Signature

`src/checkstead/snapshot_trust.json` is the trust root. It lists public keys
and no private keys. The file in this revision has an empty `keys` list.
Checksummed snapshots still scan, including ones the publisher has signed
but this client cannot check yet. That signature is reported as `unsigned`.
It is not a verified signature.

Do not pin a public key before a signed `db-YYYY-MM-DD` release exists.
Pinning first turns `signature_required` on and refuses the unsigned caches
already in use.

To sign, then pin:

1. On a machine that is not CI, run `openssl genpkey -algorithm ED25519 -out snapshot-signing-key.pem` and `openssl pkey -in snapshot-signing-key.pem -pubout`. Do not commit the private PEM and do not print it.
2. Store the private PEM in the GitHub secret `CHECKSTEAD_SNAPSHOT_SIGNING_KEY` and the id in the repository variable `CHECKSTEAD_SNAPSHOT_KEY_ID`. Only `update-snapshot.yml` receives them. Leave `snapshot_trust.json` empty.
3. The next new `db-YYYY-MM-DD` release is signed. Clients with an empty trust file still accept it by checksum. `CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE=1` refuses that signature until the key is pinned.
4. After that signed release exists, add the public PEM to `snapshot_trust.json` with that `id`, `"status": "current"`, and no `notAfter`. Clients that take the pin then verify the signature and refuse an unsigned manifest, including an older checksummed cache.
5. To rotate, add the new key as `current` and set the old key to `"status": "retired"` with `notAfter` set to the last snapshot day it may cover. Publish the pin before signing with the new key. A retired key still verifies snapshots on or before `notAfter`. It cannot sign a new manifest.

A valid signature means the manifest matches a key pinned in that client. It does not mean a second organization published the zip. Leave `CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE` unset, and leave the trust file empty, until a signed snapshot has been published and the matching public key is ready to pin. Do not commit a private key.

## Freshness

A scan prints `snapshot-freshness` and `snapshot-authenticity`.

| Status | Meaning |
| --- | --- |
| `current` | Manifest time is the scan's UTC day or one day older. |
| `aging` | Older than one day, and not past `CHECKSTEAD_SNAPSHOT_MAX_AGE_DAYS` (default 7). |
| `stale` | Older than that maximum. The scan warns and continues. |
| `unavailable` | The manifest or zip could not be downloaded, and there is no usable cache for that UTC day. The scan stops. |
| `cache=hit` | This UTC day's cached manifest was reused. The client did not download again, even if the release changed. |
| `cache=fetched` | This scan downloaded the manifest and the zip. |
| `unsigned` | No signature was verified. The trust file is empty, so a missing signature and a signature this client cannot check both land here. |
| `signed key=<id>` | The pinned key verified the manifest. |

`CHECKSTEAD_FAIL_STALE_SNAPSHOT=1` turns `stale` into a failure. The default leaves it as a warning so an offline scan of a verified cache still runs. To force a new download, remove `~/.cache/checkstead/<UTC date>/`. To publish a replacement for a bad day, delete that `db-YYYY-MM-DD` release only when you intend every later cache miss to see the new one. Caches that already verified the old zip keep it until the directory is removed.

Offline use of a verified cache does not contact GitHub or the NVD.
