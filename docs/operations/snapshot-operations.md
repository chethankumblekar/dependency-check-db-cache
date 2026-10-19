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
7. `gh release create db-YYYY-MM-DD --latest` with the manifest, the zip, and
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

## Freshness

A snapshot is "current" when it is the release tagged for that UTC day and
marked latest. A consumer that already cached an earlier manifest today keeps
it. That favors repeatability over picking up a republish. To force a new
download, remove the day directory. To publish a replacement for a bad day,
delete that `db-YYYY-MM-DD` release only when you intend every later cache
miss to see the new one. Caches that already verified the old zip keep it
until the directory is removed.

Offline use of a verified cache does not contact GitHub or the NVD. Do not
add a maximum age that fails those scans unless you also keep a way to run
with the cache you already verified.
