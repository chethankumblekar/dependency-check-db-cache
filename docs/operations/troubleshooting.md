# Troubleshooting

`checkstead doctor` prints the Checkstead version, the engine pin, the engine
path, the cache directory, and whether `NVD_API_KEY` and the OAuth secrets
are set. It prints `set` or `unset`. It does not print the secret.

## The scan exits 2

Exit code 2 is `SnapshotRefused` or `RefusedHost`.

- The message names `services.nvd.nist.gov`: the manifest or a redirect
  pointed at the NVD API. Use the Checkstead manifest URL.
- The message says cleartext HTTP: the snapshot URL is `http://` to a host
  other than loopback. Use `https://`.
- The message names an engine version: the snapshot was built by a different
  Dependency-Check than `engine.version`. Do not point a 13.0.0 client at a
  database built before the 12.2.2 schema change.
- The message says the checksum does not match: the zip and the manifest
  disagree. For a cache, remove `~/.cache/checkstead/<UTC date>/` and scan
  again. For a publish, the updater refuses to create the release.
- The message says the archive escapes its directory: do not use that zip.

## The scan exits with Dependency-Check's status

Checkstead returns that status. A policy failure (threshold, KEV, or an
unscored finding when those settings say so) is a non-zero exit from
Checkstead's own check. An engine crash is the engine's status. Neither is
reported as a successful scan.

## The first scan of the day is slow, the second is not

The first scan downloads the snapshot. Later scans that UTC day reuse the
cache and still pass `--noupdate`. If the published manifest changes during
the day, the cache is unchanged on purpose. Remove the day directory when you
need the new manifest.

## The updater did not publish

- `NVD_API_KEY` is missing. Add the repository secret and run
  `update-snapshot.yml`. Scans do not take this key.
- The log says the snapshot is already published. That day already has a
  release. Leave it, or delete it only if you mean to replace it.
- The engine did not report the pin, or the signature did not verify. The
  install stops. No release is created.
- `gh release create` failed after a second local run raced the first. The
  existing release is the one to keep.

The key is not in the workflow log. Do not add `echo "$NVD_API_KEY"`.

## The timeline asks anyone who can connect to become administrator

You published the server port and left `CHECKSTEAD_LOCAL=1`. Compose binds
`127.0.0.1:8765:8765`. A container that is started with `-p 8765:8765` is
reachable on the host's addresses. Use `-p 127.0.0.1:8765:8765`, or set
`CHECKSTEAD_LOCAL=0` and configure GitHub or Entra sign-in. Set
`CHECKSTEAD_COOKIE_SECURE=1` behind TLS.

Accounts live in `CHECKSTEAD_DATA` or `~/.local/share/checkstead`. In the
server image that directory is `/var/lib/checkstead`. Copy that volume to
back it up. Scans in the container are `/var/lib/checkstead/scans`.

## Docker build of the scanner fails on the engine signature

`gpg` has to verify the zip before the image keeps it. A changed
`engine.version` needs a real upstream release and a signature from the same
pinned key. Do not replace the key to make a download succeed, and do not
invent a checksum.

## `scripts/scan-images.sh` exits 2

Docker or Trivy is not on `PATH`. The script did not scan and did not push.
Install both tools and run it again. Exit 1 from that script is a Critical
library finding in the server image.
