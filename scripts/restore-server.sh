#!/usr/bin/env bash
# Restore a Checkstead server deployment from backup-server.sh archives.
#
#   bash scripts/restore-server.sh [--force] ARCHIVE...
#
# Run it where you run docker compose, on a new host or after losing the
# volumes. Each archive is named checkstead-<volume>-<time>.tgz and goes back
# into that compose volume. A volume that already holds files is refused
# without --force, so a restore never mixes two servers' accounts. File
# owners (uid 999) and modes (0600 for accounts.sqlite) come back as they
# were. Restore before you expose the server: with an empty data volume the
# first person to sign in becomes the administrator.
set -euo pipefail

force=0
if [[ "${1:-}" == "--force" ]]; then
  force=1
  shift
fi
if [[ $# -eq 0 ]]; then
  echo "usage: restore-server.sh [--force] ARCHIVE..." >&2
  exit 2
fi
service="${CHECKSTEAD_SERVICE:-checkstead}"

config="$(docker compose config --format json)"
image="$(python3 -c 'import json,sys; c=json.load(sys.stdin); print(c["services"][sys.argv[1]]["image"])' "$service" <<<"$config")"
volume_name() {
  python3 -c '
import json, sys
spec = (json.load(sys.stdin).get("volumes") or {}).get(sys.argv[1])
if not spec:
    sys.exit(1)
print(spec["name"])
' "$1" <<<"$config"
}

# Resolve every archive before touching anything.
plan=""
for archive in "$@"; do
  base="$(basename "$archive")"
  if [[ ! -f "$archive" || "$base" != checkstead-*-*.tgz ]]; then
    echo "restore-server: ${archive} is not a backup-server.sh archive." >&2
    exit 2
  fi
  key="${base#checkstead-}"
  key="${key%-*.tgz}"
  if ! name="$(volume_name "$key")"; then
    echo "restore-server: the compose file has no volume ${key}." >&2
    exit 2
  fi
  plan+="${name} $(cd "$(dirname "$archive")" && pwd)/${base}"$'\n'
done

# Refuse before stopping anything, so a refused restore leaves a running
# server as it was. A volume that does not exist yet is empty.
while read -r name archive; do
  [[ -n "$name" && "$force" != 1 ]] || continue
  docker volume inspect "$name" >/dev/null 2>&1 || continue
  if docker run --rm --network none --user 0 --entrypoint sh \
      -v "${name}:/data:ro" "$image" -c 'find /data -mindepth 1 -not -path /data/scans -print -quit | grep -q .'; then
    echo "restore-server: volume ${name} already holds files. Use --force to replace them." >&2
    exit 1
  fi
done <<<"$plan"

# Create the volumes and the container with their compose labels, without
# starting the server.
docker compose stop "$service" >/dev/null 2>&1 || true
docker compose create "$service" >/dev/null

while read -r name archive; do
  [[ -n "$name" ]] || continue
  docker run --rm -i --network none --user 0 --entrypoint sh \
    -v "${name}:/data" "$image" -c 'find /data -mindepth 1 -maxdepth 1 ! -name scans -exec rm -rf {} + && tar -C /data --same-owner -xzf -' < "$archive"
  echo "restored: ${name} from ${archive}"
done <<<"$plan"

docker compose up -d --wait "$service"
