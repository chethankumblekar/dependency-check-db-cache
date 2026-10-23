#!/usr/bin/env bash
# Back up a Docker Compose deployment of the Checkstead server.
#
#   bash scripts/backup-server.sh OUTDIR
#
# Run it in the directory that holds docker-compose.yml (or set
# COMPOSE_FILE / COMPOSE_PROJECT_NAME the way you run compose). It stops the
# server so SQLite is quiet, writes one archive per volume (accounts and
# GitHub App files; scan reports), and starts the server again. The archive
# is made with the server's own image, so nothing else is pulled.
#
# The data archive holds the GitHub App private key and the session table.
# Store it encrypted, with the same access as that key.
set -euo pipefail

out="${1:?usage: backup-server.sh OUTDIR}"
service="${CHECKSTEAD_SERVICE:-checkstead}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

config="$(docker compose config --format json)"
image="$(python3 -c 'import json,sys; c=json.load(sys.stdin); print(c["services"][sys.argv[1]]["image"])' "$service" <<<"$config")"
volumes="$(python3 -c '
import json, sys
config = json.load(sys.stdin)
for key, spec in sorted((config.get("volumes") or {}).items()):
    print(key + " " + spec["name"])
' <<<"$config")"
if [[ -z "$volumes" ]]; then
  echo "backup-server: the compose file names no volumes." >&2
  exit 1
fi

docker compose stop "$service"
trap 'docker compose start "$service" >/dev/null' EXIT
# The archive streams out, so it is written by you with mode 0600, not by
# the container's root.
umask 077
while read -r key name; do
  archive="${out}/checkstead-${key}-${stamp}.tgz"
  docker run --rm --network none --user 0 --entrypoint tar \
    -v "${name}:/data:ro" "$image" -C /data -czf - . > "$archive"
  echo "backup: ${archive}"
done <<<"$volumes"
