#!/usr/bin/env bash
# Deploy the server from docker-compose.yml into a clean directory, use it,
# back it up, destroy it, restore it, and check nothing was lost.
#
#   bash scripts/deploy-recovery-test.sh IMAGE
#
# IMAGE is a built server image, for example checkstead-server:ci. Exit 0 is a
# pass; exit 2 means docker is missing and nothing was checked.
set -euo pipefail

image="${1:?usage: deploy-recovery-test.sh IMAGE}"
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "deploy-recovery-test: docker compose is not available. Nothing was checked." >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
project="checkstead-recovery-$$"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
base="http://127.0.0.1:${port}"
export COMPOSE_PROJECT_NAME="$project"

cleanup() {
  (cd "$work/deploy" 2>/dev/null && docker compose down -v --remove-orphans >/dev/null 2>&1) || true
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  (cd "$work/deploy" && docker compose logs --no-color --tail 50) >&2 || true
  exit 1
}

# The shipped compose file, changed only in the image and the host port.
mkdir -p "$work/deploy" "$work/backup"
python3 - "$root/docker-compose.yml" "$work/deploy/docker-compose.yml" "$image" "$port" <<'PY'
import sys
source, target, image, port = sys.argv[1:]
text = open(source, encoding="utf-8").read()
original = "image: ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server:latest"
assert text.count(original) == 1, "docker-compose.yml image line changed"
assert text.count('"127.0.0.1:8765:8765"') == 1, "docker-compose.yml port line changed"
text = text.replace(original, f"image: {image}").replace('"127.0.0.1:8765:8765"', f'"127.0.0.1:{port}:8765"')
open(target, "w", encoding="utf-8").write(text)
PY
cp "$root/.env.example" "$work/deploy/.env"
chmod 600 "$work/deploy/.env"
cd "$work/deploy"

echo "== deploy"
docker compose up -d --wait checkstead || fail "the server did not become healthy"
[[ "$(docker compose ps --format '{{.Health}}' checkstead)" == "healthy" ]] || fail "not healthy"
container="$(docker compose ps -q checkstead)"
[[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.Config.User}}' "$container")" == "true 999:999" ]] \
  || fail "the container is not read-only as uid 999"

jar="$work/cookies"
api() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -b "$jar" -c "$jar" -X "$method" -H "Origin: ${base}" -H "Content-Type: application/json" "$@" "${base}${path}"
}

echo "== use"
api POST /api/session/local -d '{}' >/dev/null || fail "localhost sign-in failed"
api GET /api/session | grep -q '"role": "admin"' || fail "the first sign-in is not the administrator"
api POST /api/admin/users -d '{"provider":"github","login":"recovery-check","role":"user"}' >/dev/null \
  || fail "could not add a user"
docker run --rm --network none --user 0 --entrypoint sh \
  -v "${project}_checkstead-scans:/scans" -v "$root/ui/scans/01-fixture-a:/in:ro" "$image" \
  -c 'mkdir -p /scans/01-fixture-a && cp -R /in/. /scans/01-fixture-a/ && chown -R 999:999 /scans/01-fixture-a'
api GET /api/history | grep -q '01-fixture-a' || fail "the scan report is not in the timeline"
sessions_before="$(api GET /api/session)"

echo "== back up"
bash "$root/scripts/backup-server.sh" "$work/backup"
archives=("$work"/backup/*.tgz)
[[ ${#archives[@]} -eq 2 ]] || fail "expected two archives, found ${#archives[@]}"
for archive in "${archives[@]}"; do
  [[ "$(python3 -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$archive")" == "0o600" ]] \
    || fail "$archive is not mode 0600"
done
docker compose ps --format '{{.State}}' checkstead | grep -q running || fail "the server did not start again after the backup"

echo "== destroy"
docker compose down -v
[[ -z "$(docker volume ls -q --filter "name=^${project}_")" ]] || fail "volumes survived down -v"

echo "== restore"
bash "$root/scripts/restore-server.sh" "${archives[@]}"
[[ "$(api GET /api/session)" == "$sessions_before" ]] || fail "the session did not survive the restore"
api GET /api/admin/users | grep -q 'recovery-check' || fail "the added user is gone"
api GET /api/history | grep -q '01-fixture-a' || fail "the scan report is gone"
container="$(docker compose ps -q checkstead)"
docker exec "$container" stat -c '%u %a' /var/lib/checkstead/accounts.sqlite | grep -qx '999 600' \
  || fail "accounts.sqlite is not owned by 999 with mode 600"

echo "== a restore does not overwrite a live server"
if bash "$root/scripts/restore-server.sh" "${archives[@]}" 2>"$work/refused"; then
  fail "restore replaced a volume that already held data"
fi
grep -q "already holds files" "$work/refused" || fail "the refusal did not say why"
docker compose ps --format '{{.Health}}' checkstead | grep -qx healthy || fail "a refused restore stopped the server"

echo "PASS deploy, back up, destroy, restore"
