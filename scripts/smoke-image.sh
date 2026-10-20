#!/usr/bin/env bash
# Start a built image and check that it does what the deployment docs promise.
#
#   scripts/smoke-image.sh scanner|server IMAGE_REF
#
# scanner: reports the engine pin, runs as a non-root uid, and refuses to
#   scan when no snapshot is reachable, instead of calling the NVD.
# server: runs as uid 999 with no capabilities and a read-only root
#   filesystem, becomes healthy, answers /api/health, and refuses a Host
#   name it was not configured for.
# Exit 2 when docker is missing. That exit is not a pass.
set -euo pipefail

kind=${1:?usage: smoke-image.sh scanner|server IMAGE_REF}
ref=${2:?usage: smoke-image.sh scanner|server IMAGE_REF}
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not available. The smoke test was not run." >&2
  exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
pin=$(tr -d '[:space:]' < "$root/engine.version")

fail() {
  echo "smoke: $*" >&2
  exit 1
}

if [[ "$kind" == "scanner" ]]; then
  reported=$(docker run --rm --user 10001:10001 "$ref" version)
  [[ "$reported" == "$pin" ]] || fail "scanner reported '${reported}', expected ${pin}"
  uid=$(docker run --rm --user 10001:10001 --entrypoint id "$ref" -u)
  [[ "$uid" == "10001" ]] || fail "scanner did not run as the requested uid"
  docker run --rm --user 10001:10001 "$ref" doctor >/dev/null || fail "doctor failed"
  # No network: the scan must stop at the snapshot, not reach for the NVD.
  set +e
  output=$(docker run --rm --network none --user 10001:10001 -w /tmp "$ref" \
    scan --scan /tmp --out /tmp/out --dry-run 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail "a scan with no network did not fail"
  grep -q "snapshot" <<< "$output" || fail "the offline scan did not name the snapshot: ${output}"
  if grep -q "services.nvd.nist.gov" <<< "$output" && ! grep -q "Refusing" <<< "$output"; then
    fail "the offline scan tried the NVD"
  fi
  echo "smoke: scanner ${ref} ok (pin ${pin}, uid 10001, offline scan refused)"
  exit 0
fi

[[ "$kind" == "server" ]] || fail "the first argument is scanner or server"
name="checkstead-smoke-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp:size=64m \
  -p 127.0.0.1::8765 "$ref" >/dev/null

for _ in $(seq 1 60); do
  health=$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo unknown)
  [[ "$health" == "healthy" ]] && break
  if [[ "$(docker inspect -f '{{.State.Running}}' "$name")" != "true" ]]; then
    docker logs "$name" >&2 || true
    fail "server exited"
  fi
  sleep 2
done
[[ "$health" == "healthy" ]] || { docker logs "$name" >&2; fail "server did not become healthy"; }

uid=$(docker exec "$name" id -u)
[[ "$uid" == "999" ]] || fail "server runs as uid ${uid}, expected 999"
port=$(docker port "$name" 8765/tcp | head -n 1 | sed 's/.*://')
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/api/health")
[[ "$code" == "200" ]] || fail "/api/health returned ${code}"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: rebind.example" "http://127.0.0.1:${port}/api/history")
[[ "$code" == "421" ]] || fail "a foreign Host returned ${code}, expected 421"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/api/history")
[[ "$code" == "401" ]] || fail "/api/history without a session returned ${code}, expected 401"
echo "smoke: server ${ref} ok (uid 999, no capabilities, read-only root, healthy, Host checked)"
