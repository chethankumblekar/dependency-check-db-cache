#!/usr/bin/env bash
# Build both images locally and scan them with Trivy. This does not push.
# Exit 2 when docker or trivy is missing. The server-image library scan
# fails the script on CRITICAL. The scanner-image report is written either way:
# its findings are inside the pinned Dependency-Check distribution.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not available. The image scan was not run." >&2
  exit 2
fi
if ! command -v trivy >/dev/null 2>&1; then
  echo "trivy is not available. The image scan was not run." >&2
  exit 2
fi

docker build -t checkstead:local .
docker build -f Dockerfile.server -t checkstead-server:local .

mkdir -p build/trivy
trivy image \
  --severity CRITICAL,HIGH \
  --exit-code 0 \
  --format json \
  --output build/trivy/scanner.json \
  checkstead:local
trivy image \
  --severity CRITICAL \
  --vuln-type library \
  --exit-code 1 \
  --format json \
  --output build/trivy/server-library.json \
  checkstead-server:local
echo "Image scans wrote build/trivy/. No image was pushed."
