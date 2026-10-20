#!/usr/bin/env bash
# Build both images locally and run the same Trivy gates CI runs before it
# promotes a published image. This does not push.
# Exit 2 when docker or trivy is missing. That exit is not a clean scan.
# The gate policy, including exception unfixed-os-2026-10-19, is in
# scripts/image-gates.sh. There is no .trivyignore.
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

status=0
bash scripts/image-gates.sh server checkstead-server:local build/trivy || status=$?
bash scripts/image-gates.sh scanner checkstead:local build/trivy || status=$?
echo "Image scans wrote build/trivy/. No image was pushed."
exit "$status"
