#!/usr/bin/env bash
# Build both images locally and scan them with Trivy. This does not push.
# Exit 2 when docker or trivy is missing. That exit is not a clean scan.
#
# Gates, matching .github/workflows/ci.yml:
#   language packages at HIGH or CRITICAL fail (scanner skips /opt/dependency-check)
#   fixed operating-system HIGH and CRITICAL findings fail
#   Exception unfixed-os-2026-10-19, review 2027-01-19: unfixed OS findings
#   do not fail. Scope is packages with no fixed version, including
#   CVE-2025-7458 and CVE-2023-45853 on the server image. This is not a
#   .trivyignore file. A fixed High or Critical OS package still fails.
# The full scanner report, including the pinned engine jars, is written and
# does not fail this script. There is no .trivyignore.
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
  --vuln-type library \
  --ignore-unfixed=false \
  --exit-code 1 \
  --format json \
  --output build/trivy/server-library.json \
  checkstead-server:local
trivy image \
  --severity CRITICAL,HIGH \
  --vuln-type os \
  --ignore-unfixed \
  --exit-code 1 \
  --format json \
  --output build/trivy/server-os.json \
  checkstead-server:local
trivy image \
  --severity CRITICAL,HIGH \
  --vuln-type library \
  --skip-dirs /opt/dependency-check \
  --ignore-unfixed=false \
  --exit-code 1 \
  --format json \
  --output build/trivy/scanner-library.json \
  checkstead:local
trivy image \
  --severity CRITICAL,HIGH \
  --vuln-type os \
  --ignore-unfixed \
  --exit-code 1 \
  --format json \
  --output build/trivy/scanner-os.json \
  checkstead:local
trivy image \
  --severity CRITICAL,HIGH \
  --exit-code 0 \
  --format json \
  --output build/trivy/scanner.json \
  checkstead:local
echo "Image scans wrote build/trivy/. No image was pushed."
