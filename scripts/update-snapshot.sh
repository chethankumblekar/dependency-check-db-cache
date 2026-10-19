#!/usr/bin/env bash
# Publish one checksummed database snapshot for the pinned engine.
# A second run on the same UTC day leaves the existing snapshot in place.
# This script does not invent a database. Without NVD_API_KEY it stops.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VERSION=$(tr -d '[:space:]' < engine.version)
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Refusing to publish. engine.version is not a release number: ${VERSION}" >&2
  exit 1
fi

if [[ -z "${NVD_API_KEY:-}" ]]; then
  cat >&2 <<'EOF'
Set the repository secret NVD_API_KEY.
Request a key at https://nvd.nist.gov/developers/request-an-api-key
The key belongs to this updater only. Scans do not use it.
Checkstead does not publish a stand-in database.
EOF
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to publish the snapshot release." >&2
  exit 1
fi

SNAPSHOT_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SNAPSHOT_DAY=${SNAPSHOT_TIME%%T*}
TAG="db-${SNAPSHOT_DAY}"

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "Snapshot ${TAG} is already published. Leaving it in place."
  exit 0
fi

if ! command -v java >/dev/null 2>&1; then
  echo "Java is required to run Dependency-Check ${VERSION}." >&2
  exit 1
fi

ENGINE_DIR="${ROOT}/build/dependency-check"
bash "${ROOT}/scripts/install-engine.sh" "$ENGINE_DIR"

WORK="${ROOT}/build/snapshot"
rm -rf "$WORK"
mkdir -p "$WORK/data"
LOG="${WORK}/dependency-check.log"

# The key is passed only to this update process. It is not written into the snapshot.
"${ENGINE_DIR}/bin/dependency-check.sh" \
  --updateonly \
  --nvdApiKey "$NVD_API_KEY" \
  --nvdApiDelay 6000 \
  --data "${WORK}/data" \
  --log "$LOG"

(
  cd "${WORK}/data"
  zip -r -q "${WORK}/checkstead-db.zip" .
)

export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m checkstead write-manifest \
  --zip "${WORK}/checkstead-db.zip" \
  --out "${WORK}/manifest.json" \
  --time "$SNAPSHOT_TIME"

if [[ ! -s "${WORK}/checkstead-db.zip" ]]; then
  echo "Refusing to publish an empty database zip." >&2
  exit 1
fi

sha256sum "${WORK}/checkstead-db.zip" > "${WORK}/checkstead-db.zip.sha256"
CHECKSUM=$(cut -d ' ' -f 1 "${WORK}/checkstead-db.zip.sha256")

SNAPSHOT_ZIP="${WORK}/checkstead-db.zip" \
SNAPSHOT_MANIFEST="${WORK}/manifest.json" \
SNAPSHOT_SHA="${WORK}/checkstead-db.zip.sha256" \
python3 - <<'PY'
import os
import sys
from pathlib import Path

sys.path.insert(0, "src")
from checkstead.snapshot import parse_manifest, sha256_file

zip_path = Path(os.environ["SNAPSHOT_ZIP"])
manifest = parse_manifest(Path(os.environ["SNAPSHOT_MANIFEST"]).read_text(encoding="utf-8"))
actual = sha256_file(zip_path)
if actual != manifest["checksum"]:
    print("Refusing to publish. The manifest checksum does not match the zip.", file=sys.stderr)
    sys.exit(1)
recorded = Path(os.environ["SNAPSHOT_SHA"]).read_text(encoding="utf-8").split()[0]
if recorded != actual:
    print("Refusing to publish. The checksum file does not match the zip.", file=sys.stderr)
    sys.exit(1)
PY

cat > "${WORK}/notes.md" <<EOF
Dependency-Check ${VERSION}
Snapshot ${SNAPSHOT_TIME}
Checksum sha256:${CHECKSUM}

This product uses data from the NVD API but is not endorsed or certified by the NVD.
EOF

gh release create "$TAG" \
  --latest \
  --title "Database snapshot ${SNAPSHOT_TIME}" \
  --notes-file "${WORK}/notes.md" \
  "${WORK}/manifest.json" \
  "${WORK}/checkstead-db.zip" \
  "${WORK}/checkstead-db.zip.sha256"

echo "Published ${TAG}"
echo "engine: ${VERSION}"
echo "snapshot: ${SNAPSHOT_TIME}"
echo "checksum: sha256:${CHECKSUM}"
