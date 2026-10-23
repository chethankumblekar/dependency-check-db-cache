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

# CHECKSTEAD_VALIDATE_ONLY=1 runs the whole build, update, canary, and signing
# path against the real NVD and stops before `gh release create`. It is how an
# incremental update is tested on a day that already has a snapshot.
VALIDATE_ONLY=${CHECKSTEAD_VALIDATE_ONLY:-}
if [[ "$VALIDATE_ONLY" != "1" ]] && gh release view "$TAG" >/dev/null 2>&1; then
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
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

# Start from the last published snapshot, verified the way a scan verifies it,
# so --updateonly fetches only what changed. A full rebuild from the NVD takes
# hours and ran past the job timeout. CHECKSTEAD_SEED_MANIFEST= (empty) or a
# failed check forces the full build.
SEED_MANIFEST=${CHECKSTEAD_SEED_MANIFEST-$(python3 -c 'from checkstead.config import DEFAULT_SNAPSHOT_URL; print(DEFAULT_SNAPSHOT_URL)')}
# Sunday, and CHECKSTEAD_FULL_REBUILD=1, rebuild from the NVD so a defect in
# one snapshot cannot be carried forward by incremental updates for long.
if [[ "${CHECKSTEAD_FULL_REBUILD:-}" == "1" || "$(date -u +%u)" == "7" ]]; then
  SEED_MANIFEST=""
fi
SEED_NOTE="Full build. No earlier snapshot was used."
if [[ -n "$SEED_MANIFEST" ]]; then
  if SEED_OUT=$(python3 -m checkstead seed-data --url "$SEED_MANIFEST" --dest "${WORK}/data" --cache "${WORK}/seed-cache"); then
    echo "$SEED_OUT"
    SEED_NOTE="Incremental update from ${SEED_OUT#seed: }."
  else
    echo "Could not use the published snapshot as a starting point. Building the database from the NVD." >&2
    rm -rf "${WORK}/data"
    mkdir -p "${WORK}/data"
  fi
  rm -rf "${WORK}/seed-cache"
fi

# The key is passed only to this update process. It is not written into the snapshot.
# --nvdValidForHours 0: a seed checked a few hours ago would otherwise skip the
# NVD entirely ("Check for updates complete (22 ms)" in a validation run).
UPDATE_STARTED=$(date +%s)
"${ENGINE_DIR}/bin/dependency-check.sh" \
  --updateonly \
  --nvdApiKey "$NVD_API_KEY" \
  --nvdApiDelay 6000 \
  --nvdValidForHours 0 \
  --data "${WORK}/data" \
  --log "$LOG"
UPDATE_SECONDS=$(( $(date +%s) - UPDATE_STARTED ))
NVD_BATCHES=$(grep -c "Completed processing batch" "$LOG" || true)
echo "update: ${UPDATE_SECONDS}s, ${NVD_BATCHES} NVD batches"

# Canary. Before anything is published, the new database has to find a CVE
# that has been in the NVD since 2015 in a jar pinned by digest. An empty,
# truncated, or wrongly migrated database fails here instead of reaching
# every scan. The scan runs on a copy so it cannot change what is zipped.
CANARY_JAR_URL="https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar"
CANARY_JAR_SHA256="87363a4c94eaabeefd8b930cb059f66b64c9f7d632862f23de3012da7660047b"
CANARY_CVE="CVE-2015-6420"
mkdir -p "${WORK}/canary/project"
curl -fsSL --proto '=https' --tlsv1.2 --retry 5 --retry-delay 3 --connect-timeout 30 --max-time 300 \
  -o "${WORK}/canary/project/commons-collections-3.2.1.jar" "$CANARY_JAR_URL"
if [[ "$(sha256sum "${WORK}/canary/project/commons-collections-3.2.1.jar" | cut -d ' ' -f 1)" != "$CANARY_JAR_SHA256" ]]; then
  echo "Refusing to publish. The canary jar does not match its pinned SHA-256." >&2
  exit 1
fi
cp -a "${WORK}/data" "${WORK}/canary/data"
canary_status=0
"${ENGINE_DIR}/bin/dependency-check.sh" \
  --noupdate \
  --disableCentral \
  --disableOssIndex \
  --disableYarnAudit \
  --disableNodeAudit \
  --data "${WORK}/canary/data" \
  --scan "${WORK}/canary/project" \
  --project canary \
  --format JSON \
  --out "${WORK}/canary/out" \
  --log "${WORK}/canary/dependency-check.log" >/dev/null || canary_status=$?
if [[ "$canary_status" -ne 0 ]]; then
  echo "Refusing to publish. The canary scan on the new database exited ${canary_status}." >&2
  exit 1
fi
if ! grep -q "\"${CANARY_CVE}\"" "${WORK}/canary/out/dependency-check-report.json"; then
  echo "Refusing to publish. The canary scan did not find ${CANARY_CVE} in commons-collections 3.2.1." >&2
  exit 1
fi
rm -rf "${WORK}/canary/data"
echo "canary: ${CANARY_CVE} found"

(
  cd "${WORK}/data"
  zip -r -q "${WORK}/checkstead-db.zip" .
)

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

# The private key is a repository secret. It is not written into the release.
# With no key configured, the snapshot stays unsigned and the client records that.
AUTH_NOTE="Unsigned. Integrity is the manifest checksum. No snapshot signing key is configured for this run."
if [[ -n "${CHECKSTEAD_SNAPSHOT_SIGNING_KEY:-}" ]]; then
  if [[ -z "${CHECKSTEAD_SNAPSHOT_KEY_ID:-}" ]]; then
    echo "Refusing to publish. CHECKSTEAD_SNAPSHOT_KEY_ID is required when the signing key is set." >&2
    exit 1
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "Refusing to publish. openssl is required to sign the snapshot." >&2
    exit 1
  fi
  SIGNED_MANIFEST="${WORK}/manifest.json" \
  python3 - <<'PY'
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "src")
from checkstead.errors import ChecksteadError
from checkstead.snapshot import parse_manifest
from checkstead.snapshot_auth import load_trust, sign_manifest

path = Path(os.environ["SIGNED_MANIFEST"])
manifest = parse_manifest(path.read_text(encoding="utf-8"))
try:
    signed = sign_manifest(
        manifest,
        os.environ["CHECKSTEAD_SNAPSHOT_SIGNING_KEY"],
        os.environ["CHECKSTEAD_SNAPSHOT_KEY_ID"],
        load_trust(),
    )
except ChecksteadError as exc:
    print(f"Refusing to publish. {exc}", file=sys.stderr)
    sys.exit(1)
path.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
print(f"signature: {signed['signature']['keyId']}")
PY
  # The public half is safe to show. The maintainer pins it from here.
  python3 -m checkstead snapshot-key public --id "$CHECKSTEAD_SNAPSHOT_KEY_ID" > "${WORK}/trust-entry.json"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### Snapshot signing key"
      echo
      echo "Key id \`${CHECKSTEAD_SNAPSHOT_KEY_ID}\` signed this snapshot."
      if python3 -c 'import os, sys; from checkstead.snapshot_auth import load_trust; sys.exit(0 if os.environ["CHECKSTEAD_SNAPSHOT_KEY_ID"] in load_trust().keys else 1)'; then
        echo "It is pinned in \`src/checkstead/snapshot_trust.json\`. Clients verify it."
        # Recovery from a lost key without a client release needs a second
        # current key whose private half is kept offline.
        if ! python3 -c 'import os, sys; from checkstead.snapshot_auth import load_trust; keys = load_trust().keys; sys.exit(0 if any(k.status == "current" and i != os.environ["CHECKSTEAD_SNAPSHOT_KEY_ID"] for i, k in keys.items()) else 1)'; then
          echo
          echo "**No standby key is pinned.** If this key is lost, clients need a new release before they accept another key. See \"Standby key\" in docs/operations/production-operations.md."
        fi
      else
        echo "It is **not pinned**. Clients record this snapshot as unsigned until this entry is added to \`src/checkstead/snapshot_trust.json\`:"
        echo
        echo '```json'
        cat "${WORK}/trust-entry.json"
        echo '```'
      fi
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  AUTH_NOTE="Signed with the key id in manifest.json. snapshot_trust.json is not updated by this job. Clients with an empty trust file still accept the checksum and do not treat this signature as verified. Pin the public key only after this signed release exists. The signature is not a second publisher."
fi

cat > "${WORK}/notes.md" <<EOF
Dependency-Check ${VERSION}
Snapshot ${SNAPSHOT_TIME}
Checksum sha256:${CHECKSUM}
${AUTH_NOTE}
${SEED_NOTE}

This product uses data from the NVD API but is not endorsed or certified by the NVD.
EOF

ZIP_BYTES=$(wc -c < "${WORK}/checkstead-db.zip" | tr -d ' ')
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Snapshot ${SNAPSHOT_TIME}"
    echo
    echo "| | |"
    echo "| --- | --- |"
    echo "| Mode | $([[ "$VALIDATE_ONLY" == "1" ]] && echo "validate only, not published" || echo "publish ${TAG}") |"
    echo "| Start | ${SEED_NOTE} |"
    echo "| NVD update | ${UPDATE_SECONDS}s, ${NVD_BATCHES} batches |"
    echo "| Canary | ${CANARY_CVE} found |"
    echo "| Zip | ${ZIP_BYTES} bytes, sha256:${CHECKSUM} |"
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ "$VALIDATE_ONLY" == "1" ]]; then
  echo "Validation only. ${TAG} was not published. The manifest and notes are in ${WORK}."
  exit 0
fi

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
