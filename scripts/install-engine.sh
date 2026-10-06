#!/usr/bin/env bash
# Install the pinned Dependency-Check release and refuse any other version.
set -euo pipefail

DEST=${1:-/opt/dependency-check}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION_FILE=${ENGINE_VERSION_FILE:-"$ROOT/engine.version"}
VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Refusing to install. engine.version is not a release number: ${VERSION}" >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
URL="https://github.com/dependency-check/DependencyCheck/releases/download/v${VERSION}/dependency-check-${VERSION}-release.zip"
curl -fsSL -o "$TMP/dc.zip" "$URL"
unzip -q "$TMP/dc.zip" -d "$TMP/unpacked"
SRC=""
for candidate in "$TMP/unpacked"/dependency-check*; do
  if [[ -d "$candidate" ]]; then
    SRC=$candidate
    break
  fi
done
if [[ -z "${SRC}" || ! -f "${SRC}/bin/dependency-check.sh" ]]; then
  echo "The Dependency-Check archive did not contain bin/dependency-check.sh" >&2
  exit 1
fi
chmod +x "${SRC}/bin/dependency-check.sh"
rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
mv "$SRC" "$DEST"

REPORTED=$("$DEST/bin/dependency-check.sh" --version)
if ! grep -Eq "(^|[[:space:]])${VERSION}($|[[:space:]])" <<< "$REPORTED"; then
  echo "Refusing the downloaded engine. Expected ${VERSION} but it reported: ${REPORTED}" >&2
  exit 1
fi
echo "Installed Dependency-Check ${VERSION} at ${DEST}"
