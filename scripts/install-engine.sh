#!/usr/bin/env bash
# Install the pinned Dependency-Check release and refuse any other version.
# The zip is verified with the vendored public key before it is extracted.
# That key is Jeremy Long's release key, fingerprint pinned below. The
# fingerprint was read from the Ubuntu keyserver, not from the GitHub asset.
set -euo pipefail

DEST=${1:-/opt/dependency-check}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION_FILE=${ENGINE_VERSION_FILE:-"$ROOT/engine.version"}
VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")
KEY_FILE=${ENGINE_PUBLIC_KEY:-"$ROOT/scripts/keys/dependency-check-release.asc"}
EXPECTED_FPR=${ENGINE_KEY_FINGERPRINT:-259A55407DD6C00299E6607EFFDE55BE73A2D1ED}
ARCHIVE=${CHECKSTEAD_ARCHIVE:-"$ROOT/src/checkstead/archive.py"}
# Patched library jars. Empty string skips them, which only tests should do.
OVERRIDES=${ENGINE_OVERRIDES-"$ROOT/scripts/engine-overrides.txt"}
MAVEN_CENTRAL=${ENGINE_MAVEN_CENTRAL:-https://repo1.maven.org/maven2}

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Refusing to install. engine.version is not a release number: ${VERSION}" >&2
  exit 1
fi
if [[ ! -f "$KEY_FILE" ]]; then
  echo "Refusing to install. Engine signing key is missing: ${KEY_FILE}" >&2
  exit 1
fi
if [[ ! -f "$ARCHIVE" ]]; then
  echo "Refusing to install. Archive extractor is missing: ${ARCHIVE}" >&2
  exit 1
fi
if ! command -v gpg >/dev/null 2>&1; then
  echo "Refusing to install. gpg is required to verify the Dependency-Check signature." >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
URL="https://github.com/dependency-check/DependencyCheck/releases/download/v${VERSION}/dependency-check-${VERSION}-release.zip"
fetch() {
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 5 --retry-delay 3 --retry-connrefused \
    --connect-timeout 30 --max-time 1200 \
    -o "$1" "$2"
}
fetch "$TMP/dc.zip" "$URL"
fetch "$TMP/dc.zip.asc" "${URL}.asc"

GNUPGHOME="$TMP/gnupg"
export GNUPGHOME
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
gpg --batch --import "$KEY_FILE" >/dev/null
FPR=$(gpg --batch --with-colons --show-keys "$KEY_FILE" | awk -F: '/^fpr:/ {print $10; exit}')
if [[ "$FPR" != "$EXPECTED_FPR" ]]; then
  echo "Refusing engine key. Expected fingerprint ${EXPECTED_FPR} but found ${FPR:-none}." >&2
  exit 1
fi
if ! gpg --batch --verify "$TMP/dc.zip.asc" "$TMP/dc.zip" >"$TMP/gpg.out" 2>&1; then
  echo "Refusing the downloaded engine. The release signature does not verify." >&2
  cat "$TMP/gpg.out" >&2
  exit 1
fi

python3 "$ARCHIVE" "$TMP/dc.zip" "$TMP/unpacked"
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

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [[ -n "$OVERRIDES" ]]; then
  if [[ ! -f "$OVERRIDES" ]]; then
    echo "Refusing to install. Engine override list is missing: ${OVERRIDES}" >&2
    exit 1
  fi
  while read -r jar path digest extra; do
    [[ -z "${jar:-}" || "$jar" == \#* ]] && continue
    if [[ -n "${extra:-}" || ! "$jar" =~ ^[A-Za-z0-9._-]+\.jar$ || ! "$path" =~ ^[A-Za-z0-9._/-]+\.jar$ || "$path" == *..* || ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
      echo "Refusing to install. Bad line in ${OVERRIDES}: ${jar} ${path}" >&2
      exit 1
    fi
    if [[ ! -f "${SRC}/lib/${jar}" ]]; then
      echo "Refusing to install. ${jar} is not in Dependency-Check ${VERSION}. Remove its override." >&2
      exit 1
    fi
    fetch "$TMP/override.jar" "${MAVEN_CENTRAL}/${path}"
    actual=$(sha256_of "$TMP/override.jar")
    if [[ "$actual" != "$digest" ]]; then
      echo "Refusing ${path}. Expected SHA-256 ${digest} but downloaded ${actual}." >&2
      exit 1
    fi
    mv "$TMP/override.jar" "${SRC}/lib/${jar}"
    echo "Replaced lib/${jar} with ${path##*/}"
  done < "$OVERRIDES"
fi

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
mv "$SRC" "$DEST"

REPORTED=$("$DEST/bin/dependency-check.sh" --version)
if ! grep -Eq "(^|[[:space:]])${VERSION}($|[[:space:]])" <<< "$REPORTED"; then
  echo "Refusing the downloaded engine. Expected ${VERSION} but it reported: ${REPORTED}" >&2
  rm -rf "$DEST"
  exit 1
fi
echo "Installed Dependency-Check ${VERSION} at ${DEST}"
