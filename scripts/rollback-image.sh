#!/usr/bin/env bash
# Pull one already-published image by digest.
# This does not tag :latest, does not move a floating tag, and does not push.
set -euo pipefail

ref=${1:?usage: rollback-image.sh IMAGE@sha256:<64 hex digits>}
if [[ "$ref" == *":latest"* ]]; then
  echo "Refusing a rollback that names :latest." >&2
  exit 2
fi
if [[ "$ref" == *" "* || "$ref" == *$'\n'* || "$ref" == *$'\t'* ]]; then
  echo "Refusing a rollback reference with whitespace." >&2
  exit 2
fi
if [[ ! "$ref" =~ @sha256:[0-9a-f]{64}$ ]]; then
  echo "A rollback reference must end with @sha256 and 64 hex digits." >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not available. The rollback pull was not run." >&2
  exit 2
fi
docker pull "$ref"
echo "Pulled ${ref}"
echo "Did not tag :latest and did not push."
