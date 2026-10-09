#!/usr/bin/env bash
# Publish a stamped VSIX when the marketplace token is set. Otherwise leave the package on the GitHub release.
set -euo pipefail

vsix=${1:?usage: publish-azure-extension.sh path/to/checkstead.vsix}
token=${AZURE_MARKETPLACE_TOKEN:-}
publisher=${AZURE_MARKETPLACE_PUBLISHER:-}

if [[ -z "$token" ]]; then
  echo "AZURE_MARKETPLACE_TOKEN is not set."
  echo "The VSIX is attached to the GitHub release. Marketplace publish was skipped."
  echo "Create a publisher at https://marketplace.visualstudio.com/manage"
  echo "Then set AZURE_MARKETPLACE_TOKEN to a PAT with Marketplace (publish) scope,"
  echo "and AZURE_MARKETPLACE_PUBLISHER to that publisher id."
  exit 0
fi

if [[ -z "$publisher" ]]; then
  echo "AZURE_MARKETPLACE_PUBLISHER is not set." >&2
  exit 1
fi

npx --yes tfx-cli@0.24.2 extension publish \
  --vsix "$vsix" \
  --publisher "$publisher" \
  --auth-type pat \
  --token "$token" \
  --no-wait-validation
echo "Published ${vsix} for publisher ${publisher}."
