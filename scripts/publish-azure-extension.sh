#!/usr/bin/env bash
# Publish a stamped VSIX when the marketplace token is set. Otherwise leave the package on the GitHub release.
set -euo pipefail

vsix=${1:?usage: publish-azure-extension.sh path/to/checkstead.vsix}
token=${AZURE_MARKETPLACE_TOKEN:-}
publisher=${AZURE_MARKETPLACE_PUBLISHER:-}

if [[ -z "$token" ]]; then
  echo "AZURE_MARKETPLACE_TOKEN is not set."
  echo "The VSIX is attached to the GitHub release. Marketplace publish was skipped."
  echo "You do not need an Azure DevOps organization."
  echo "Upload the VSIX at https://marketplace.visualstudio.com/manage :"
  echo "create a publisher, then New extension, Azure DevOps."
  echo "The package is public. Other organizations install it themselves."
  echo "A token is only for this automatic upload."
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
