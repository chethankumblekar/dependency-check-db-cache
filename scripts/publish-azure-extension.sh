#!/usr/bin/env bash
# The release pipeline publishes the stamped VSIX. Both settings are required.
set -euo pipefail

vsix=${1:?usage: publish-azure-extension.sh path/to/checkstead.vsix}
token=${AZURE_MARKETPLACE_TOKEN:-}
publisher=${AZURE_MARKETPLACE_PUBLISHER:-}

if [[ -z "$token" || -z "$publisher" ]]; then
  echo "The release pipeline publishes this extension." >&2
  echo "Set the secret AZURE_MARKETPLACE_TOKEN and the variable AZURE_MARKETPLACE_PUBLISHER." >&2
  echo "The token is a Marketplace (Publish) personal access token." >&2
  echo "The variable is the publisher id from https://marketplace.visualstudio.com/manage." >&2
  exit 1
fi

npx --yes tfx-cli@0.24.2 extension publish \
  --vsix "$vsix" \
  --publisher "$publisher" \
  --auth-type pat \
  --token "$token" \
  --no-wait-validation
echo "Published ${vsix} for publisher ${publisher}."
