#!/usr/bin/env bash
# Container entrypoint. GitHub Actions passes inputs as INPUT_* variables.
# A direct `docker run` can pass checkstead arguments instead.
set -euo pipefail

if [[ "${1:-}" == "scan" || "${1:-}" == "version" || "${1:-}" == "write-manifest" ]]; then
  exec checkstead "$@"
fi

args=(scan --scan "${INPUT_SCAN:-.}" --out "${INPUT_OUTPUT:-checkstead-report}")
if [[ -n "${INPUT_PROJECT:-}" ]]; then
  args+=(--project "$INPUT_PROJECT")
fi
if [[ -n "${INPUT_CONFIG:-}" ]]; then
  args+=(--config "$INPUT_CONFIG")
fi
exec checkstead "${args[@]}"
