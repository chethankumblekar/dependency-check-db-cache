#!/usr/bin/env bash
# Container entrypoint. GitHub Actions passes inputs as INPUT_* variables.
# A direct `docker run` can pass checkstead arguments instead.
set -euo pipefail

# The image starts as root only to choose who to become. It then drops to the
# owner of the working directory (the host user behind `-v "$PWD:/work" -w
# /work`), or to uid 10001 when that owner is root, with every capability
# cleared and no-new-privileges set. The scan never runs as root, and the
# report stays owned by the host user. CHECKSTEAD_ALLOW_ROOT=1 keeps root.
# `docker run --user "$(id -u):$(id -g)"` skips this block entirely.
if [[ "$(id -u)" == "0" && "${CHECKSTEAD_ALLOW_ROOT:-}" != "1" ]]; then
  owner=$(stat -c '%u:%g' . 2>/dev/null || echo "0:0")
  if [[ ! "$owner" =~ ^[0-9]+:[0-9]+$ || "$owner" == 0:* ]]; then
    owner="10001:10001"
  fi
  exec setpriv --reuid="${owner%%:*}" --regid="${owner##*:}" --clear-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs -- "$0" "$@"
fi

# A non-root uid gets a HOME it can write.
if [[ "$(id -u)" != "0" ]]; then
  if [[ -z "${HOME:-}" || ! -w "${HOME}" ]]; then
    HOME="/tmp/checkstead-$(id -u)"
    export HOME
    mkdir -p "$HOME"
  fi
  mkdir -p "${HOME}/.cache/checkstead"
  if [[ -z "${TMPDIR:-}" || ! -w "${TMPDIR}" ]]; then
    TMPDIR="${HOME}/tmp"
    export TMPDIR
    mkdir -p "$TMPDIR"
  fi
fi

if [[ "${1:-}" == "scan" || "${1:-}" == "upload" || "${1:-}" == "version" || "${1:-}" == "write-manifest" || "${1:-}" == "ui" || "${1:-}" == "doctor" ]]; then
  exec checkstead "$@"
fi

args=(scan --scan "${INPUT_SCAN:-.}" --out "${INPUT_OUTPUT:-checkstead-report}")
if [[ -n "${INPUT_PROJECT:-}" ]]; then
  args+=(--project "$INPUT_PROJECT")
fi
if [[ -n "${INPUT_CONFIG:-}" ]]; then
  args+=(--config "$INPUT_CONFIG")
fi
if [[ -n "${INPUT_PULL_REQUEST:-}" ]]; then
  args+=(--pull-request "$INPUT_PULL_REQUEST")
fi
if [[ -n "${INPUT_BASE:-}" ]]; then
  args+=(--base "$INPUT_BASE")
fi
if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
  args+=(--branch "$GITHUB_REF_NAME")
elif [[ -n "${INPUT_BRANCH:-}" ]]; then
  args+=(--branch "$INPUT_BRANCH")
fi
if [[ -n "${GITHUB_SHA:-}" ]]; then
  args+=(--revision "$GITHUB_SHA")
fi
if [[ -n "${CHECKSTEAD_AUTHOR:-}" ]]; then
  args+=(--author "$CHECKSTEAD_AUTHOR")
fi
if [[ -n "${CHECKSTEAD_AUTHOR_EMAIL:-}" ]]; then
  args+=(--author-email "$CHECKSTEAD_AUTHOR_EMAIL")
fi
exec checkstead "${args[@]}"
