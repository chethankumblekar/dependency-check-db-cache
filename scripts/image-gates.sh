#!/usr/bin/env bash
# The Trivy gates for one Checkstead image. One policy for local scans, pull
# requests, and the image a publish is about to promote.
#
#   scripts/image-gates.sh scanner|server IMAGE_REF [OUT_DIR]
#
# IMAGE_REF is a local tag (checkstead:ci) or a pushed digest
# (ghcr.io/owner/repo/checkstead@sha256:...). PLATFORMS, comma separated,
# scans each platform of a multi-arch index, for example
# PLATFORMS=linux/amd64,linux/arm64. Unset scans the default platform.
#
# Gates:
#   language packages at HIGH or CRITICAL fail, in both images, including the
#     Dependency-Check engine under /opt/dependency-check. The engine's own
#     vulnerable jars are replaced at install time from
#     scripts/engine-overrides.txt. A new engine CVE fails this gate until it
#     gets an override or a dated exception here.
#   fixed operating-system HIGH and CRITICAL findings fail.
#   Exception unfixed-os-2026-10-19, review 2027-01-19: operating-system
#     findings with no fixed version do not fail. This is --ignore-unfixed on
#     the OS gate only. This is not a .trivyignore file. On 19 October it
#     covered 61 unfixed High and 2 unfixed Critical findings on the server
#     image, including CVE-2025-7458 (libsqlite3-0) and CVE-2023-45853 (zlib1g).
# Exit 1 is a failed gate. Exit 2 means trivy is missing and nothing was scanned.
set -euo pipefail

kind=${1:?usage: image-gates.sh scanner|server IMAGE_REF [OUT_DIR]}
ref=${2:?usage: image-gates.sh scanner|server IMAGE_REF [OUT_DIR]}
out=${3:-build/trivy}
case "$kind" in
  scanner|server) ;;
  *) echo "The first argument is scanner or server." >&2; exit 2 ;;
esac
if ! command -v trivy >/dev/null 2>&1; then
  echo "trivy is not available. The image gates were not run." >&2
  exit 2
fi
mkdir -p "$out"

IFS=, read -r -a platforms <<< "${PLATFORMS:-default}"
failed=0
for platform in "${platforms[@]}"; do
  label=${platform//\//-}
  if [[ "$platform" == "default" ]]; then
    unset TRIVY_PLATFORM
  else
    export TRIVY_PLATFORM=$platform
  fi
  echo "== ${kind} ${platform}: HIGH and CRITICAL language packages"
  if ! trivy image --quiet --scanners vuln --severity CRITICAL,HIGH --pkg-types library \
      --exit-code 1 --format table "$ref" \
      | tee "${out}/${kind}-${label}-library.txt"; then
    failed=1
  fi
  echo "== ${kind} ${platform}: fixed HIGH and CRITICAL operating-system packages"
  if ! trivy image --quiet --scanners vuln --severity CRITICAL,HIGH --pkg-types os \
      --ignore-unfixed --exit-code 1 --format table "$ref" \
      | tee "${out}/${kind}-${label}-os.txt"; then
    failed=1
  fi
  # Report only. Everything, including unfixed OS findings.
  trivy image --quiet --scanners vuln --severity CRITICAL,HIGH --exit-code 0 \
    --format json --output "${out}/${kind}-${label}-report.json" "$ref"
  trivy image --quiet --format cyclonedx --output "${out}/${kind}-${label}-sbom.cdx.json" "$ref"
done

if [[ "$failed" -ne 0 ]]; then
  echo "Image gates failed for ${ref}. See ${out}." >&2
  exit 1
fi
echo "Image gates passed for ${ref}. Reports and SBOMs are in ${out}."
