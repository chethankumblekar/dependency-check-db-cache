#!/usr/bin/env bash
# Check release inputs on this checkout. Does not create a tag, release, or image.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
export PYTHONPATH="${root}/src${PYTHONPATH:+:$PYTHONPATH}"

python3 -m unittest tests.test_release -v
python3 scripts/write-sbom.py "${root}/build/checkstead-sbom.cdx.json"
python3 -m checkstead version
python3 -m checkstead doctor
echo "Release validation did not publish."
