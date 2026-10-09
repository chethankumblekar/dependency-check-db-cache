#!/usr/bin/env bash
# Lint, build, and test. CI runs this before it publishes container images.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if ! command -v ruff >/dev/null 2>&1; then
  echo "ruff is not on PATH. Install ruff==0.14.2 and run this again." >&2
  exit 1
fi
if ! python3 -c "import build" >/dev/null 2>&1; then
  echo "The build module is not installed. Install build==1.3.0 and run this again." >&2
  exit 1
fi

ruff check src tests
python3 -m compileall -q src tests
for script in scripts/*.sh; do
  bash -n "$script"
done
python3 -m unittest discover -s tests -v
python3 -m build --wheel --outdir "$root/build/wheel"
mvn -B -f integrations/maven/pom.xml verify
