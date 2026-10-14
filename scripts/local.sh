#!/usr/bin/env bash
# Install anything Checkstead still needs, then start the local server.
# A JDK, engine, or package that is already present stays in place.
# This script does not call the NVD and does not publish a database.
set -euo pipefail

setup_url="https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.sh"
export CHECKSTEAD_LOCAL=1

if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  if [[ -f "$here/setup.sh" ]]; then
    bash "$here/setup.sh"
  else
    curl -fsSL "$setup_url" | bash
  fi
else
  curl -fsSL "$setup_url" | bash
fi

python="$HOME/checkstead/venv/bin/python"
package_url="https://github.com/chethankumblekar/dependency-check-db-cache/archive/refs/heads/main.tar.gz"
if [[ -x "$python" ]] && ! "$python" -c 'import checkstead.github_app' >/dev/null 2>&1; then
  "$python" -m pip install --disable-pip-version-check --upgrade --force-reinstall --no-cache-dir "$package_url"
fi

mkdir -p "$HOME/checkstead/scans"
exec "$HOME/checkstead/bin/checkstead" ui --host 127.0.0.1 --port 8765 --scans "$HOME/checkstead/scans"
