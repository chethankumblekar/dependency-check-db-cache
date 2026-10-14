#!/usr/bin/env bash
# Install Checkstead for a Mac user under $HOME/checkstead.
# A second run leaves Python, java, the pinned engine, and the package in place.
# This script does not call the NVD and does not publish a database.
set -euo pipefail

ROOT="$HOME/checkstead"
PACKAGE_URL="https://github.com/chethankumblekar/dependency-check-db-cache/archive/refs/heads/main.tar.gz"
PIN_URL="https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/engine.version"
PATH_MARKER="# checkstead setup: user install on PATH"
PATH_LINE='export PATH="$HOME/checkstead/bin:$PATH"'
JDK_MARKER="# checkstead setup: bundled JDK"

python_ok() {
  local bin=$1
  [[ -x "$bin" ]] || return 1
  "$bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'
}

select_python() {
  local candidate resolved
  if python_ok "$ROOT/python/bin/python3"; then
    echo "$ROOT/python/bin/python3"
    return 0
  fi
  for candidate in python3.13 python3.12 python3.11 python3; do
    resolved=$(command -v "$candidate" 2>/dev/null || true)
    if [[ -n "$resolved" ]] && python_ok "$resolved"; then
      echo "$resolved"
      return 0
    fi
  done
  return 1
}

java_runs() {
  # /usr/bin/java on macOS is a stub. It is present, prints a dialog, and exits 1.
  java -version >/dev/null 2>&1
}

engine_reports_pin() {
  local bin=$1 reported
  [[ -x "$bin" ]] || return 1
  reported=$("$bin" --version 2>&1 || true)
  grep -Eq "(^|[[:space:]])${PIN}($|[[:space:]])" <<< "$reported"
}

find_pinned_engine() {
  local candidate
  local -a candidates=(
    "$ROOT/dependency-check/bin/dependency-check.sh"
    "$(command -v dependency-check.sh 2>/dev/null || true)"
    "$(command -v dependency-check 2>/dev/null || true)"
    "/opt/dependency-check/bin/dependency-check.sh"
  )
  for candidate in "${candidates[@]}"; do
    [[ -n "$candidate" ]] || continue
    if engine_reports_pin "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

require_mac() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Installing Python or a JDK this way needs macOS." >&2
    exit 1
  fi
}

install_python() {
  local arch url tmp
  require_mac
  case "$(uname -m)" in
    arm64|aarch64) arch=aarch64 ;;
    x86_64) arch=x86_64 ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
  url="https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15+20261013-${arch}-apple-darwin-install_only.tar.gz"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/python.tar.gz" "$url"
  tar -xzf "$tmp/python.tar.gz" -C "$tmp"
  rm -rf "$ROOT/python"
  mkdir -p "$ROOT"
  mv "$tmp/python" "$ROOT/python"
  rm -rf "$tmp"
  echo "Installed Python under $ROOT/python"
}

install_jdk() {
  local arch url tmp found home
  require_mac
  case "$(uname -m)" in
    arm64|aarch64) arch=aarch64 ;;
    x86_64) arch=x64 ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
  url="https://api.adoptium.net/v3/binary/latest/21/ga/mac/${arch}/jdk/hotspot/normal/eclipse"
  tmp=$(mktemp -d)
  curl -fsSL -L -o "$tmp/jdk.tgz" "$url"
  tar -xzf "$tmp/jdk.tgz" -C "$tmp"
  found=$(find "$tmp" -type f -path '*/bin/java' | head -n 1)
  if [[ -z "$found" ]]; then
    echo "The JDK archive did not contain bin/java." >&2
    exit 1
  fi
  home=$(cd "$(dirname "$found")/.." && pwd)
  rm -rf "$ROOT/jdk"
  mkdir -p "$ROOT"
  mv "$home" "$ROOT/jdk"
  rm -rf "$tmp"
  echo "Installed a JDK under $ROOT/jdk"
}

install_engine() {
  local url tmp src candidate
  url="https://github.com/dependency-check/DependencyCheck/releases/download/v${PIN}/dependency-check-${PIN}-release.zip"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/dc.zip" "$url"
  unzip -q "$tmp/dc.zip" -d "$tmp/unpacked"
  src=""
  for candidate in "$tmp/unpacked"/dependency-check*; do
    if [[ -d "$candidate" && -f "$candidate/bin/dependency-check.sh" ]]; then
      src=$candidate
      break
    fi
  done
  if [[ -z "$src" ]]; then
    echo "The Dependency-Check archive did not contain bin/dependency-check.sh" >&2
    exit 1
  fi
  chmod +x "$src/bin/dependency-check.sh"
  rm -rf "$ROOT/dependency-check"
  mkdir -p "$ROOT"
  mv "$src" "$ROOT/dependency-check"
  rm -rf "$tmp"
  if ! engine_reports_pin "$ROOT/dependency-check/bin/dependency-check.sh"; then
    echo "Refusing the downloaded engine. Expected ${PIN}." >&2
    exit 1
  fi
  echo "Installed Dependency-Check ${PIN} under $ROOT/dependency-check"
}

ensure_engine_wrapper() {
  local bin upstream
  bin="$ROOT/dependency-check/bin/dependency-check.sh"
  upstream="$ROOT/dependency-check/bin/dependency-check.upstream.sh"
  if [[ ! -f "$bin" && ! -f "$upstream" ]]; then
    return 0
  fi
  if [[ -f "$bin" ]] && ! grep -q "checkstead setup: yarn audit" "$bin"; then
    mv "$bin" "$upstream"
  fi
  if [[ -f "$upstream" ]]; then
    chmod +x "$upstream"
  fi
  cat > "$bin" <<'EOF'
#!/bin/sh
# checkstead setup: yarn audit
# A missing yarn makes Dependency-Check exit 14 after the reports are written.
upstream=$(CDPATH= cd "$(dirname "$0")" && pwd)/dependency-check.upstream.sh
if [ "${1:-}" = "--version" ] || [ "${1:-}" = "-v" ]; then
  exec "$upstream" "$@"
fi
for arg in "$@"; do
  if [ "$arg" = "--disableYarnAudit" ]; then
    exec "$upstream" "$@"
  fi
done
version=$(yarn --version 2>/dev/null || true)
version=$(printf '%s' "$version" | tr -d '[:space:]')
if [ -z "$version" ]; then
  exec "$upstream" --disableYarnAudit "$@"
fi
exec "$upstream" "$@"
EOF
  chmod +x "$bin"
}

read_pin() {
  local reported
  if [[ -x "$ROOT/venv/bin/checkstead" ]]; then
    reported=$("$ROOT/venv/bin/checkstead" version 2>/dev/null || true)
    reported=$(tr -d '[:space:]' <<< "$reported")
    if [[ "$reported" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$reported"
      return 0
    fi
  fi
  local script_dir version_file
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  version_file="$script_dir/../engine.version"
  if [[ -f "$version_file" ]]; then
    tr -d '[:space:]' < "$version_file"
    return 0
  fi
  curl -fsSL "$PIN_URL"
}

ensure_command() {
  mkdir -p "$ROOT/bin"
  cat > "$ROOT/bin/checkstead" <<'EOF'
#!/bin/sh
# The macOS java stub exits 1. Prefer the JDK installed under $HOME/checkstead.
if ! java -version >/dev/null 2>&1; then
  if [ -x "$HOME/checkstead/jdk/bin/java" ]; then
    export JAVA_HOME="$HOME/checkstead/jdk"
    export PATH="$JAVA_HOME/bin:$PATH"
  fi
fi
exec "$HOME/checkstead/venv/bin/checkstead" "$@"
EOF
  chmod +x "$ROOT/bin/checkstead"
}

ensure_path() {
  local profile changed=0
  for profile in "$HOME/.zprofile" "$HOME/.zshrc"; do
    if [[ -f "$profile" ]] && grep -F "$PATH_MARKER" "$profile" >/dev/null 2>&1; then
      continue
    fi
    printf '\n%s\n%s\n' "$PATH_MARKER" "$PATH_LINE" >> "$profile"
    changed=1
  done
  if [[ "$changed" -eq 0 ]]; then
    echo "PATH already includes \$HOME/checkstead/bin."
  else
    echo "Added \$HOME/checkstead/bin to the shell PATH."
  fi
}

ensure_jdk_shell() {
  local profile changed=0
  for profile in "$HOME/.zprofile" "$HOME/.zshrc"; do
    if [[ -f "$profile" ]] && grep -F "$JDK_MARKER" "$profile" >/dev/null 2>&1; then
      continue
    fi
    printf '\n%s\nexport JAVA_HOME="$HOME/checkstead/jdk"\nexport PATH="$JAVA_HOME/bin:$PATH"\n' "$JDK_MARKER" >> "$profile"
    changed=1
  done
  if [[ "$changed" -eq 0 ]]; then
    echo "JAVA_HOME already prefers \$HOME/checkstead/jdk."
  else
    echo "Put \$HOME/checkstead/jdk/bin ahead of /usr/bin."
  fi
}

mkdir -p "$ROOT"

if python=$(select_python); then
  echo "Python 3.11+ already present."
else
  install_python
  python="$ROOT/python/bin/python3"
fi

bundled_jdk=0
if java_runs; then
  echo "java already runs."
elif [[ -x "$ROOT/jdk/bin/java" ]]; then
  echo "JDK already installed."
  bundled_jdk=1
else
  install_jdk
  bundled_jdk=1
fi
if [[ "$bundled_jdk" -eq 1 ]]; then
  export JAVA_HOME="$ROOT/jdk"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

PIN=$(read_pin)
PIN=$(tr -d '[:space:]' <<< "$PIN")
if [[ ! "$PIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Refusing to install. The engine pin is not a release number: ${PIN}" >&2
  exit 1
fi

if find_pinned_engine >/dev/null; then
  echo "Dependency-Check ${PIN} already present."
else
  install_engine
fi

ensure_engine_wrapper

checkstead_current() {
  local scan
  [[ -x "$ROOT/venv/bin/checkstead" ]] || return 1
  "$ROOT/venv/bin/checkstead" version >/dev/null 2>&1 || return 1
  scan=$(find "$ROOT/venv" -path '*/checkstead/scan.py' -print -quit 2>/dev/null || true)
  if [[ -z "$scan" ]]; then
    return 0
  fi
  if ! grep -q -- '--disableYarnAudit' "$scan"; then
    return 1
  fi
  local score github
  score=$(find "$ROOT/venv" -path '*/checkstead/score.py' -print -quit 2>/dev/null || true)
  github=$(find "$ROOT/venv" -path '*/checkstead/github_app.py' -print -quit 2>/dev/null || true)
  [[ -n "$score" && -n "$github" ]]
}

install_checkstead_package() {
  if [[ ! -x "$ROOT/venv/bin/python" ]]; then
    rm -rf "$ROOT/venv"
    if "$python" -c 'import ensurepip' >/dev/null 2>&1; then
      "$python" -m venv "$ROOT/venv"
    else
      "$python" -m venv --without-pip "$ROOT/venv"
      pip_tmp=$(mktemp -d)
      curl -fsSL -o "$pip_tmp/get-pip.py" https://bootstrap.pypa.io/get-pip.py
      "$ROOT/venv/bin/python" "$pip_tmp/get-pip.py"
      rm -rf "$pip_tmp"
    fi
  fi
  "$ROOT/venv/bin/python" -m pip install --disable-pip-version-check --upgrade --force-reinstall --no-cache-dir "$PACKAGE_URL"
  echo "Installed checkstead under $ROOT/venv"
}

if checkstead_current; then
  echo "checkstead already installed."
else
  install_checkstead_package
fi

ensure_command
ensure_path
if [[ "$bundled_jdk" -eq 1 ]]; then
  ensure_jdk_shell
fi

if [[ "${CHECKSTEAD_LOCAL:-}" == "1" ]]; then
  echo "Checkstead is ready."
else
  echo "Open a new terminal, then run: checkstead scan --scan . --project my-service"
fi
