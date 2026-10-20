#!/usr/bin/env bash
# Install Checkstead under $HOME/checkstead on macOS or Linux.
# A second run leaves Python, java, the pinned engine, and the package in place.
# This script does not call the NVD and does not publish a database.
# Windows uses scripts/setup.ps1.
set -euo pipefail

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "On Windows, open PowerShell and run: irm https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.ps1 | iex" >&2
    exit 1
    ;;
esac

ROOT="$HOME/checkstead"
# CHECKSTEAD_REF installs a release tag instead of the main branch, for example
# CHECKSTEAD_REF=v0.1.1. A tag is what a production install should name.
REF=${CHECKSTEAD_REF:-main}
if [[ ! "$REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$ || "$REF" == *..* ]]; then
  echo "CHECKSTEAD_REF is not a branch or tag name: ${REF}" >&2
  exit 1
fi
if [[ "$REF" == v[0-9]* ]]; then
  PACKAGE_URL="https://github.com/chethankumblekar/dependency-check-db-cache/archive/refs/tags/${REF}.tar.gz"
else
  PACKAGE_URL="https://github.com/chethankumblekar/dependency-check-db-cache/archive/refs/heads/${REF}.tar.gz"
fi
PIN_URL="https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/${REF}/engine.version"
PATH_MARKER="# checkstead setup: user install on PATH"
PATH_LINE='export PATH="$HOME/checkstead/bin:$PATH"'
JDK_MARKER="# checkstead setup: bundled JDK"
# Jeremy Long's Dependency-Check release key. The fingerprint is the pin.
# ENGINE_KEY_FINGERPRINT overrides it only for the installer tests.
ENGINE_FPR_DEFAULT=259A55407DD6C00299E6607EFFDE55BE73A2D1ED
ENGINE_KEY_URL="https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/${REF}/scripts/keys/dependency-check-release.asc"
ENGINE_ARCHIVE_URL="https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/${REF}/src/checkstead/archive.py"

# Every download is https only, retried on a transient failure, and bounded in
# time. --retry-all-errors is not used because older Linux curl lacks it.
fetch() {
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 5 --retry-delay 3 --retry-connrefused \
    --connect-timeout 30 --max-time 1200 \
    -o "$1" "$2"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Refuse a download whose SHA-256 is not the pinned value. The pins below were
# read from the upstream release API and checked against GitHub's asset digest.
verify_sha256() {
  local file=$1 expected=$2 what=$3 actual
  actual=$(sha256_of "$file")
  if [[ "$actual" != "$expected" ]]; then
    echo "Refusing ${what}. Expected SHA-256 ${expected} but downloaded ${actual}." >&2
    rm -f "$file"
    exit 1
  fi
}

# python-build-standalone 20261013, CPython 3.12.15, install_only archives.
PYTHON_RELEASE="https://github.com/astral-sh/python-build-standalone/releases/download/20261013"
python_sha256() {
  case "$1" in
    aarch64-apple-darwin) echo ba32036ad8f4c434d97a1ee7feef8b7edc0fac16777639b97e39c74a108e4440 ;;
    x86_64-apple-darwin) echo 9686ddd8639b855905447ea4a16eb54a804a9ef12afbe7c9ecb1412d9c1fbc98 ;;
    aarch64-unknown-linux-gnu) echo 34a43010cc05982d8b5debbad7d09f7b1200117ebf018f7acfd656895e408205 ;;
    x86_64-unknown-linux-gnu) echo 5d546fc004fc2435fa142eb8f42ed8de5eb4725963dc22f7e6671014a80eb560 ;;
    *) return 1 ;;
  esac
}

# Eclipse Temurin jdk-21.0.12.1+1. A fixed release, not "latest", so the
# digest below is the file that is installed.
JDK_RELEASE="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1"
jdk_asset() {
  case "$1" in
    mac/aarch64) echo "OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.12.1_1.tar.gz 3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998" ;;
    mac/x64) echo "OpenJDK21U-jdk_x64_mac_hotspot_21.0.12.1_1.tar.gz 44db0f08196daf19a47f90d13388b0c943b67663cb537f998fe29e836fa842ce" ;;
    linux/aarch64) echo "OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz 23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223" ;;
    linux/x64) echo "OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94" ;;
    *) return 1 ;;
  esac
}

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

python_triple() {
  local os arch
  os=$(uname -s)
  arch=$(uname -m)
  case "$os:$arch" in
    Darwin:arm64|Darwin:aarch64) echo "aarch64-apple-darwin" ;;
    Darwin:x86_64) echo "x86_64-apple-darwin" ;;
    Linux:aarch64|Linux:arm64) echo "aarch64-unknown-linux-gnu" ;;
    Linux:x86_64) echo "x86_64-unknown-linux-gnu" ;;
    *)
      echo "Installing Python this way needs macOS or Linux. On Windows, run scripts/setup.ps1." >&2
      return 1
      ;;
  esac
}

jdk_platform() {
  local os arch platform jdk_arch
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Darwin) platform=mac ;;
    Linux) platform=linux ;;
    *)
      echo "Installing a JDK this way needs macOS or Linux. On Windows, run scripts/setup.ps1." >&2
      return 1
      ;;
  esac
  case "$arch" in
    arm64|aarch64) jdk_arch=aarch64 ;;
    x86_64) jdk_arch=x64 ;;
    *)
      echo "Unsupported architecture: $arch" >&2
      return 1
      ;;
  esac
  echo "${platform}/${jdk_arch}"
}

install_python() {
  local triple url tmp expected
  triple=$(python_triple)
  expected=$(python_sha256 "$triple")
  url="${PYTHON_RELEASE}/cpython-3.12.15+20261013-${triple}-install_only.tar.gz"
  tmp=$(mktemp -d)
  fetch "$tmp/python.tar.gz" "$url"
  verify_sha256 "$tmp/python.tar.gz" "$expected" "the Python download"
  tar -xzf "$tmp/python.tar.gz" -C "$tmp"
  rm -rf "$ROOT/python"
  mkdir -p "$ROOT"
  mv "$tmp/python" "$ROOT/python"
  rm -rf "$tmp"
  echo "Installed Python under $ROOT/python"
}

install_jdk() {
  local platform url tmp found home asset name expected
  platform=$(jdk_platform)
  asset=$(jdk_asset "$platform")
  name=${asset%% *}
  expected=${asset##* }
  url="${JDK_RELEASE}/${name}"
  tmp=$(mktemp -d)
  fetch "$tmp/jdk.tgz" "$url"
  verify_sha256 "$tmp/jdk.tgz" "$expected" "the JDK download"
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
  local url tmp src candidate key_file archive_py expected_fpr fpr script_dir
  if ! command -v gpg >/dev/null 2>&1; then
    echo "Refusing to install. gpg is required to verify the Dependency-Check signature." >&2
    exit 1
  fi
  expected_fpr=${ENGINE_KEY_FINGERPRINT:-$ENGINE_FPR_DEFAULT}
  url="https://github.com/dependency-check/DependencyCheck/releases/download/v${PIN}/dependency-check-${PIN}-release.zip"
  tmp=$(mktemp -d)
  cleanup_engine() { rm -rf "$tmp"; unset GNUPGHOME; }
  trap cleanup_engine RETURN
  fetch "$tmp/dc.zip" "$url"
  fetch "$tmp/dc.zip.asc" "${url}.asc"
  script_dir=""
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  fi
  if [[ -n "${ENGINE_PUBLIC_KEY:-}" ]]; then
    key_file=$ENGINE_PUBLIC_KEY
  elif [[ -n "$script_dir" && -f "$script_dir/keys/dependency-check-release.asc" ]]; then
    key_file=$script_dir/keys/dependency-check-release.asc
  else
    fetch "$tmp/dependency-check-release.asc" "$ENGINE_KEY_URL"
    key_file=$tmp/dependency-check-release.asc
  fi
  if [[ -n "$script_dir" && -f "$script_dir/../src/checkstead/archive.py" ]]; then
    archive_py=$script_dir/../src/checkstead/archive.py
  else
    fetch "$tmp/archive.py" "$ENGINE_ARCHIVE_URL"
    archive_py=$tmp/archive.py
  fi
  GNUPGHOME="$tmp/gnupg"
  export GNUPGHOME
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
  gpg --batch --import "$key_file" >/dev/null
  fpr=$(gpg --batch --with-colons --show-keys "$key_file" | awk -F: '/^fpr:/ {print $10; exit}')
  if [[ "$fpr" != "$expected_fpr" ]]; then
    echo "Refusing engine key. Expected fingerprint ${expected_fpr} but found ${fpr:-none}." >&2
    exit 1
  fi
  if ! gpg --batch --verify "$tmp/dc.zip.asc" "$tmp/dc.zip" >"$tmp/gpg.out" 2>&1; then
    echo "Refusing the downloaded engine. The release signature does not verify." >&2
    exit 1
  fi
  mkdir -p "$tmp/unpacked"
  "$python" "$archive_py" "$tmp/dc.zip" "$tmp/unpacked"
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
  if ! engine_reports_pin "$ROOT/dependency-check/bin/dependency-check.sh"; then
    echo "Refusing the downloaded engine. Expected ${PIN}." >&2
    rm -rf "$ROOT/dependency-check"
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
  local pin_tmp
  pin_tmp=$(mktemp)
  fetch "$pin_tmp" "$PIN_URL"
  tr -d '[:space:]' < "$pin_tmp"
  rm -f "$pin_tmp"
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
  for profile in "$HOME/.zprofile" "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
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
  for profile in "$HOME/.zprofile" "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
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

run_setup() {
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
  if ! grep -q 'dependency-check.bat' "$scan"; then
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
    if ! "$python" -c 'import ensurepip' >/dev/null 2>&1; then
      # A system Python without ensurepip (Debian without python3-venv).
      # Use the pinned, checksummed Python instead of running pip's bootstrap
      # script from the network, which has no pinned digest.
      if ! python_ok "$ROOT/python/bin/python3"; then
        install_python
      fi
      python="$ROOT/python/bin/python3"
    fi
    "$python" -m venv "$ROOT/venv"
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
}

# A sourced script defines the functions for tests. An executed script, including
# `curl | bash` where BASH_SOURCE is empty, runs the install.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
  run_setup
fi
