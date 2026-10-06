#!/bin/sh
# Start the Checkstead server. Accounts live in the mounted data directory.
set -eu
data="${CHECKSTEAD_DATA:-/var/lib/checkstead}"
case "$data" in
  *[!A-Za-z0-9/_.-]*) echo "checkstead: CHECKSTEAD_DATA has unsupported characters." >&2; exit 1 ;;
esac
mkdir -p "$data"
if id checkstead >/dev/null 2>&1; then
  chown -R checkstead:checkstead "$data"
  exec su -s /bin/sh checkstead -c "exec checkstead ui --host 0.0.0.0 --port 8765 --scans /opt/checkstead/scans --data '$data'"
fi
exec checkstead ui --host 0.0.0.0 --port 8765 --scans /opt/checkstead/scans --data "$data"
