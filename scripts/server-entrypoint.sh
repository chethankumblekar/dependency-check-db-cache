#!/bin/sh
# Start the Checkstead server. Accounts and scans live in the mounted directories.
# Localhost sign-in is on unless CHECKSTEAD_LOCAL=0. OAuth variables stay optional.
set -eu
data="${CHECKSTEAD_DATA:-/var/lib/checkstead}"
scans="${CHECKSTEAD_SCANS:-/var/lib/checkstead/scans}"
case "$data" in
  *[!A-Za-z0-9/_.-]*) echo "checkstead: CHECKSTEAD_DATA has unsupported characters." >&2; exit 1 ;;
esac
case "$scans" in
  *[!A-Za-z0-9/_.-]*) echo "checkstead: CHECKSTEAD_SCANS has unsupported characters." >&2; exit 1 ;;
esac
if [ "${CHECKSTEAD_LOCAL:-1}" = "1" ]; then
  export CHECKSTEAD_LOCAL=1
else
  export CHECKSTEAD_LOCAL
fi
mkdir -p "$data" "$scans"
if id checkstead >/dev/null 2>&1; then
  chown -R checkstead:checkstead "$data" "$scans"
  # su without -p drops CHECKSTEAD_LOCAL and the optional OAuth variables.
  exec su -p -s /bin/sh checkstead -c "exec checkstead ui --host 0.0.0.0 --port 8765 --scans '$scans' --data '$data'"
fi
exec checkstead ui --host 0.0.0.0 --port 8765 --scans "$scans" --data "$data"
