#!/bin/sh
# autovpn-mgmt-responder — mode C: management interface prompt responder.
# Catches ALL prompts (even unknown ones) of the OpenVPN management interface
# and answers them with credentials; the TOTP is minted ANEW AT EVERY PROMPT
# (age < 30 s). Logs nothing sensitive.
# Runs as autovpn-responder.service (Restart=always).
set -eu
PROJECT_DIR="${PROJECT_DIR:-/opt/autovpn}"
PY="$PROJECT_DIR/autovpn.py"
ENVF="${AUTOVPN_ENV:-$PROJECT_DIR/.env}"
MGMT="${MGMT_SOCKET:-/run/autovpn/mgmt.sock}"

[ -f "$PY" ] || { echo "autovpn.py not found at $PY" >&2; exit 1; }

exec python3 "$PY" --responder --mgmt "$MGMT" --env "$ENVF"
