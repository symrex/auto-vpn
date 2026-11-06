#!/bin/sh
# totp_auth.sh — thin wrapper around autovpn.py.
# Builds the auth file (/run/autovpn/auth.txt) with a FRESH TOTP.
# Called by systemd ExecStartPre + route-up/route-pre-down before EVERY
# (re)connect so the token is never older than 30 seconds.
#
# Auth fallback chain (static-challenge with TOTP/MFA), selected via VPN_AUTH_MODE in .env:
#   A: auth-user-pass file (built by autovpn.py, tmpfs, 600 root):
#                line1 username, line2 password+token (VPN_AUTH_FORMAT=3line
#                -> user/pass/TOTP on 3 lines).
#   B (via-env):  OpenVPN calls: totp_auth.sh "$UDF"
#                 -> autovpn.py --via-env writes the user-disposition file.
#   C (catchall): management prompt responder for unknown prompts
#                 (autovpn.py --responder, own systemd instance).
set -eu
PROJECT_DIR="${PROJECT_DIR:-/opt/autovpn}"
PY="$PROJECT_DIR/autovpn.py"
ENVF="${AUTOVPN_ENV:-$PROJECT_DIR/.env}"

[ -f "$PY" ] || { echo "autovpn.py not found at $PY" >&2; exit 1; }

# mode B: OpenVPN passes the UDF as $1 and credentials (common_name,
# password, answer) via env -> autovpn.py writes the UDF and exit 0 = ACCEPT.
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    exec python3 "$PY" --via-env "$1" --env "$ENVF"
fi

# no UDF argument: rebuild the auth file with a token minted NOW (mode A path)
exec python3 "$PY" --env "$ENVF"
