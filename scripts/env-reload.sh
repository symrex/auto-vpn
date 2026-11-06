#!/bin/sh
# env-reload: .env changed -> rebuild auth + reconnect VPN
# so new secrets take effect immediately. Called by autovpn-env.path/.service.
set -eu
PROJECT_DIR="${PROJECT_DIR:-/opt/autovpn}"
SERVICE="${SERVICE:-autovpn.service}"

logger -t autovpn-env-reload ".env changed -> restarting $SERVICE"
# mode A/B: pre-build the auth file with a fresh token (rc!=0 on missing
# credentials is only logged, restart happens anyway -> ExecStartPre rebuilds).
MODE=$(sed -n "s/^VPN_AUTH_MODE=//p" "$PROJECT_DIR/.env" 2>/dev/null | tr -d "\"" | tail -n1)
MODE=$(echo "${MODE:-C}" | tr "[:lower:]" "[:upper:]")
if [ "$MODE" != "C" ]; then
    python3 "$PROJECT_DIR/autovpn.py" --token >/dev/null 2>&1 \
        || logger -t autovpn-env-reload "auth rebuild failed (check .env syntax/permissions)"
fi
systemctl restart "$SERVICE"
