#!/bin/sh
# autoVPN watchdog: checks that the VPN tunnel is up; restarts if needed.
# Called by autovpn-watchdog.timer (every 60s). Secret-free, logs nothing sensitive.
set -u

PROJECT_DIR="${PROJECT_DIR:-/opt/autovpn}"
SERVICE="${SERVICE:-autovpn.service}"
IFACE="${VPN_INTERFACE:-tun0}"

# load .env overrides (allowed keys only, no secrets needed)
if [ -f "$PROJECT_DIR/.env" ]; then
    VPN_INTERFACE="$(sed -n 's/^VPN_INTERFACE=\(.*\)$/\1/p' "$PROJECT_DIR/.env" | tr -d '"' | tail -n1)"
    IFACE="${VPN_INTERFACE:-tun0}"
fi

if ! systemctl is-active --quiet "$SERVICE"; then
    # systemd Restart=always is responsible; only report, do not double-start
    logger -t autovpn-watchdog "service $SERVICE not active (systemd restart handles it)"
    exit 0
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    logger -t autovpn-watchdog "interface $IFACE missing -> restarting $SERVICE"
    systemctl restart "$SERVICE"
    exit 0
fi

exit 0
