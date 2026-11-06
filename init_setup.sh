#!/usr/bin/env bash
# autoVPN — interactive setup + self-checkup.
# Validates .env values, installs systemd units and finishes with a real
# selftest (dry-run + live connect on tun0) including a report.
#
# Usage:  sudo ./init_setup.sh            # interactive (asks for missing .env values)
#         sudo ./init_setup.sh --check    # check only, install nothing
#         sudo ./init_setup.sh --selftest # units installed? run the self-checkup
#
# Assumptions: Debian/Ubuntu with systemd, openvpn + python3 installed.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVF="$PROJECT_DIR/.env"
ENVX="$PROJECT_DIR/.env.example"
UNITS=(autovpn.service autovpn-responder.service autovpn-watchdog.service autovpn-watchdog.timer autovpn-env.path autovpn-env.service)
UNIT_DIR=/etc/systemd/system
# shellcheck source=scripts/lib_report.sh
. "$PROJECT_DIR/scripts/lib_report.sh"

MODE=setup
[ "${1:-}" = "--check" ] && MODE=check
[ "${1:-}" = "--selftest" ] && MODE=selftest

# ---------------------------------------------------------------- checks
need_root() {
    [ "$(id -u)" = "0" ] || { bad "root required (sudo $0)"; exit 1; }
}

check_deps() {
    if command -v python3 >/dev/null 2>&1; then ok "python3 present"; else bad "python3 missing: apt install python3"; fi
    if command -v openvpn >/dev/null 2>&1 || [ -x /usr/sbin/openvpn ]; then
        ok "openvpn present"
    else
        bad "openvpn missing: apt install openvpn"
    fi
    if [ ! -x /usr/sbin/openvpn ]; then
        warn "openvpn is not at /usr/sbin/openvpn — the systemd unit uses the absolute path"
    fi
    if [ -f /opt/autovpn/autovpn.py ] || [ -f "$PROJECT_DIR/autovpn.py" ]; then
        ok "autovpn.py found"
    else
        bad "autovpn.py not found"
    fi
    if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)"; then
        ok "python3 >= 3.8"
    else
        bad "python3 >= 3.8 required"
    fi
    # TOTP is time-based: an unsynced host clock is the top cause of rejected logins
    if command -v timedatectl >/dev/null 2>&1; then
        if [ "$(timedatectl show-timesync --property=NTPSynchronized 2>/dev/null | cut -d= -f2)" = "yes" ]; then
            ok "host clock NTP synchronized"
        else
            warn "host clock NOT NTP-synchronized — TOTP codes are likely rejected (enable systemd-timesyncd/chrony)"
        fi
    else
        warn "timedatectl missing — clock sync state not verifiable"
    fi
    # TUN device: required by OpenVPN (often missing in LXC containers)
    if python3 -c "import os; os.close(os.open('/dev/net/tun', os.O_RDWR))" 2>/dev/null; then
        ok "/dev/net/tun openable"
    elif [ "$MODE" = "setup" ] && mkdir -p /dev/net 2>/dev/null && mknod /dev/net/tun c 10 200 2>/dev/null && chmod 666 /dev/net/tun; then
        if python3 -c "import os; os.close(os.open('/dev/net/tun', os.O_RDWR))" 2>/dev/null; then
            ok "/dev/net/tun created + openable"
        else
            bad "/dev/net/tun exists but opening is denied — the LXC container needs this on the HOST (stop + start the container afterwards):
    printf 'lxc.cgroup2.devices.allow: c 10:200 rwm\\nlxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file\\n' >> <container-conf>
    then stop/start the container (host tool of the virtualization stack)"
        fi
    else
        bad "/dev/net/tun missing — OpenVPN cannot create a tunnel device.
    VM/KVM: kernel module: modprobe tun. LXC (privileged and unprivileged): lxc.cgroup2.devices.allow + lxc.mount.entry (see docs/MANUAL.md §2)."
    fi
}

check_env() {
    [ -f "$ENVF" ] || {
        if [ "$MODE" = "check" ]; then bad ".env missing (copy from .env.example)"; return; fi
        warn ".env missing — creating it from .env.example"
        cp "$ENVX" "$ENVF"; chmod 600 "$ENVF"
    }
    # permissions
    local mode; mode=$(stat -c %a "$ENVF")
    if [ "$mode" = "600" ]; then
        ok ".env permissions 600"
    elif [ "$MODE" = "setup" ]; then
        chmod 600 "$ENVF"; ok ".env permissions set to 600"
    else
        warn ".env permissions are $mode (should be 600)"
    fi
    local owner; owner=$(stat -c %U "$ENVF")
    if [ "$owner" = "root" ]; then
        ok ".env owned by root"
    else
        warn ".env owned by $owner (the unit runs as root — prefer: chown root:root .env)"
    fi

    # interactively ask for missing required fields (never into logs/history)
    if [ "$MODE" = "setup" ] && [ -t 0 ]; then
        local key
        for key in VPN_USER VPN_PASSWORD TOTP_SECRET; do
            if ! grep -Eq "^${key}=\S" "$ENVF"; then
                printf 'Enter value for %s (not echoed): ' "$key"
                local val=""; read -rs val; echo
                val="${val%$'\r'}"
                # set the value in .env (replace existing line)
                python3 - "$ENVF" "$key" "$val" <<'PY'
import sys, re
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read()
if re.search(rf"^{key}=", src, re.M):
    src = re.sub(rf"^{key}=.*$", f"{key}={val}", src, flags=re.M)
else:
    src += f"{key}={val}\n"
open(path, "w").write(src)
PY
                ok "$key set"
            fi
        done
    fi

    # validate values (values are never printed, only field names/formats).
    # The validator lives in scripts/validate_env.py so it is unit-testable.
    if python3 "$PROJECT_DIR/scripts/validate_env.py" "$ENVF"; then
        ok ".env values plausible"
    else
        bad ".env values incomplete (see lines above)"
    fi

    # OpenVPN config: mode-C directives?
    # '|| true': no OPENVPN_CONFIG line = grep exits 1 = the failing case;
    # unguarded it would end the whole script under set -e before any report.
    local cfg; cfg=$(grep -E '^OPENVPN_CONFIG=' "$ENVF" | cut -d= -f2- | head -1 || true)
    if [ -n "$cfg" ] && [ -f "$cfg" ]; then
        ok "OpenVPN config found: $cfg"
        if grep -qE '^static-challenge' "$cfg"; then
            ok "static-challenge directive present"
        else
            warn "no static-challenge directive — TOTP prompt may differ"
        fi
        if grep -qE '^auth-user-pass[[:space:]]+\S' "$cfg"; then
            warn "auth-user-pass with a file path — with static-challenge the config MUST use 'auth-user-pass' without a path (mode C)"
        elif grep -qE '^auth-user-pass$' "$cfg"; then
            ok "auth-user-pass (stdin, mode-C compliant)"
        else
            warn "auth-user-pass missing in the config"
        fi
        if grep -qE '^management[[:space:]]' "$cfg"; then
            ok "management socket configured"
        else
            warn "management directive missing (mode C needs: management /run/autovpn/mgmt.sock unix + management-query-passwords)"
        fi
        if grep -qE '^management-query-passwords$' "$cfg"; then
            ok "management-query-passwords active"
        else
            warn "management-query-passwords missing"
        fi
        if grep -qE '^management[[:space:]]+[0-9.]+[[:space:]]+tcp' "$cfg"; then
            bad "management over TCP — the interface has no password, credentials would be exposed on the network; use 'management /run/autovpn/mgmt.sock unix'"
        fi
    else
        bad "OpenVPN config not readable ($cfg) — place openvpn-client.ovpn at OPENVPN_CONFIG (chmod 600)"
    fi
}

install_units() {
    need_root
    local unit content
    for unit in "${UNITS[@]}"; do
        [ -f "$PROJECT_DIR/systemd/$unit" ] || { bad "unit file missing: systemd/$unit"; continue; }
        content="$PROJECT_DIR/systemd/$unit"
        if [ "$PROJECT_DIR" != "/opt/autovpn" ]; then
            # The shipped units use the documented default /opt/autovpn so that
            # `systemd-analyze verify systemd/*` works from a clean checkout.
            # For a non-default install path the paths are rewritten in the
            # INSTALLED copy — one source of truth, no drop-in overrides.
            sed "s|/opt/autovpn|$PROJECT_DIR|g" "$content" > "$UNIT_DIR/$unit"
            chmod 644 "$UNIT_DIR/$unit"
            ok "installed (paths rewritten to $PROJECT_DIR): $unit"
        else
            install -m 644 "$content" "$UNIT_DIR/$unit"
            ok "installed: $unit"
        fi
    done
    systemctl daemon-reload
    if command -v systemd-analyze >/dev/null 2>&1; then
        if systemd-analyze verify "$UNIT_DIR"/autovpn*.service "$UNIT_DIR"/autovpn*.timer "$UNIT_DIR"/autovpn*.path >/dev/null 2>&1; then
            ok "systemd-analyze verify: units clean"
        else
            warn "systemd-analyze verify reports issues: systemd-analyze verify $UNIT_DIR/autovpn*.service"
        fi
    fi
    systemctl enable autovpn.service autovpn-responder.service autovpn-watchdog.timer autovpn-env.path >/dev/null
    ok "units enabled (boot autostart active)"
    # enable alone does not start timer/path units — without this the watchdog
    # only becomes active after the next reboot.
    systemctl start autovpn-watchdog.timer autovpn-env.path
    ok "timer + path units started"
}

# Proves the units keep secrets out of the process environment: systemd injects
# every EnvironmentFile key into /proc/<pid>/environ, where it is world-readable
# to root and inherited by all children. The units must carry no secret keys.
check_env_not_in_process() {
    # The secret key names come from autovpn.py (single source of truth).
    local keys unit pid hits
    keys=$(python3 -c "
import sys; sys.path.insert(0, sys.argv[1])
import autovpn
names = set(autovpn.SECRET_ENV_KEYS)
print('|'.join(sorted(names)))" "$PROJECT_DIR" 2>/dev/null)
    [ -n "$keys" ] || { warn "secret key list unavailable — environment check skipped"; return; }
    for unit in autovpn.service autovpn-responder.service; do
        pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)
        # explicit if: an "A && B" chain with a trailing "||" block is the
        # same SC2015 trap this repo bans — the block runs when A is true and
        # B fails, so a healthy unit would be reported as "not running".
        if [ -z "$pid" ] || [ "$pid" = "0" ]; then
            warn "$unit not running — environment check skipped"
            continue
        fi
        [ -r "/proc/$pid/environ" ] || { warn "/proc/$pid/environ not readable — environment check skipped"; continue; }
        # '|| true' is load-bearing: grep exits 1 on NO match, i.e. exactly
        # when the check PASSES (no secrets in the environment). Under
        # set -euo pipefail that would kill the whole script mid-selftest.
        hits=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null \
            | grep -oE "^($keys)=" | tr -d '=' | sort -u | tr '\n' ' ' || true)
        if [ -z "$hits" ]; then
            ok "$unit: no secrets in the process environment (PID $pid)"
        else
            bad "$unit: secret keys present in the process environment: $hits (must be read from .env by path only)"
        fi
    done
}

selftest() {
    local PYBIN="$PROJECT_DIR/autovpn.py"
    if python3 "$PYBIN" --dry-run --env "$ENVF"; then ok "dry-run PASS"; else bad "dry-run FAIL"; fi
    [ "$MODE" = "check" ] && return
    systemctl start autovpn-responder.service autovpn.service 2>/dev/null || true
    # Windows are generous on purpose: MFA servers rate-limit
    # repeated logins (every selftest is a login), so a tight 60 s window
    # reports a healthy tunnel as FAIL under test-heavy conditions.
    local up=0
    for _ in $(seq 1 20); do
        sleep 5
        ip -4 addr show tun0 >/dev/null 2>&1 && { up=1; break; }
    done
    if [ "$up" = "1" ]; then
        ok "live connect: tun0 has an IP ($(ip -4 -o addr show tun0 | awk '{print $4}'))"
        if [ "$(systemctl is-active autovpn)" = active ]; then ok "autovpn.service active"; else bad "autovpn.service not active"; fi
        if [ "$(systemctl is-active autovpn-responder)" = active ]; then ok "responder active"; else bad "responder not active"; fi
        if [ "$(systemctl is-active autovpn-watchdog.timer)" = active ]; then ok "watchdog.timer active"; else warn "watchdog.timer not active"; fi
        check_env_not_in_process
        # reconnect selftest: kill the process, systemd must reconnect
        local pid oldpid; oldpid=$(pgrep -f "openvpn --config" | head -1 || true)
        if [ -n "$oldpid" ]; then
            warn "reconnect selftest: killing the OpenVPN process — the tunnel drops for a few seconds"
            kill -9 "$oldpid"
            local re=0
            for _ in $(seq 1 18); do
                sleep 5
                ip -4 addr show tun0 >/dev/null 2>&1 && { re=1; break; }
            done
            pid=$(pgrep -f "openvpn --config" | head -1 || true)
            if [ "$re" = 1 ] && [ -n "$pid" ] && [ "$pid" != "$oldpid" ]; then
                ok "auto-reconnect after hard kill: new PID $pid, tun0 back"
            else
                bad "auto-reconnect failed"
            fi
        fi
        # 'Initialization Sequence Completed' must be in the journal (fresh after reconnect)
        if journalctl -u autovpn --since "-15 min" --no-pager 2>/dev/null | grep -q "Initialization Sequence Completed"; then
            ok "OpenVPN: Initialization Sequence Completed in the journal"
        else
            warn "no 'Initialization Sequence Completed' in the journal of the last 15 min"
        fi
    else
        bad "no tunnel after 100 s — check logs: journalctl -u autovpn -u autovpn-responder -n 40 (MFA servers rate-limit repeated logins: repeated selftests may need a few minutes)"
    fi
}

summary() {
    echo
    echo "=== autoVPN setup report: $PASS ok / $WARN warn / $FAIL fail ==="
    [ "$FAIL" = 0 ] && echo "Ready. Status anytime: systemctl status autovpn" \
        && echo "Logs: journalctl -u autovpn -u autovpn-responder -f"
    [ "$FAIL" = 0 ] || echo "Fix the FAIL items and run the script again."
    exit "$([ "$FAIL" = 0 ] && echo 0 || echo 1)"
}

echo "autoVPN init_setup — project: $PROJECT_DIR (mode: $MODE)"
check_deps
check_env
if [ "$MODE" = "check" ]; then summary; fi
[ "$MODE" = "selftest" ] && { selftest; summary; }
install_units
selftest
summary
