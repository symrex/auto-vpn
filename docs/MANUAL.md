# autoVPN — Manual

Step by step: deployment, configuration, operations, selftest, troubleshooting.
Background and rationale: [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Deployment steps

The target directory is `/opt/autovpn` (all units, scripts and the config
assume this path).

1. **Packages** (Debian/Ubuntu):

       sudo apt install -y openvpn python3

2. **Place the project** (the units assume the path `/opt/autovpn`):

       cd /opt
       sudo git clone https://github.com/symrex/auto-vpn.git autovpn

   A plain copy works too (`sudo cp -a . /opt/autovpn/` from a checkout); the
   executable bits on `init_setup.sh` and `scripts/*.sh` are tracked in git.

3. **Place the client config**: obtain your provider's config and save it as
   `/opt/autovpn/openvpn-client.ovpn`. For the default mode C these directives
   must be set (see `openvpn-client.ovpn.example`):

       auth-user-pass                       # WITHOUT a file path!
       static-challenge "Enter your OTP:" 1 # keep as provided by the provider
       management /run/autovpn/mgmt.sock unix
       management-query-passwords
       auth-nocache

   The file contains the TLS key/CA: `chmod 600`, root-only, never commit
   (`.gitignore` covers it).

4. **Secrets**: `sudo cp /opt/autovpn/.env.example /opt/autovpn/.env`,
   fill in (see §3), set permissions:

       sudo chown root:root /opt/autovpn/.env && sudo chmod 600 /opt/autovpn/.env

5. **Setup + selftest** (validates `.env`, installs units, connects live,
   tests reconnect):

       sudo /opt/autovpn/init_setup.sh

   Exit 0 = deploy-ready. Variants: `--check` (check only), `--selftest`
   (selftest on an already installed unit).

Manual alternative to step 5: §4 (units) + §6 (selftest).

## 2. LXC: TUN delegation

In LXC containers — privileged **and** unprivileged — `/dev/net/tun` is not
delegated by default; OpenVPN cannot create a tunnel then. `init_setup.sh`
detects this and prints the fix (in `setup` mode it first tries `mknod`
itself, which only succeeds in a privileged container). Once **on the LXC
host**, add to the container configuration:

    lxc.cgroup2.devices.allow: c 10:200 rwm
    lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file

then stop and start the container (a plain restart does not re-apply device
and mount entries). In VMs/KVM the kernel module is usually enough
(`modprobe tun`). Unprivileged containers work too once the device is
delegated like this — verified live: unprivileged LXC, OpenVPN 2.6.19,
full tunnel including the reconnect selftest (2026-11-06).

`nesting` is **not** required for TUN: verified live with `nesting=0` on an
unprivileged Debian 13 container — `/dev/net/tun` openable through the
delegation lines, tunnel up, provider IP assigned (2026-11-06). On Debian 13
(`systemd` 257) **keep `nesting=1`** anyway: without it systemd starts
degraded inside the container (`dev-mqueue.mount`, `run-lock.mount`,
`tmp.mount` fail; PVE itself warns "Systemd 257 detected. You may need to
enable nesting."). The tunnel survives the degraded state, a half-broken
init system is not a sound operating state. Without the delegation lines,
TUN stays impossible there.

On Proxmox the container configuration is `/etc/pve/lxc/<CT-ID>.conf`, and
`pct set` cannot set these keys: it accepts a fixed option list, and low-level
`lxc.*` keys are only passed through when written directly into the config
file (PVE docs, "File Format"). `/etc/pve` is a cluster filesystem and a
single append is atomic:

    cat >> /etc/pve/lxc/<CT-ID>.conf <<'EOF'
    lxc.cgroup2.devices.allow: c 10:200 rwm
    lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
    EOF
    pct stop <CT-ID> && pct start <CT-ID>

Verify inside the container:

    python3 -c "import os; os.close(os.open('/dev/net/tun', os.O_RDWR))" && echo TUN-ok
    openvpn --version | head -1   # expect 2.6.x

`init_setup.sh --check` runs the first check and verifies that `openvpn` is
present at the unit's absolute path — it does **not** check the OpenVPN
version, so confirm 2.6.x yourself. The responder needs no TUN at all, only
the unix socket under `/run/autovpn` (`RuntimeDirectory=`, already in the
units).

Sizing for a container: 2 vCPU, 512 MB–1 GB RAM, 8 GB disk, Debian 13 —
OpenVPN and Python run at the lower end. No Docker inside the container is
needed (the components are systemd units).

Container-specific unit building block (already included in `systemd/`):
`RuntimeDirectory=autovpn` — creates `/run/autovpn` before the mount
namespace; an `ExecStartPre: install -d` loses the race inside containers.

## 3. `.env` configuration

Fully commented in `.env.example`; short form:

| Variable | Meaning |
|---|---|
| `VPN_USER` / `VPN_PASSWORD` | Provider login (username without domain suffix; `VPN_PASSWORD` is NOT the one-time password). |
| `TOTP_SECRET` | Base32 secret **or** `OTPAUTH_URI` with a full `otpauth://` URI (the URI wins if both are set). |
| `TOTP_ALGO` / `TOTP_PERIOD` / `TOTP_DIGITS` | Default `sha1` / `30` / `6`. |
| `OPENVPN_CONFIG` | Default `/opt/autovpn/openvpn-client.ovpn`. |
| `AUTH_FILE` | tmpfs target of the generated pass-file, default `/run/autovpn/auth.txt`. |
| `VPN_AUTH_MODE` | `C` (default, responder), `A` (pass-file), `B` (via-env). See ARCHITECTURE §3. |
| `VPN_AUTH_FORMAT` | Mode A: `concat` (user / pw+token), `3line`, `userfile`. |
| `MGMT_SOCKET` | Default `/run/autovpn/mgmt.sock`. |
| `MGMT_ALLOW_TCP` | Default off. TCP management targets are refused (the interface has no password); set `1` for a loopback target only. |
| `TOTP_CLOCK_OFFSET` | Optional seconds added to the local clock for a drifting clock (clamped to ±600; fix NTP instead of shifting). |
| `TOTP_SKEW_WINDOWS` | Optional `0`/`1`/`2` extra future windows for a clock behind the server; applies to multi-line prompt answers only (`VPN_AUTH_FORMAT=3line`). |
| `VPN_INTERFACE` | Interface checked by the watchdog, default `tun0`. |

Secret rotation: edit and save `.env` — `autovpn-env.path` immediately
triggers auth rebuild + tunnel restart. Never loosen permissions: 600, root.

Secrets are read from `.env` **by path** and are deliberately never exported
into the unit environment: `systemd` injects every `EnvironmentFile=` key into
`/proc/<pid>/environ`, where it is readable by root and inherited by all child
processes. The units therefore carry only non-secret paths
(`PROJECT_DIR`, `AUTOVPN_ENV`, `OPENVPN_CONFIG`, `MGMT_SOCKET`).

## 4. systemd installation

`init_setup.sh` installs the units automatically. The shipped units use the
documented default `/opt/autovpn`; for an install at a **different path**
`init_setup.sh` rewrites the paths in the installed copy (one source of truth,
no drop-in overrides). Manual install at a non-default path:

    sudo mkdir -p /etc/systemd/system
    for f in systemd/*.service systemd/*.timer systemd/*.path; do
        sudo sed "s|/opt/autovpn|/your/path|g" "$f" \
            > "/etc/systemd/system/$(basename "$f")"
    done
    sudo systemctl daemon-reload
    sudo systemctl enable --now autovpn.service autovpn-responder.service \
            autovpn-watchdog.timer autovpn-env.path

Behaviour: `Restart=always`/`RestartSec=10` (fresh connect with a fresh
token), watchdog every 60 s, `.env` watcher. Offline syntax check:

    systemd-analyze verify systemd/*.service systemd/*.timer systemd/*.path

Hardening in the units: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, `UMask=0077`, `RestrictNamespaces`, `RestrictRealtime`,
`ProtectKernelModules`, `ProtectControlGroups`, `SystemCallArchitectures=native`,
plus a per-service address-family and capability profile — the OpenVPN service
keeps only the capabilities it needs for the tunnel (`CAP_NET_ADMIN`/`CAP_NET_RAW`
plus the ones OpenVPN uses to drop privileges), the responder is restricted to
`AF_UNIX` with an **empty** capability bounding set, watchdog and env-reload get
no capabilities and no network at all. `ReadWritePaths` is `/run/autovpn` only.

## 5. Operations

    systemctl status autovpn autovpn-responder
    journalctl -u autovpn -f
    ip addr show tun0                 # VPN IP present?
    sudo /opt/autovpn/autovpn.py --token   # live token (debug, root only)
    sudo /opt/autovpn/autovpn.py --version # installed version

Forwarding for clients behind this host (if desired): `ip_forward=1` via
sysctl, MASQUERADE outgoing over `tun0`, FORWARD chains. The provider may
require routing/ACL settings on their side.

## 6. Selftest

Levels — each runs up to the server, the last one live:

1. **Offline check**: `sudo /opt/autovpn/autovpn.py --dry-run` — verifies the
   openvpn binary, `.env` permissions and required fields, TOTP parameters,
   host clock/NTP state, management transport (unix socket vs TCP), config
   (challenge directives), auth-file build. Exit 0 = OK, no server contact.
2. **Unit syntax**: `systemd-analyze verify systemd/*` (see §4).
3. **Test suite**: `python3 -m unittest discover -s tests` — RFC 6238
   vectors, `otpauth://` parser, pass-file formats, clock offset/skew,
   management transport guard (TCP refused), via-env, responder against a mock
   server, plus the `init_setup.sh` support layer (`scripts/lib_report.sh`,
   `scripts/validate_env.py`, shellcheck clean).
4. **Live connect**: `systemctl is-active autovpn` + `ip addr show tun0`
   (VPN IP) + `ip route | grep tun0`.
5. **Secret-in-environment proof**: `init_setup.sh --selftest` reads
   `/proc/<MainPID>/environ` of both services and fails if any secret key
   (from `autovpn.SECRET_ENV_KEYS`) is exported there.
6. **Reconnect proof**: kill the OpenVPN process and let systemd reconnect.
   **This drops the tunnel for a few seconds** — do not run it while traffic
   depends on the tunnel:

       sudo systemctl show autovpn -p MainPID
       sudo kill -TERM <MainPID>
       sleep 15
       sudo systemctl show autovpn -p MainPID    # new PID
       ip addr show tun0                          # tunnel back up

   Expected in the journal: `Scheduled restart job` → new PID → `tun0` back.
7. **Full package**: `sudo /opt/autovpn/init_setup.sh --selftest` combines
   dry-run, connect, the environment check and the reconnect test.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Auth failed` / challenge rejected | Token too old, wrong TOTP parameters (algo/period/digits), system clock drifting (check `timedatectl`, dry-run reports the NTP state), login with domain suffix. Mode C needs the four config directives from §1.3. As a last resort for a clock that runs slightly behind the server: `TOTP_SKEW_WINDOWS=1` (multi-line answers only) — fixing NTP is the real fix. |
| `refusing management target: TCP management target refused` | `MGMT_SOCKET` is a `host:port` target. The management interface has no password, so TCP is refused by default. Use the unix socket; for a deliberate loopback setup set `MGMT_ALLOW_TCP=1` (loopback only). |
| Connect ends every ~48 h | Provider policy — normal; systemd reconnects with a fresh token automatically (§6.6). |
| `TUN/TAP device /dev/net/tun … Permission denied` | TUN not delegated → §2. In a VM: `modprobe tun`. |
| Service running, no `tun0` | Watchdog acts within ≤60 s; before that: scan `journalctl -u autovpn -b` for connect errors. |
| Responder starts, OpenVPN does not | Socket permissions: `/run/autovpn` must be 700 root; write the config directive `management /run/autovpn/mgmt.sock unix` exactly like that. |
| `.env` change has no effect | Unit not running: `systemctl status autovpn-env.path`; the path must be exactly `/opt/autovpn/.env`. |
| `systemd-analyze verify` reports an `openvpn` path | The unit uses `/usr/sbin/openvpn` (absolute); on non-Debian systems adjust the path in `autovpn.service`. |
| Dry-run: `TOTP_SECRET: not base32` | Secret copied with spaces/quotes; put an `otpauth://` URI into `OTPAUTH_URI` instead. |
| Dry-run reports missing config directives | Provider config unmodified? Add the mode-C block (see `openvpn-client.ovpn.example`). |
| Service on the same host loses its published ports after the VPN starts | `redirect-gateway` left in the provider config — §8. |

## 8. Sharing the host with a Docker service (jump host, proxy, …)

**Verified position — no need to re-research:** running this repo on a host
that also runs a Dockerised service is fine, and the service needs **no
changes at all** (no sidecar container, no `network_mode`, no proxy config).
The routing decision is made by the **host kernel**, not by the container:
container traffic leaves the bridge, is routed by the host (`ip_forward`) and
masqueraded, so whichever interface the routing table picks also supplies the
source address. Give the host prefix routes for the target networks and the
service reaches them over the tunnel, transparently.

Requirements, all in the provider config (not in this repo's files):

    route-nopull                      # ignore server-pushed routes/DNS
    route <net1> <mask1>              # one line per target prefix
    route <net2> <mask2>
    mssfix 1400                       # bridge MTU 1500 > tunnel MTU

Remove any `redirect-gateway` from the provider config. This is the one
requirement that is not optional: it takes the default route, so the
service's **own ingress** (published ports) would leave with the VPN source
address and the service becomes unreachable from outside. `route-nopull`
also means pushed DNS is ignored — address such services by IP, not name.
Do not add route scripts / `script-security 2`: the directives above are
declarative and keep the unit sandbox intact.

Check the Docker side, do not rebuild it:

    sysctl net.ipv4.ip_forward                                  # must be 1
    sudo iptables -t nat -L POSTROUTING -n | grep -i masq       # SNAT present
    sudo iptables -L FORWARD -n | head                          # bridge ACCEPT

Docker's default `FORWARD` rules already allow bridge → `tun0`; an explicit
allowance is only needed with `iptables=false` or an nftables default-drop,
and then belongs in the `DOCKER-USER` chain (survives Docker restarts).

One precondition: the service's own networks (its bridge subnet, its ingress
network) must lie **outside** every routed prefix. If they overlap, the
service's own traffic is pulled into the tunnel and connections loop. Check
before enabling:

    docker network inspect <net> --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'

Proof that traffic really uses the tunnel (`nc` alone can pass over the
physical interface):

    ip route get <target-ip>      # expect: dev tun0 src <VPN-IP>
    ip route get 8.8.8.8          # expect: dev <physical> — default stays out
    sudo tcpdump -ni tun0 host <target-ip>

Boot order needs no dependency: only the routed prefixes are bound to the
tunnel, and `Restart=always` here plus `restart: unless-stopped` on the
service converge on their own.

