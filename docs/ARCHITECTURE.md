# autoVPN — Architecture

This file explains *why* the system is built the way it is.
Operational steps live in [MANUAL.md](MANUAL.md).

## 1. Problem

An MFA-protected OpenVPN server demands username + password + TOTP one-time
code (`static-challenge`) and typically drops long-lived clients after ~48 h.
An unattended client must therefore

1. mint a **fresh** TOTP token on every (re)connect, and
2. **automatically** reconnect after every disconnect.

## 2. SCRV1 finding (OpenVPN 2.6) — the core of the design

Verified from the OpenVPN source code (`misc.c`, `manage.c`) and by a live
test against a real server:

- With `static-challenge`, OpenVPN 2.6 reads from the `auth-user-pass` file
  only the username (+ password). It fetches the challenge response
  **exclusively over the management interface**.
- Query: `>PASSWORD:Need 'Auth' username/password SC:1,<text>`
- Expected answer: `username Auth <user>` and
  `password Auth SCRV1:b64(password):b64(challenge-response)` — the `SCRV1:`
  prefix is the protocol's static-challenge response format.
- The management interface parses **unframed** commands; bytecount-framed
  commands (`18:username …`) are rejected as unknown commands.

Therefore a pure pass-file (mode A) is **not sufficient** against a real
static-challenge server; the management responder (mode C) is the working
practice standard.

## 3. Auth fallback chain A/B/C (`VPN_AUTH_MODE`)

| Mode | Mechanism | Config directives | Use case |
|---|---|---|---|
| **C** (default) | `autovpn.py --responder` as `autovpn-responder.service`: persistent connection to the management socket, answers the SCRV1 query and every `OUTPUT_*` prompt (catches even unknown prompts) | `auth-user-pass` **without** file path, `management /run/autovpn/mgmt.sock unix`, `management-query-passwords` | practice standard with `static-challenge` (see §2) |
| **A** | pass-file `/run/autovpn/auth.txt`: `concat` = user / password+token; `3line` = user / password / token; `userfile` = user only. `ExecStartPre` + `route-up`/`route-pre-down` rebuild it on every connect | `auth-user-pass /run/autovpn/auth.txt` (+ `route-up`/`route-pre-down`) | providers without a real challenge; functionally tested |
| **B** | `auth-user-pass-verify … via-env`: `scripts/totp_auth.sh "$UDF"` → `autovpn.py --via-env` fills the user-disposition file (600) from `common_name`/`password`/`answer` | `auth-user-pass-verify /opt/autovpn/scripts/totp_auth.sh via-env` | server-side verification hooks |

The chain is defensive: mode C covers the documented case; A and B are
implemented fallbacks for providers that take the challenge differently.
`autovpn.py --token` and `--dry-run` serve diagnostics.

Management socket: unix socket under `/run/autovpn` (mode 700, root) —
root-exclusive, so **no** management password is needed (no shared secret to
rotate).

## 4. systemd topology

    autovpn-env.path ──(change)──> autovpn-env.service ──> scripts/env-reload.sh
    autovpn-watchdog.timer (60 s) ──> autovpn-watchdog.service ──> scripts/watchdog.sh
    autovpn-responder.service (Restart=always, Before=autovpn)
    autovpn.service  ExecStartPre=totp_auth.sh  ExecStart=/usr/sbin/openvpn --config …

- **autovpn.service** — OpenVPN in the foreground (`Type=simple`),
  `Restart=always` + `RestartSec=10`: every abort (provider timeout, network
  change, server restart) leads to a fresh connect after 10 s.
  `RuntimeDirectory=autovpn` creates `/run/autovpn` before namespacing
  (container-safe; an `ExecStartPre: install -d` loses the namespace race
  there). Hardening: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
  `ProtectHome`, `UMask=0077`, `ReadWritePaths=/run/autovpn /var/log`.
- **autovpn-responder.service** — mode C; starts before `autovpn.service`,
  waits for the socket in a resilience loop (OpenVPN creates it only when
  connecting) and is `Restart=always`.
- **autovpn-watchdog.timer/.service** — safety net: service running, but the
  tunnel interface (`VPN_INTERFACE`, default `tun0`) missing → restart.
- **autovpn-env.path/.service** — `.env` rotation (new secret, new password)
  immediately triggers auth rebuild + service restart.

All units take secrets from `/opt/autovpn/.env` **by path** (the root-only file,
mode 600) — there is deliberately **no** `EnvironmentFile=`: systemd injects
every `EnvironmentFile` key into the process environment, where it is visible in
`/proc/<pid>/environ` and inherited by every child process. The units export
only non-secret paths (`PROJECT_DIR`, `AUTOVPN_ENV`, `OPENVPN_CONFIG`,
`MGMT_SOCKET`); `init_setup.sh --selftest` proves this by scanning
`/proc/<MainPID>/environ` for the secret key names.

The units are shipped with the documented default path `/opt/autovpn` so that
`systemd-analyze verify systemd/*` works from a clean checkout; for an install
elsewhere `init_setup.sh` rewrites the paths in the installed copy (no drop-in
override files).

### 4.1 Hardening profile

| Unit | Capabilities | Address families | Notes |
|---|---|---|---|
| `autovpn.service` | `CapabilityBoundingSet` limited to what OpenVPN needs (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SETUID`/`CAP_SETGID` for the privilege drop, `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER` for the tun device), `DeviceAllow=/dev/net/tun rw` | `AF_INET AF_INET6 AF_UNIX AF_NETLINK` | root is unavoidable (tun), so the bounding set shrinks what root may do; no `CAP_MKNOD`/`CAP_IPC_LOCK`/`CAP_SYS_CHROOT` — the config uses no `dev-node`, `mlock` or `chroot` |
| `autovpn-responder.service` | **empty** bounding set | `AF_UNIX` only | it only talks to the management socket |
| `autovpn-watchdog.service` | empty | `AF_UNIX AF_NETLINK` | `systemctl` + `ip link` checks |
| `autovpn-env.service` | empty | `AF_UNIX` | `ReadOnlyPaths=/opt/autovpn`, restarts the service |

Common to all: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, `UMask=0077`, `RestrictNamespaces`, `RestrictRealtime`,
`RestrictSUIDSGID`, `ProtectKernelModules`, `ProtectControlGroups`,
`LockPersonality`, `SystemCallArchitectures=native`. `ReadWritePaths` is
`/run/autovpn` only — `/var/log` was in the list without any writer and is gone.

## 5. Token freshness (why the token never expires)

TOTP windows are typically 30 s. A token minted once at unit start and cached
would be worthless after the next window. autoVPN therefore mints the token
**fresh per use**:

- Mode A: `ExecStartPre` (before every start) and `route-up`/`route-pre-down`
  (on every connect) rebuild `auth.txt` → token age < 30 s.
- Mode C: the responder generates the token **at the moment of answering the
  prompt**, not when the responder process starts.
- After a reconnect (restart, watchdog, `.env` reload) the same applies: the
  next connect always sees a fresh token.
- Clock drift is a separate axis and is NOT solved by freshness: see §6
  (`TOTP_CLOCK_OFFSET`, `TOTP_SKEW_WINDOWS`, dry-run NTP report).

Reconnect proof (live test): `kill -TERM` on the OpenVPN process →
`Scheduled restart job` → new PID → tunnel back up.

## 6. Threat model and crypto

- **TOTP**: RFC 6238 / RFC 4226, `HMAC(secret, counter)` (standard
  sha1/30 s/6 digits, configurable via `.env` to sha256/sha512), implemented
  with `hmac`/`hashlib`/`base64`/`struct` only — no pip packages, no binaries
  in the path. The tests check the official RFC 6238 vectors.
- **Clock**: TOTP is time-based, so a drifting host clock is the top
  operational failure. `--dry-run` reports the NTP sync state
  (`timedatectl show-timesync`, probed with a 5 s timeout, optional). Two
  opt-in knobs exist for clocks that cannot be fixed: `TOTP_CLOCK_OFFSET`
  (clamped to ±600 s — beyond that the clock is broken, fix NTP) and
  `TOTP_SKEW_WINDOWS` (0/1/2 extra future windows, for a clock behind the
  server). Defaults are strict: exactly the current-window code. A SCRV1
  response carries exactly one code, so skew only applies to multi-line prompt
  answers (`VPN_AUTH_FORMAT=3line`).
- **Secret storage**: exclusively `/opt/autovpn/.env` (600, root), read **by
  path** — never exported into the unit environment (see §4).
  `.gitignore` keeps `.env`, `openvpn-client.ovpn` (contains the TLS static
  key), `*.key`, `auth*` out of the repository.
- **Ephemeral auth**: `auth.txt` lives on tmpfs (`/run/autovpn`, 700), mode
  600, disappears on reboot; `auth-nocache` in the client config prevents
  caching in OpenVPN-internal buffers. `write_auth_file` only tightens the
  mode of a directory it creates — it never chmods a pre-existing shared dir.
- **Log leakage**: `autovpn.py` never prints secret values (only
  booleans/lengths). The responder answers prompts but logs no answers. The
  `.env` validator prints field names and format problems only, never values.
- **Management transport**: the interface has **no** password — the design
  relies on the unix socket being root-exclusive (`/run/autovpn`, 700). A TCP
  target would expose username + password + SCRV1 response to anyone who can
  reach the port, so `--responder` refuses `host:port` targets unless the
  operator opts in (`MGMT_ALLOW_TCP=1`) **and** the target is loopback.
  `init_setup.sh` reports a `management ... tcp` directive as a hard `[FAIL]`.
- **Attack surface**: root is required (tun device). Whoever has root on the
  host has the secret — the design creates no new risk from that (`.env`
  mode 600 is the floor) and does not enlarge it: no management password, no
  world-readable token, no secret in the journal, no secret in the process
  environment, capability bounding sets per service (§4.1).

## 7. Limitations

- Provider-protocol dependent: `static-challenge` text, token length and
  concat format are provider-specific; the A/B/C chain catches known
  variants, mode C answers unknown prompts best effort — a provider with a
  wholly custom MFA workflow (e.g. browser redirect) cannot be automated
  from this repository.
- TOTP requires a correct system clock (run NTP; drift > window = rejected
  logins). `--dry-run` reports the sync state; `TOTP_CLOCK_OFFSET` /
  `TOTP_SKEW_WINDOWS` (§6) are stopgaps for clocks that cannot be fixed, not a
  substitute for NTP.
- 48-h timeouts are covered by restart; provider-side ACL/routing changes
  cannot be solved from this repo.
- TUN in LXC needs the host-side device delegation (MANUAL §2); without it
  there is no tunnel — use a VM/host. This holds for privileged **and**
  unprivileged containers.
- Single-user setup: no multi-user separation, no central secret management
  (a vault deliberately does not replace `.env`).
- The responder runs as root and holds the credentials in memory: a process
  that can read root memory has them. This is the same trust level as root
  itself (§6) — the mitigations are the empty capability bounding set, the
  `AF_UNIX`-only address-family restriction and the TCP refusal (§6).
