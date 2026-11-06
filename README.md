# autoVPN — OpenVPN TOTP Connect & Keep-Alive

Unattended OpenVPN client for OpenVPN servers with TOTP/MFA
(`static-challenge`): automatic token refresh, automatic reconnect, pure
Python stdlib. All state lives under `/opt/autovpn`.

## Requirements

- Linux with systemd; packages `openvpn` and `python3` (>= 3.8, stdlib only); root.
- Your provider's client config, placed at `/opt/autovpn/openvpn-client.ovpn`
  (contains the TLS static key: git-ignored, mode 600, root-only).
- The TOTP secret of your VPN account (Base32 or `otpauth://` URI) from your MFA setup.

## Quickstart

    cd /opt
    sudo git clone https://github.com/symrex/auto-vpn.git autovpn
    # place your provider's client config at /opt/autovpn/openvpn-client.ovpn
    sudo /opt/autovpn/init_setup.sh

`init_setup.sh` validates `.env`, installs the systemd units, connects live and
proves the reconnect path (process kill → systemd re-tunnels). Exit 0 =
deploy-ready. Check only, install nothing: `sudo /opt/autovpn/init_setup.sh --check`.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Auth chain A/B/C, SCRV1 finding (OpenVPN 2.6), systemd topology, token freshness, threat model/crypto, limitations |
| [docs/MANUAL.md](docs/MANUAL.md) | Deployment steps, LXC TUN delegation (incl. Proxmox), `.env` configuration, systemd install, selftest, troubleshooting |
| [.env.example](.env.example) | All configuration variables, commented (placeholders only) |
| [openvpn-client.ovpn.example](openvpn-client.ovpn.example) | Config template incl. the directives required for mode C |

## Quick reference

    sudo /opt/autovpn/autovpn.py --version    # installed version
    sudo /opt/autovpn/autovpn.py --dry-run    # offline self-check, no server contact
    python3 -m unittest discover -s tests     # RFC 6238 vectors, auth formats, responder mock,
                                              # init_setup support layer, shellcheck
    systemd-analyze verify systemd/*.service systemd/*.timer systemd/*.path

The default auth mode is `VPN_AUTH_MODE=C` (management-interface prompt
responder); rationale (SCRV1 finding) and fallbacks A/B:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Secrets live exclusively in `/opt/autovpn/.env` (mode 600, root) and are read
by path — the systemd units export no secret keys into the process environment.
`.gitignore` keeps `.env`, `openvpn-client.ovpn`, `*.key` and `auth*` out of the
repository.
