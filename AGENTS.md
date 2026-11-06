`init_setup.sh` is the agentic entry point: check, install, selftest.
Usage and documentation map: see [README.md](README.md).

## Agent rules

1. **Changes only with a test run.** After every code change run
   `python3 -m unittest discover -s tests` and `sudo ./init_setup.sh --check`;
   both must be green before committing. The suite includes a shellcheck gate
   (skips itself when shellcheck is absent) — do not add shell warnings.
2. **Shell reporting rule.** Every check in `init_setup.sh` uses an explicit
   `if/then/else`. The shorthand `cond && ok x || bad y` is a trap: when `cond`
   is true and `ok` returns non-zero, `bad` runs too, so a passing check is
   reported as a failure. `scripts/lib_report.sh` holds the counters;
   `scripts/validate_env.py` holds the `.env` validator — both are unit-tested
   in `tests/test_init_setup.py`, because `init_setup.sh` itself is root-only
   and cannot be executed in a test.
3. **Secrets-never principle.** Secrets exist only in `/opt/autovpn/.env`
   (mode 600, root). Never write secrets into code, docs, commits, logs or
   agent answers. Secrets are read from `.env` **by path**: do not add
   `EnvironmentFile=` to a unit — systemd injects those keys into
   `/proc/<pid>/environ`, and `init_setup.sh --selftest` fails on that.
4. **Never print `.env` values.** Reading, catting, quoting or including
   `.env`, `openvpn-client.ovpn`, `*.key` and `auth*` in diff context is
   forbidden; check paths and permissions only. Diagnostics print field names
   and formats, never values.
5. **Escalate `[FAIL]` lines.** If `init_setup.sh` ends with `[FAIL]`:
   do not reinterpret, do not work around inside the repo — escalate the
   `[FAIL]` text plus environment verbatim (task comment / the requester).

## Sharing the host with a Docker service

No sidecar, no `network_mode`, no service-side change: the host kernel routes
container traffic, so host prefix routes for the target networks are enough.
Requirements are provider-config directives (`route-nopull`, one `route` per
prefix, `mssfix 1400`) and removing `redirect-gateway` — keeping it moves the
default route into the tunnel and kills the service's published ports.
Verified position and proof commands: [docs/MANUAL.md](docs/MANUAL.md) §8.

## Management-interface facts (do not relearn the hard way)

- `autovpn.py --responder` is a **long-running loop** by design: it answers the
  prompt, then keeps reading the socket. Any test or probe that runs it must
  terminate the process — never wait for it to exit.
- OpenVPN 2.6 parses **unframed** command lines (`username Auth x`), and rejects
  bytecount-framed ones (`18:username Auth x`). A **multi-line** answer (e.g.
  `VPN_AUTH_FORMAT=3line` with `TOTP_SKEW_WINDOWS`) must therefore use the
  `+<len>:<payload>` form, with `\n` inside the payload — otherwise OpenVPN
  reads the extra lines as separate commands.
- A SCRV1 response carries exactly **one** code. Clock tolerance is an
  `TOTP_CLOCK_OFFSET` (±600 s) plus optional future windows that only apply to
  multi-line prompt answers, never to the SCRV1 field.
- The management socket has **no authentication** beyond filesystem
  permissions, so it is a unix socket in `/run/autovpn` (0700, root). TCP is
  refused unless `MGMT_ALLOW_TCP=1` *and* the host is loopback.
