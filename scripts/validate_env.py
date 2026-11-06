#!/usr/bin/env python3
"""validate_env.py — the .env value validator used by init_setup.sh.

Extracted from init_setup.sh so it can be unit-tested (tests/test_init_setup.py)
without running a root-only setup script. Prints ONLY field names and format
problems — never values — and exits 1 if there is any hard problem.

Usage: python3 scripts/validate_env.py <path-to-.env>
"""
import base64
import binascii
import os
import re
import sys
from typing import Dict, List, Tuple

# Clock knobs: autovpn.py clamps them, so a value outside the clamp means the
# host clock is broken (fix NTP) rather than that the VPN needs a big shift.
OFFSET_MAX = 600
SKEW_ALLOWED = ("0", "1", "2")
SECRET_KEYS = ("VPN_PASSWORD", "TOTP_SECRET", "OTPAUTH_URI")


def parse_env(path: str) -> Dict[str, str]:
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.split(" #")[0].strip()
    return env


def validate(env: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """Return (fails, notes). Both are lists of human strings, values excluded."""
    fails, notes = [], []

    user = env.get("VPN_USER", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{2,64}", user):
        fails.append("VPN_USER missing/invalid (VPN username, 2-64 chars, without domain suffix)")
    if not env.get("VPN_PASSWORD", ""):
        fails.append("VPN_PASSWORD missing")

    secret = env.get("TOTP_SECRET", "")
    uri = env.get("OTPAUTH_URI", "")
    if uri:
        m = re.search(r"secret=([A-Z2-7]+=*)", uri, re.I)
        if not m:
            fails.append("OTPAUTH_URI without valid secret parameter")
        else:
            secret = m.group(1)
    if not fails and not secret:
        fails.append("TOTP_SECRET (base32) or OTPAUTH_URI missing")
    if secret:
        s = secret.upper().replace(" ", "")
        try:
            base64.b32decode(s, casefold=True)
            if not re.fullmatch(r"[A-Z2-7]+=*", s):
                fails.append("TOTP_SECRET is not valid base32")
        except binascii.Error:
            fails.append("TOTP_SECRET is not valid base32")

    for key, want in (("TOTP_ALGO", r"(?i)^(sha1|sha256|sha512)$"),
                      ("TOTP_PERIOD", r"^\d+$"),
                      ("TOTP_DIGITS", r"^\d+$")):
        v = env.get(key, "")
        if v and not re.match(want, v):
            fails.append(f"{key} invalid (expected {want})")
    # autovpn.totp_code raises on non-positive period/digits: catch it at
    # setup time, not in the responder at prompt time.
    for key in ("TOTP_PERIOD", "TOTP_DIGITS"):
        v = env.get(key, "")
        if v.isdigit() and int(v) <= 0:
            fails.append(f"{key} must be positive")

    off = env.get("TOTP_CLOCK_OFFSET", "")
    if off and off not in ("0", "0.0"):
        try:
            ov = int(float(off))
        except ValueError:
            fails.append("TOTP_CLOCK_OFFSET is not a number of seconds")
        else:
            if abs(ov) > OFFSET_MAX:
                fails.append(f"TOTP_CLOCK_OFFSET exceeds +-{OFFSET_MAX}s (clamped) — fix the host clock/NTP")
            elif abs(ov) > 30:
                notes.append("TOTP_CLOCK_OFFSET is large — prefer fixing NTP sync over shifting the clock")

    skew = env.get("TOTP_SKEW_WINDOWS", "")
    if skew and skew not in SKEW_ALLOWED:
        fails.append(f"TOTP_SKEW_WINDOWS must be one of {'/'.join(SKEW_ALLOWED)}")

    # Management transport: the interface has NO password, so a TCP target would
    # expose username+password+SCRV1 response to anyone who can reach the port.
    mgmt = env.get("MGMT_SOCKET", "")
    allow = env.get("MGMT_ALLOW_TCP", "").strip().lower()
    if re.search(r":\d+$", mgmt):
        if allow not in ("1", "true", "yes", "on"):
            fails.append("MGMT_SOCKET is a TCP target but MGMT_ALLOW_TCP is not set — "
                         "the management interface has no password; use the unix socket")
        elif not re.match(r"^(127\.0\.0\.1|localhost|::1):\d+$", mgmt):
            fails.append("MGMT_SOCKET TCP target must be loopback (127.0.0.1/localhost/::1)")

    cfg = env.get("OPENVPN_CONFIG", "")
    if cfg and not os.path.isfile(cfg):
        fails.append(f"OPENVPN_CONFIG points to a missing file: {cfg}")

    return fails, notes


def main(path: str) -> int:
    fails, notes = validate(parse_env(path))
    for n in notes:
        print(f"  - note: {n}")
    for f in fails:
        print(f"  - {f}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
