#!/usr/bin/env python3
"""autoVPN — TOTP provider + auth fallback chain for OpenVPN (MFA server, static-challenge).

Self-contained: Python 3 stdlib only (hmac, hashlib, base64, struct). No pip packages.

Works against any OpenVPN server that uses username/password + TOTP/MFA
(static-challenge). Designed for long-lived unattended clients with
auto-reconnect (many MFA servers disconnect after ~48 h).

Auth fallback chain (select via VPN_AUTH_MODE in .env; C is the default):
  A  auth-user-pass pass file (VPN_AUTH_FORMAT=concat):
       line1 = VPN username
       line2 = VPN password + current TOTP token (concatenated, no separator)
       (VPN_AUTH_FORMAT=3line -> line1 user / line2 password / line3 token,
        the three-line format some providers expect)
     Built by this script (ExecStartPre + route-up) into /run/autovpn/auth.txt
     (tmpfs, 600 root). Fresh token on every (re)connect => token age < 30 s.
  B  auth-user-pass-verify via-env:
       scripts/totp_auth.sh "$UDF" — reads username/password/answer from the
       OpenVPN environment and writes the user-disposition file (ACCEPT).
  C  management-interface prompt responder (catch-all for unknown prompts):
       autovpn.py --responder — connects to the OpenVPN management socket and
       answers OUTPUT_PROMPT/OUTPUT_PASSWORD/OUTPUT_USERNAME/OUTPUT_STATIC_CHALLENGE
       with a token generated AT PROMPT TIME (never older than 30 s).

Usage:
  autovpn.py                    mode A: write auth file (ExecStartPre / route-up)
  autovpn.py --responder        mode C: management-interface responder loop
  autovpn.py --token            print one fresh token (dev/debug; goes to
                                stdout = history/terminal buffer: last resort)
  autovpn.py --dry-run          validate everything WITHOUT contacting the server
NEVER prints secrets (only booleans / lengths).
"""
import argparse
import base64
import hashlib
import hmac
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

ENV_PATH_DEFAULT = "/opt/autovpn/.env"
__version__ = "1.1.1"
AUTH_DIR = "/run/autovpn"
AUTH_FILE = AUTH_DIR + "/auth.txt"
MGMT_SOCK_DEFAULT = "/run/autovpn/mgmt.sock"
BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")
# Guard rails for the clock knobs: a larger offset than +-600 s means the host
# clock is broken (fix NTP), not that the VPN needs a 10-minute shift.
OFFSET_MAX = 600
WINDOW_MAX = 5

# Environment keys this tool reads: VPN_*, TOTP_*, OPENVPN_*, MGMT_*, AUTH_*.
ENV_PREFIXES = ("VPN_", "TOTP_", "OPENVPN_", "MGMT_", "AUTH_")

# Secret key names that must never appear in a unit's process environment
# (init_setup.sh --selftest proves this via /proc/<pid>/environ).
SECRET_ENV_KEYS = frozenset({"VPN_PASSWORD", "TOTP_SECRET", "OTPAUTH_URI"})


# ---------------------------------------------------------------- env loading
def load_env(path: str = ENV_PATH_DEFAULT) -> Dict[str, str]:
    """Parse a simple KEY=VALUE .env file. Inline comments after value are stripped
    only for '#'-preceded whitespace; quoted values kept verbatim."""
    env = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
                if not m:
                    continue
                key, val = m.group(1), m.group(2).strip()
                if val[:1] in ('"', "'") and val[:1] == val[-1:]:
                    val = val[1:-1]
                elif val.startswith("#"):
                    # template line 'KEY=   # comment' -> value is EMPTY, not the comment
                    val = ""
                elif " #" in val:
                    # unquoted inline comment: KEY=***   # note -> strip '  # note'
                    val = val.split(" #", 1)[0].strip()
                env[key] = val
    # Shell/CI environment wins over the .env file.
    env.update({k: v for k, v in os.environ.items()
                if k.startswith(ENV_PREFIXES)})
    return env


# ---------------------------------------------------------------- TOTP core
def b32_decode(secret: str) -> bytes:
    s = unquote(str(secret)).strip().upper().replace(" ", "").replace("-", "")
    s = s.rstrip("=")
    if not s or not BASE32_RE.match(s):
        raise ValueError("TOTP secret is not valid Base32")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def totp_code(secret_b32: str, t: int, algo: str = "sha1", digits: int = 6,
              period: int = 30) -> str:
    """RFC 6238 TOTP (stdlib only)."""
    key = b32_decode(secret_b32)
    algo_l = str(algo).lower()
    if algo_l not in hashlib.algorithms_available:
        raise ValueError(f"unknown hash algo {algo}")
    if int(period) <= 0 or int(digits) <= 0:
        raise ValueError("digits and period must be positive")
    counter = int(t) // int(period)
    digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algo_l)).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** int(digits))
    return str(code).zfill(int(digits))


def parse_otpauth(uri: str) -> Dict[str, Any]:
    """Parse otpauth://totp/LABEL?secret=...&algorithm=...&digits=...&period=..."""
    u = urlparse(uri)
    if u.scheme != "otpauth" or u.netloc.lower() not in ("totp", "hotp"):
        raise ValueError("not an otpauth URI")
    q = {k.lower(): v[0] for k, v in parse_qs(u.query).items()}
    if "secret" not in q:
        raise ValueError("otpauth URI without secret")
    return {
        "secret": q["secret"],
        "algo": q.get("algorithm", "sha1").lower(),
        "digits": int(q.get("digits", 6)),
        "period": int(q.get("period", 30)),
        "label": unquote(u.path.lstrip("/").split("?")[0]),
    }


def get_totp_params(env: Dict[str, str]) -> Dict[str, Any]:
    """TOTP params from env; OTPAUTH_URI (if set) overrides individual vars.

    Clock knobs (both optional, defaults keep the strict default behaviour):
      TOTP_CLOCK_OFFSET  seconds added to the local clock before computing the
                         counter, for a host clock that drifts against the
                         server (clamped to +-600 s: bigger drift = fix NTP).
      TOTP_SKEW_WINDOWS  0/1/2 extra FUTURE windows offered as alternatives,
                         for a host clock running slightly behind the server.
    """
    p = {"secret": env.get("TOTP_SECRET", ""),
         "algo": env.get("TOTP_ALGO", "sha1").lower(),
         "digits": int(env.get("TOTP_DIGITS", 6)),
         "period": int(env.get("TOTP_PERIOD", 30)),
         "offset": _clamp_offset(env.get("TOTP_CLOCK_OFFSET", "0")),
         "skew": _clamp_skew(env.get("TOTP_SKEW_WINDOWS", "0"))}
    uri = env.get("OTPAUTH_URI", "").strip()
    if uri:
        q = parse_otpauth(uri)
        p.update({"secret": q["secret"], "algo": q["algo"],
                  "digits": q["digits"], "period": q["period"]})
    return p


def _clamp_offset(raw: object) -> int:
    try:
        val = int(float(str(raw).strip() or "0"))
    except ValueError:
        return 0
    return max(-OFFSET_MAX, min(OFFSET_MAX, val))


def _clamp_skew(raw: object) -> int:
    try:
        val = int(str(raw).strip() or "0")
    except ValueError:
        return 0
    return max(0, min(WINDOW_MAX, val))


def fresh_token(env: Dict[str, str]) -> str:
    """TOTP generated at CALL time — the single freshness entry point (token age < 30 s)."""
    return fresh_tokens(env)[0]


def fresh_tokens(env: Dict[str, str]) -> List[str]:
    """Current code first, then TOTP_SKEW_WINDOWS future-window codes.

    A static-challenge response can carry exactly ONE code, so callers that
    answer a single prompt use [0]; multi-line prompt answers may offer the
    rest. With the default TOTP_SKEW_WINDOWS=0 this is exactly one code."""
    p = get_totp_params(env)
    if not p["secret"]:
        raise ValueError("TOTP_SECRET (or OTPAUTH_URI) missing in .env")
    now = int(time.time()) + p["offset"]
    period = int(p["period"])
    return [totp_code(p["secret"], now + k * period, p["algo"], p["digits"], period)
            for k in range(0, p["skew"] + 1)]


def clock_health() -> Tuple[bool, str]:
    """(ok, detail) — NTP sync state of the host, for the dry-run report.
    TOTP is time-based: an unsynced clock is the single most common cause of
    rejected logins. Never runs anything that could block: timedatectl is
    probed with a short timeout and is optional."""
    timedatectl = shutil.which("timedatectl")
    if not timedatectl:
        return True, "timedatectl not present (clock state not verifiable)"
    try:
        # -p --no-pager: plain property dump. In containers show-timesync can
        # block on dbus, so the probe gets a 2 s budget, not 5: the dry-run
        # report is a UX path, not a health gate (observed TimeoutExpired=5s
        # in LXC on the 211 battle run).
        out = subprocess.run([timedatectl, "show-timesync",
                              "--property=NTPSynchronized,LocalPollInterval"],
                             capture_output=True, text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError) as e:
        return True, f"timedatectl probe failed: {type(e).__name__}"
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if props.get("NTPSynchronized") == "yes":
        poll = props.get("LocalPollInterval", "")
        try:
            if int(poll) > 128:
                return True, f"NTP synchronized, slow poll interval {poll}s"
        except ValueError:
            pass
        return True, "NTP synchronized"
    if props:
        return False, "NTP NOT synchronized — TOTP codes likely rejected (enable systemd-timesyncd/chrony)"
    return True, "timesyncd not active (no NTP sync reported)"


# ---------------------------------------------------------------- auth file (mode A)
def build_auth_lines(env: Dict[str, str], token: str) -> List[str]:
    """Mode A pass file. Default (VPN_AUTH_FORMAT=concat):
         line1 username, line2 password+token.
       Alternative (VPN_AUTH_FORMAT=3line): line1 user, line2 pw, line3 token."""
    user = env.get("VPN_USER", "").strip()
    pw = env.get("VPN_PASSWORD", "")
    if not user:
        raise ValueError("VPN_USER missing in .env")
    if not pw:
        raise ValueError("VPN_PASSWORD missing in .env")
    if env.get("VPN_AUTH_FORMAT", "concat").strip().lower() == "3line":
        # Provider variant: user / password / TOTP on three lines
        return [user, pw, token]
    if env.get("VPN_AUTH_FORMAT", "concat").strip().lower() == "userfile":
        # OpenVPN 2.6 static-challenge reality: the challenge RESPONSE cannot come
        # from the auth file. Auth file = username only; the responder (mode C)
        # answers the '>PASSWORD:Need ... SC:' query via the management interface.
        return [user]
    return [user, pw + token]


def write_auth_file(lines: List[str], path: Optional[str] = None) -> None:
    path = path or os.environ.get("AUTH_FILE", AUTH_FILE)
    d = os.path.dirname(path)
    # Only tighten the mode of a directory WE create. An existing directory
    # (e.g. systemd's RuntimeDirectory /run/autovpn, mode 700) is already
    # correct, and chmodding a pre-existing shared dir such as /tmp would fail
    # outright and break the dry-run probe.
    created = not os.path.isdir(d)
    os.makedirs(d, exist_ok=True)
    if created:
        os.chmod(d, 0o700)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def refresh_auth_file(env_path: str = ENV_PATH_DEFAULT) -> None:
    """Regenerate the pass file with a token minted NOW (route-up/route-pre-down hook)."""
    env = load_env(env_path)
    write_auth_file(build_auth_lines(env, fresh_token(env)))


# ---------------------------------------------------------------- mode B: via-env
def via_env_verify(udf_path: str, env_path: str = ENV_PATH_DEFAULT) -> int:
    """auth-user-pass-verify via-env handler. OpenVPN exports common_name,
    password, and (for static-challenge) answer into the environment. We accept
    and write a minimal user-disposition file. Token is minted at verify time by
    the prompt layer (mode C) / auth file (mode A); here the 'answer' env var
    already carries it."""
    env = load_env(env_path)
    user = os.environ.get("common_name", "").strip() or env.get("VPN_USER", "").strip()
    pw = os.environ.get("password", "") or env.get("VPN_PASSWORD", "")
    answer = os.environ.get("answer", "")
    if not user:
        print("no username in environment", file=sys.stderr)
        return 1
    # If OpenVPN gave us no answer (plain user+pass auth), append a fresh token.
    resp = answer if answer else pw + fresh_token(env)
    # UDF: accept the user (plugin-style disposition file)
    if udf_path:
        try:
            fd = os.open(udf_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("username %s\n" % user)
                f.write("password %s\n" % resp)
                f.write("common_name %s\n" % user)
                f.write("user_auth_verified yes\n")
        except OSError as e:
            print("cannot write UDF: %s" % e, file=sys.stderr)
            return 1
    return 0


# ---------------------------------------------------------------- mode C: management responder
def _sock_target(spec: str, allow_tcp: bool = False) -> Tuple[int, Any]:
    """'/path' -> AF_UNIX; 'host:port' -> AF_INET; bare int -> TCP localhost.

    TCP is the dangerous transport: the management interface has NO password
    (the design relies on the unix socket being root-exclusive in /run/autovpn,
    mode 700), so a TCP listener would hand username+password+SCRV1 response to
    anyone who can reach the port. Therefore TCP is refused unless the operator
    opts in explicitly (MGMT_ALLOW_TCP=1) AND the target is loopback.
    """
    spec = spec.strip()
    if re.fullmatch(r"\d+", spec):
        host, port = "127.0.0.1", int(spec)
    else:
        m = re.fullmatch(r"([^:/]+):(\d+)", spec)
        if not m:
            return (socket.AF_UNIX, spec)
        host, port = m.group(1), int(m.group(2))
    if not allow_tcp:
        raise ValueError(
            "TCP management target refused: the interface has no password, use the "
            "unix socket (MGMT_SOCKET=/run/autovpn/mgmt.sock). Opt in with "
            "MGMT_ALLOW_TCP=1 for a loopback target only.")
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("TCP management target must be loopback (MGMT_ALLOW_TCP=1)")
    return (socket.AF_INET, (host, port))


def _recv_exactly(sock: socket.socket, n: int,
                  buf: List[bytes]) -> Optional[bytes]:
    """Read exactly n bytes, consuming from the persistent buffer buf=[bytes]."""
    while len(buf[0]) < n:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf[0] += chunk
    data, buf[0] = buf[0][:n], buf[0][n:]
    return data


def _read_msg(sock: socket.socket, buf: List[bytes],
              bytecount: bool) -> Optional[str]:
    """Read one management message. In bytecount mode messages are framed as
    '[+]<n>:<payload>' + newline ('+' prefix = payload has embedded newlines).
    Unframed lines (e.g. the '>bytecount is on' echo in a fresh connection)
    are returned as-is for the dispatch loop to interpret."""
    if not bytecount:
        return _readline(sock, buf)
    # peek: framed message starts with digits (or '+'digits) up to ':';
    # anything before the first newline that is not numeric => plain line.
    while True:
        nl = buf[0].find(b"\n")
        colon = buf[0].find(b":")
        if colon != -1 and (nl == -1 or colon < nl):
            head = buf[0][:colon]
            embedded = head.startswith(b"+")
            digits = head[1:] if embedded else head
            if digits.isdigit():
                buf[0] = buf[0][colon + 1:]
                n = int(digits)
                payload = _recv_exactly(sock, n, buf)
                if payload is None:
                    return None
                _recv_exactly(sock, 1, buf)  # trailing newline delimiter
                return payload.decode("utf-8", "replace")
            line, buf[0] = buf[0][:nl], buf[0][nl + 1:]
            return line.decode("utf-8", "replace").rstrip("\r")
        if nl != -1:
            line, buf[0] = buf[0][:nl], buf[0][nl + 1:]
            return line.decode("utf-8", "replace").rstrip("\r")
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf[0] += chunk


def _readline(sock: socket.socket, buf: List[bytes]) -> Optional[str]:
    """Line reader over a socket with a persistent buffer (buf=[bytes])."""
    while b"\n" not in buf[0]:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf[0] += chunk
    line, buf[0] = buf[0].split(b"\n", 1)
    return line.decode("utf-8", "replace").rstrip("\r")


def responder(env_path: str = ENV_PATH_DEFAULT,
              mgmt: Optional[str] = None) -> int:
    """Connect to the OpenVPN management interface and answer every prompt
    (known AND unknown) with the right credential. Token minted per-prompt,
    so it is never older than 30 s. Nothing sensitive is ever logged."""
    env = load_env(env_path)
    spec = mgmt or env.get("MGMT_SOCKET", MGMT_SOCK_DEFAULT)
    allow_tcp = env.get("MGMT_ALLOW_TCP", "").strip() in ("1", "true", "yes", "on")
    try:
        fam, addr = _sock_target(spec, allow_tcp)
    except ValueError as e:
        print(f"refusing management target: {e}", file=sys.stderr)
        return 2
    bytecount = None  # greeting tells us: True/False

    def answer_for(prompt: str, bc: bool) -> str:
        # NOTE: bytecount prefixing (N:) is applied by send(); a '+' prefix would
        # mean an embedded-newline response, which we never send in concat mode.
        p = prompt.lower()
        if "user" in p and "pass" not in p:          # OUTPUT_USERNAME
            return user
        wants_pw = "pass" in p or "text" in p
        wants_otp = ("otp" in p) or ("token" in p) or ("static" in p and "challenge" in p)
        if wants_otp:
            toks = fresh_tokens(env)                 # minted AT prompt time
            if wants_pw:                             # combined "password + OTP" prompt
                # 3line: one value per line, so extra skew windows can follow the
                # primary code; concat: a single code is all the provider accepts.
                return "\n".join([pw] + toks) if fmt3 else (pw + toks[0])
            return toks[0]                           # OTP-only prompt -> token alone
        if wants_pw:                                 # OUTPUT_PASSWORD / OUTPUT_TEXT / askpass
            return pw
        # unknown OUTPUT_PROMPT: answer with the full static-challenge response
        return answer_for("static challenge password", bc)

    def scrv1() -> str:
        """Static-challenge wire format (OpenVPN 2.6, misc.c): SCRV1:b64(pw):b64(response).
        The TOTP is minted NOW, so it is fresh on every prompt. The SCRV1 response
        field carries exactly one code, so the primary (current-window) code is used;
        TOTP_SKEW_WINDOWS only applies to multi-line prompt answers."""
        tok = fresh_token(env)
        pwb = base64.b64encode(pw.encode()).decode()
        tokb = base64.b64encode(tok.encode()).decode()
        return f"SCRV1:{pwb}:{tokb}"

    def handle_special(msg: str, send: Callable[[str], None]) -> bool:
        """Handle the management special-state query
        '>PASSWORD:Need 'Auth' username/password SC:1,<challenge>'
        (OpenVPN 2.6 static-challenge via management-query-passwords)."""
        if not msg.startswith(">"):
            return False
        if msg.startswith(">PASSWORD:") or msg.startswith(">NEED-"):
            if not user:
                print("REFUSING credential query: VPN_USER empty in .env", flush=True)
                return True                          # never answer with empty creds
            m = re.search(r"Need '([^']+)'", msg)
            typ = m.group(1) if m else "Auth"
            wants_up = "username/password" in msg
            if wants_up and user:
                send(f"username {typ} {user}")
            if "SC:" in msg:                         # static challenge -> SCRV1 packing
                send(f"password {typ} {scrv1()}")
            else:
                send(f"password {typ} {pw}")
            print(f"answered password query (type={typ}, sc={'SC:' in msg})", flush=True)
            return True
        if msg.startswith(">RSA_SIGN") or msg.startswith(">PK_SIGN") or msg.startswith(">NEED-CERT"):
            return True                              # not applicable (no cert challenges here)
        return True                                  # other '>...' state notices: ignore

    while True:  # resilience loop: OpenVPN restarts recreate the socket
        # RE-READ .env on every (re)connection: the unit has no EnvironmentFile
        # and the responder is long-lived, so a secret/param change that is
        # picked up by the autovpn restart (env.path) must NOT be shadowed by
        # a stale copy cached at process start (battle-found on CT212).
        env = load_env(env_path)
        user = env.get("VPN_USER", "").strip()
        pw = env.get("VPN_PASSWORD", "")
        fmt3 = env.get("VPN_AUTH_FORMAT", "concat").strip().lower() == "3line"
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.connect(addr)
        except OSError:
            time.sleep(1)  # fast poll: must be connected BEFORE openvpn prompts
            continue
        buf = [b""]
        try:
            print("connected to management interface", flush=True)
            # UNFRAMED mode: OpenVPN 2.6 parses bytecount-framed commands
            # ('18:username ...') as unknown commands -> no bytecount!
            bytecount = False

            def send(text: str) -> None:
                data = text.encode()
                if b"\n" in data:  # embedded newline: mgmt needs the '+' bytecount form
                    s.sendall(("+%d:" % len(data)).encode() + data + b"\n")
                elif bytecount:
                    s.sendall(("%d:" % len(data)).encode() + data + b"\n")
                else:
                    s.sendall(data + b"\n")

            while True:
                line = _read_msg(s, buf, bool(bytecount))
                if line is None:
                    break
                toks = line.split()
                if not toks:
                    continue
                tag = toks[0]
                if tag == ">bytecount" and len(toks) >= 4 and toks[2] == "is":
                    bytecount = (toks[3] == "on")   # echo '>bytecount is on'
                elif tag in ("OUTPUT_PROMPT", "OUTPUT_USERNAME", "OUTPUT_PASSWORD",
                           "OUTPUT_STATIC_CHALLENGE", "OUTPUT_TEXT"):
                    try:
                        answer = answer_for(" ".join(toks[1:]), bool(bytecount))
                    except (ValueError, OSError) as e:
                        # A mint failure (broken/expired secret, bad params) must
                        # NOT kill the unit: Restart=always on a ValueError gives
                        # a crash loop. Report once, do not answer with garbage,
                        # drop the connection so OpenVPN retries on its own clock.
                        print(f"cannot answer prompt ({tag}): {e} — "
                              "check TOTP_SECRET/params in .env", flush=True)
                        break
                    print(f"answered prompt: {tag}", flush=True)  # tag only, never payload
                    send(answer)
                elif tag.startswith(">"):
                    try:
                        handle_special(line, send)  # '>PASSWORD:Need ...' etc.
                    except (ValueError, OSError) as e:
                        print(f"cannot answer query: {e} — "
                              "check TOTP_SECRET/params in .env", flush=True)
                        break
                elif tag == "bytecount" and len(toks) >= 2:
                    if toks[-1] == "on":
                        bytecount = True
                    elif toks[-1] == "off":
                        bytecount = False
                    elif toks[1].isdigit():         # greeting 'bytecount 1'
                        bytecount = toks[1] == "1"
                elif tag in ("Initialize", "TIMEOUT", "VERIFY_USER", "AUTH_PENDING"):
                    send("proceed")
                # SUCCESS:, log lines, state notifications: ignored, never logged
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(3)


# ---------------------------------------------------------------- checks
def check_env_file(path: str) -> List[str]:
    """Secret hygiene: mode must be 600 (or 400), owner root."""
    problems = []
    if not os.path.exists(path):
        return [f"{path} missing"]
    st = os.stat(path)
    if stat.S_IMODE(st.st_mode) & 0o077:
        problems.append(f"{path} mode is {oct(stat.S_IMODE(st.st_mode))}, must be 600")
    if st.st_uid != 0:
        problems.append(f"{path} owner uid={st.st_uid}, must be root")
    return problems


def openvpn_binary() -> str:
    for cand in ("/usr/sbin/openvpn", "/usr/bin/openvpn"):
        if os.path.exists(cand):
            return cand
    return shutil.which("openvpn") or ""


def dry_run(env_path: str) -> int:
    ok = True

    def report(name: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and passed
        print(f"[{'OK ' if passed else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

    def warn(name: str, detail: str) -> None:
        print(f"[WARN] {name} — {detail}")

    b = openvpn_binary()
    report("openvpn binary found", bool(b), b)

    problems = check_env_file(env_path)
    report(".env exists, chmod 600, root-owned", not problems, "; ".join(problems))

    env = load_env(env_path)
    user = env.get("VPN_USER", "").strip()
    report("VPN_USER set", bool(user) and not user.startswith("#"), user if not user.startswith("#") else "PLACEHOLDER (comment text)")
    pw = env.get("VPN_PASSWORD", "")
    report("VPN_PASSWORD set", bool(pw), f"len={len(pw)}")
    if pw.upper().startswith("BASE32SECRETPLACEHOLDER") or user.startswith("#") or user.upper().startswith("S000000"):
        warn("credentials look like placeholders", "set real VPN_USER/VPN_PASSWORD before enabling autovpn.service")
    p = get_totp_params(env)
    report("TOTP secret present + Base32", bool(p["secret"]) and bool(BASE32_RE.match(p["secret"].strip().upper())))
    report("TOTP params (sha1/30s/6)", p["algo"] == "sha1" and p["period"] == 30 and p["digits"] == 6,
           f"{p['algo']}/{p['period']}s/{p['digits']}")

    # clock: TOTP is time-based, an unsynced clock is the top cause of rejects
    clock_ok, clock_detail = clock_health()
    report("host clock state", clock_ok, clock_detail)
    if p["offset"]:
        warn("TOTP_CLOCK_OFFSET active", f"{p['offset']}s — fix the host clock/NTP instead of shifting")
    if p["skew"]:
        warn("TOTP_SKEW_WINDOWS active", f"{p['skew']} extra future windows — only for a clock behind the server")

    # management transport: TCP without a password would expose the credentials
    mgmt_spec = env.get("MGMT_SOCKET", MGMT_SOCK_DEFAULT)
    allow_tcp = env.get("MGMT_ALLOW_TCP", "").strip() in ("1", "true", "yes", "on")
    try:
        fam, _addr = _sock_target(mgmt_spec, allow_tcp)
        report("management target is a unix socket", fam == socket.AF_UNIX, mgmt_spec)
    except ValueError as e:
        report("management target safe (unix socket)", False, str(e))

    # Default C matches .env.example and docs/MANUAL.md ("C is the default").
    mode = env.get("VPN_AUTH_MODE", "C").strip().upper()
    report("auth mode A/B/C", mode in ("A", "B", "C"), f"VPN_AUTH_MODE={mode}")

    cfg = env.get("OPENVPN_CONFIG", "/opt/autovpn/openvpn-client.ovpn")
    report("openvpn config exists", os.path.exists(cfg), cfg)
    if os.path.exists(cfg):
        with open(cfg, "r", encoding="utf-8") as f:
            txt = f.read()
        report("config: static-challenge", "static-challenge" in txt)
        report("config: management interface (mode C responder)", "management" in txt)
        if mode == "C":
            # OpenVPN 2.6 reality: static-challenge response via management interface.
            # Requires 'auth-user-pass' (stdin, NOT a file) + management-query-passwords.
            report("config: auth-user-pass stdin (mode C)", bool(re.search(r"^auth-user-pass\s*$", txt, re.M)))
            report("config: management-query-passwords", "management-query-passwords" in txt)
            report("config: NO auth-file path in mode C", AUTH_FILE not in txt)
            report("responder script executable",
                   os.access(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "scripts", "mgmt_responder.sh"), os.X_OK))
        else:
            report("config: auth-user-pass <auth-file> (mode A)", AUTH_FILE in txt)
            report("config: route-up auth refresh (token freshness)", "route-up" in txt)

    here = os.path.dirname(os.path.abspath(__file__))
    for sc in ("totp_auth.sh", "env-reload.sh", "watchdog.sh"):
        path = os.path.join(here, "scripts", sc)
        report(f"script executable: {sc}", os.path.exists(path) and os.access(path, os.X_OK), path)

    # token generation + pass file build, to a throwaway probe path (no server contact)
    try:
        token = fresh_token(env)
        report("token generatable (6 digits)", re.fullmatch(r"\d{6}", token) is not None,
               f"len={len(token)}")
        lines = build_auth_lines(env, token)
        probe = os.path.join(AUTH_DIR, "auth.probe") if os.path.isdir(AUTH_DIR) else "/tmp/autovpn-auth.probe"
        write_auth_file(lines, probe)
        mode_ok = stat.S_IMODE(os.stat(probe).st_mode) == 0o600
        os.unlink(probe)
        fmt = env.get("VPN_AUTH_FORMAT", "concat").strip().lower()
        if fmt == "3line":
            shape_ok = len(lines) == 3 and re.fullmatch(r"\d{6}", lines[2]) is not None
        elif fmt == "userfile":
            shape_ok = len(lines) == 1 and bool(lines[0])
        else:
            shape_ok = len(lines) == 2 and lines[1].endswith(token)
        report("pass file buildable (mode A, format ok, 600)", shape_ok and mode_ok)
    except Exception as e:  # never print secrets, message only
        report("auth chain buildable", False, str(e))

    # token freshness of the live pass file (advisory — regenerated on start/route-up)
    live = os.environ.get("AUTH_FILE", AUTH_FILE)
    if os.path.exists(live):
        age = time.time() - os.stat(live).st_mtime
        if age > 30:
            warn("live auth file older than 30 s", f"age={int(age)}s — regenerated on unit start and route-up")

    print("DRY-RUN:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="TOTP auth provider for OpenVPN (MFA static-challenge servers)")
    ap.add_argument("--version", action="version", version=f"autovpn {__version__}")
    ap.add_argument("--dry-run", action="store_true", help="validate without contacting the server")
    ap.add_argument("--responder", action="store_true", help="mode C: management prompt responder")
    ap.add_argument("--token", action="store_true", help="print one fresh token (dev/debug)")
    ap.add_argument("--via-env", metavar="UDF", default=None,
                    help="mode B: auth-user-pass-verify via-env, write UDF")
    ap.add_argument("--mgmt", default=None,
                    help="management target: unix socket path (default); 'host:port' "
                         "needs MGMT_ALLOW_TCP=1 and must be loopback")
    ap.add_argument("--env", default=ENV_PATH_DEFAULT)
    args = ap.parse_args()

    if args.dry_run:
        return dry_run(args.env)
    if args.token:
        # A TOTP code is a secret while it is valid: stdout lands in shell
        # history and the terminal scrollback, so point at the safe path.
        print("warning: the code goes to stdout (shell history, scrollback). "
              "Prefer --dry-run for diagnostics.", file=sys.stderr)
        try:
            tok = fresh_token(load_env(args.env))
        except (ValueError, OSError) as e:
            print(f"token generation failed: {e}", file=sys.stderr)
            return 1
        print(tok)
        return 0
    if args.responder:
        return responder(args.env, args.mgmt)
    if args.via_env is not None:
        return via_env_verify(args.via_env, args.env)
    # mode A: rebuild the pass file with a token minted now
    env = load_env(args.env)
    try:
        write_auth_file(build_auth_lines(env, fresh_token(env)))
    except (ValueError, OSError) as e:
        # systemd ExecStartPre: a clean stderr line beats a traceback in the journal
        print(f"auth file build failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
