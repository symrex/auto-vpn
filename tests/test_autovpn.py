#!/usr/bin/env python3
"""Unit tests for the autovpn auth chain (stdlib unittest, no network).

Covers: RFC 6238 vectors, pass-file shapes (concat/3line), .env hygiene checks,
via-env UDF writing, and the mode-C prompt-responder answer logic via a mock
OpenVPN management server over a unix socket.
"""
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import autovpn  # noqa: E402

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
RFC_SECRET_SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"  # 32 bytes, RFC 6238 App. B


class TestTotp(unittest.TestCase):
    def test_rfc6238_vectors(self):
        # RFC 6238 Appendix B (SHA1, 8 digits)
        self.assertEqual(autovpn.totp_code(RFC_SECRET, 59, "sha1", 8, 30), "94287082")
        self.assertEqual(autovpn.totp_code(RFC_SECRET, 1111111109, "sha1", 8, 30), "07081804")
        self.assertEqual(autovpn.totp_code(RFC_SECRET, 1234567890, "sha1", 8, 30), "89005924")
        # 6-digit forms
        self.assertEqual(autovpn.totp_code(RFC_SECRET, 59, "sha1", 6, 30), "287082")

    def test_otpauth_uri(self):
        env = {"OTPAUTH_URI": "otpauth://totp/VPN:x?secret=%s&algorithm=SHA256&digits=8&period=60" % RFC_SECRET_SHA256}
        p = autovpn.get_totp_params(env)
        self.assertEqual((p["algo"], p["digits"], p["period"]), ("sha256", 8, 60))
        self.assertEqual(autovpn.totp_code(p["secret"], 59, p["algo"], p["digits"], 30),
                         "46119246")  # RFC 6238 App. B, SHA256 T=59, 8 digits


class TestPassFile(unittest.TestCase):
    def env(self):
        return {"VPN_USER": "s0000001", "VPN_PASSWORD": "pw123", "TOTP_SECRET": RFC_SECRET}

    def test_concat_shape(self):
        lines = autovpn.build_auth_lines(self.env(), "123456")
        self.assertEqual(lines, ["s0000001", "pw123123456"])

    def test_3line_shape(self):
        e = self.env()
        e["VPN_AUTH_FORMAT"] = "3line"
        self.assertEqual(autovpn.build_auth_lines(e, "123456"), ["s0000001", "pw123", "123456"])

    def test_missing_creds_raise(self):
        with self.assertRaises(ValueError):
            autovpn.build_auth_lines({"TOTP_SECRET": RFC_SECRET}, "123456")

    def test_write_mode_600(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "auth.txt")
            autovpn.write_auth_file(["u", "p123456"], p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            self.assertEqual(open(p).read().splitlines(), ["u", "p123456"])

    def test_existing_dir_mode_is_not_touched(self):
        """A pre-existing shared directory must not be chmodded (that is what
        broke the dry-run probe in /tmp); only directories we create are 700."""
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "sub")
            os.makedirs(sub)
            os.chmod(sub, 0o755)
            autovpn.write_auth_file(["u", "p1"], os.path.join(sub, "auth.txt"))
            self.assertEqual(stat.S_IMODE(os.stat(sub).st_mode), 0o755)

    def test_created_dir_is_700(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "created")
            autovpn.write_auth_file(["u", "p1"], os.path.join(sub, "auth.txt"))
            self.assertEqual(stat.S_IMODE(os.stat(sub).st_mode), 0o700)

    def test_fresh_token_current_window(self):
        env = {"TOTP_SECRET": RFC_SECRET}
        tok = autovpn.fresh_token(env)
        self.assertRegex(tok, r"^\d{6}$")
        self.assertEqual(tok, autovpn.totp_code(RFC_SECRET, _mid_window_now()))

    def test_default_is_single_strict_code(self):
        """No clock knobs set -> exactly the current-window code (strict default)."""
        toks = autovpn.fresh_tokens({"TOTP_SECRET": RFC_SECRET})
        self.assertEqual(len(toks), 1)
        self.assertEqual(toks[0], autovpn.fresh_token({"TOTP_SECRET": RFC_SECRET}))

    def test_clock_offset_shifts_the_counter(self):
        base = {"TOTP_SECRET": RFC_SECRET}
        shifted = autovpn.fresh_tokens({**base, "TOTP_CLOCK_OFFSET": "30"})
        self.assertEqual(len(shifted), 1)
        self.assertEqual(shifted[0], autovpn.totp_code(RFC_SECRET, _mid_window_now() + 30))

    def test_skew_offers_future_windows_first_is_current(self):
        toks = autovpn.fresh_tokens({"TOTP_SECRET": RFC_SECRET, "TOTP_SKEW_WINDOWS": "2"})
        now = _mid_window_now()
        self.assertEqual(len(toks), 3)
        self.assertEqual(toks[0], autovpn.totp_code(RFC_SECRET, now))
        self.assertEqual(toks[1], autovpn.totp_code(RFC_SECRET, now + 30))
        self.assertEqual(toks[2], autovpn.totp_code(RFC_SECRET, now + 60))

    def test_clock_knobs_are_clamped_and_tolerant_of_garbage(self):
        p = autovpn.get_totp_params({"TOTP_SECRET": RFC_SECRET,
                                     "TOTP_CLOCK_OFFSET": "99999",
                                     "TOTP_SKEW_WINDOWS": "99"})
        self.assertEqual(p["offset"], autovpn.OFFSET_MAX)
        self.assertEqual(p["skew"], autovpn.WINDOW_MAX)
        p = autovpn.get_totp_params({"TOTP_SECRET": RFC_SECRET,
                                     "TOTP_CLOCK_OFFSET": "not-a-number",
                                     "TOTP_SKEW_WINDOWS": "also-not"})
        self.assertEqual((p["offset"], p["skew"]), (0, 0))

    def test_negative_offset_allowed_within_clamp(self):
        p = autovpn.get_totp_params({"TOTP_SECRET": RFC_SECRET, "TOTP_CLOCK_OFFSET": "-45"})
        self.assertEqual(p["offset"], -45)


class TestMgmtTransport(unittest.TestCase):
    """The management interface has no password: TCP must be an explicit,
    loopback-only opt-in, the unix socket stays the default."""

    def test_unix_path_is_default(self):
        self.assertEqual(autovpn._sock_target("/run/autovpn/mgmt.sock"),
                         (socket.AF_UNIX, "/run/autovpn/mgmt.sock"))

    def test_tcp_refused_without_opt_in(self):
        for spec in ("127.0.0.1:11999", "10.0.0.5:11999", "11999"):
            with self.assertRaises(ValueError):
                autovpn._sock_target(spec, allow_tcp=False)

    def test_tcp_opt_in_allows_loopback_only(self):
        self.assertEqual(autovpn._sock_target("127.0.0.1:11999", allow_tcp=True),
                         (socket.AF_INET, ("127.0.0.1", 11999)))
        self.assertEqual(autovpn._sock_target("11999", allow_tcp=True),
                         (socket.AF_INET, ("127.0.0.1", 11999)))
        with self.assertRaises(ValueError):
            autovpn._sock_target("10.0.0.5:11999", allow_tcp=True)

    def test_responder_exits_cleanly_on_refused_target(self):
        """A refused target must be a clear message + non-zero exit, not a traceback."""
        with tempfile.TemporaryDirectory() as d:
            envf = os.path.join(d, ".env")
            with open(envf, "w") as f:
                f.write("VPN_USER=u\nVPN_PASSWORD=p\nTOTP_SECRET=%s\n" % RFC_SECRET)
            proc = subprocess.run(
                [sys.executable, os.path.join(ROOT, "autovpn.py"), "--responder",
                 "--mgmt", "10.0.0.5:11999", "--env", envf],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("refusing management target", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)


class TestCli(unittest.TestCase):
    """AGENTS.md rule 3/4 applied to the CLI: diagnostics must not leak the
    code via a traceback, and a broken .env exits with a message not a crash."""

    def _run(self, *args, env_path):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "autovpn.py"), *args,
             "--env", env_path],
            capture_output=True, text=True, timeout=30)

    def test_token_missing_secret_exits_1_no_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".env")
            with open(p, "w") as f:
                f.write("VPN_USER=u\nVPN_PASSWORD=p\n")
            r = self._run("--token", env_path=p)
            self.assertEqual(r.returncode, 1)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("token generation failed", r.stderr)
            self.assertEqual(r.stdout.strip(), "", "no code may reach stdout on failure")

    def test_token_warns_about_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".env")
            with open(p, "w") as f:
                f.write(f"TOTP_SECRET={RFC_SECRET}\n")
            r = self._run("--token", env_path=p)
            self.assertEqual(r.returncode, 0)
            self.assertRegex(r.stdout.strip(), r"^\d{6}$")
            self.assertIn("stdout", r.stderr, "must warn the code lands in shell history")

    def test_mode_a_missing_creds_exits_1_no_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".env")
            with open(p, "w") as f:
                f.write("TOTP_SECRET=%s\n" % RFC_SECRET)   # VPN_USER missing
            r = self._run(env_path=p)                        # mode A default path
            self.assertEqual(r.returncode, 1)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("auth file build failed", r.stderr)

    def test_dry_run_default_mode_matches_docs(self):
        """docs/MANUAL.md + .env.example document C as the default; the dry-run
        report must agree, or the docs and the code drift apart."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".env")
            with open(p, "w") as f:
                f.write(f"TOTP_SECRET={RFC_SECRET}\n")
            r = self._run("--dry-run", env_path=p)
            self.assertIn("VPN_AUTH_MODE=C", r.stdout)


class TestEnvHygiene(unittest.TestCase):
    def test_mode_600_ok_644_fail(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".env")
            open(p, "w").write("X=1\n")
            os.chmod(p, 0o644)
            self.assertTrue(autovpn.check_env_file(p))  # problems found
            os.chmod(p, 0o600)
            # mode is fine now; only owner check remains (root on the VM, uid here)
            probs = autovpn.check_env_file(p)
            self.assertTrue(all("mode" not in x for x in probs))


class TestViaEnv(unittest.TestCase):
    def test_udf_written(self):
        envf = os.path.join(tempfile.mkdtemp(), ".env")
        open(envf, "w").write("VPN_USER=s0000001\nVPN_PASSWORD=pw\nTOTP_SECRET=%s\n" % RFC_SECRET)
        os.environ["common_name"] = "s0000001"
        os.environ["password"] = "pw"
        os.environ["answer"] = "pw123456"
        try:
            with tempfile.TemporaryDirectory() as d:
                udf = os.path.join(d, "udf.txt")
                rc = autovpn.via_env_verify(udf, envf)
                self.assertEqual(rc, 0)
                txt = open(udf).read()
                self.assertIn("username s0000001", txt)
                self.assertEqual(stat.S_IMODE(os.stat(udf).st_mode), 0o600)
        finally:
            for k in ("common_name", "password", "answer"):
                os.environ.pop(k, None)


def _mid_window_now() -> int:
    """A timestamp in the middle of the current 30 s TOTP window: tests mint
    their expected code from this, the responder mints seconds later — both
    land in the same window unless the test straddles a window edge."""
    now = int(time.time())
    return now + (15 - now % 30)


def _mock_mgmt(sock_path, prompts, answers_seen):
    """Minimal OpenVPN 2.6 mgmt server, UNFRAMED line mode — the mode that
    actually works against OpenVPN 2.6 (framed '18:username ..' commands are
    parsed as unknown commands). Plain lines in, plain lines out.

    Answers are collected from a line buffer: the responder may send two commands
    in a single write (e.g. 'username Auth ..' + 'password Auth SCRV1:..'), and a
    plain read-until-newline would count them as one answer."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    conn = None
    buf = ""
    try:
        conn, _ = srv.accept()
        conn.settimeout(10)
        conn.sendall(b">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n")
        for item in prompts:
            tag_prompt, n_answers = item if isinstance(item, tuple) else (item, 1)
            conn.sendall(tag_prompt.encode() + b"\n")
            for _ in range(n_answers):
                while "\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk.decode()
                if "\n" not in buf:
                    break
                line, buf = buf.split("\n", 1)
                answers_seen.append(line.strip())
    except OSError:
        pass
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        srv.close()


class TestResponder(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.envf = os.path.join(self.d, ".env")
        open(self.envf, "w").write(
            "VPN_USER=s0000001\nVPN_PASSWORD=pwtop\nTOTP_SECRET=%s\n" % RFC_SECRET)
        self.sock = os.path.join(self.d, "mgmt.sock")

    def test_env_reread_between_reconnects(self):
        """Long-lived responder + no EnvironmentFile: .env must be RE-READ on
        every reconnect, not cached at process start. Battle scenario: secret
        swapped from broken to valid while the responder is in its connect
        loop -> the next prompt must be answered from the CURRENT .env."""
        open(self.envf, "w").write(
            "VPN_USER=s0000001\nVPN_PASSWORD=pwtop\nTOTP_SECRET=!!!broken!!!\n")
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "autovpn.py"), "--responder",
             "--mgmt", self.sock, "--env", self.envf],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.2)   # responder has cached env, is polling the absent socket
        open(self.envf, "w").write(
            "VPN_USER=s0000001\nVPN_PASSWORD=pwtop\nTOTP_SECRET=%s\n" % RFC_SECRET)
        seen = []
        t = threading.Thread(target=_mock_mgmt,
                             args=(self.sock, [("OUTPUT_STATIC_CHALLENGE Auth x", 1)], seen),
                             daemon=True)
        t.start()
        deadline = time.time() + 15
        while time.time() < deadline and not seen:
            time.sleep(0.5)
        proc.terminate()
        out, err = proc.communicate(timeout=10)
        t.join(10)
        self.assertEqual(len(seen), 1,
                         "responder answered with stale cached .env: %r" % out.decode())
        # 'OUTPUT_STATIC_CHALLENGE Auth x': the prompt TEXT carries no otp/
        # static hint, so the responder answers with the full static-challenge
        # response: concat mode = password+token (3line would be pw\n token).
        self.assertRegex(seen[0], r"^pwtop\d{6}$")
        self.assertNotIn(b"Traceback", err)


    def test_broken_secret_survives_prompt_no_crashloop(self):
        """A TOTP mint failure AT PROMPT TIME must not kill the process:
        Restart=always + ValueError = crash loop (battle-found via mock probe).
        Expected: clean exit, one diagnostic on stdout, NO answer sent."""
        open(self.envf, "w").write(
            "VPN_USER=s0000001\nVPN_PASSWORD=pwtop\nTOTP_SECRET=!!!broken!!!\n")
        seen = []
        t = threading.Thread(target=_mock_mgmt,
                             args=(self.sock, [("OUTPUT_STATIC_CHALLENGE Auth x", 0)], seen),
                             daemon=True)
        t.start()
        time.sleep(0.3)
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "autovpn.py"), "--responder",
             "--mgmt", self.sock, "--env", self.envf],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # the resilience loop keeps the process alive by design: read stdout
        # nonblocking, then terminate. rc must NOT be a crash (negative=signal).
        import selectors
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        collected = b""
        deadline = time.time() + 8
        while time.time() < deadline and b"cannot answer prompt" not in collected:
            if sel.select(0.5):
                collected += proc.stdout.read1(4096) if hasattr(proc.stdout, "read1") else b""
        proc.terminate()
        out, err = proc.communicate(timeout=10)
        t.join(10)
        self.assertNotIn(b"Traceback", err, "responder must fail clean, not crash")
        self.assertIn("cannot answer prompt", (collected + out).decode())
        self.assertNotIn("pwtop", out.decode(), "diagnostic must not leak the password")
        self.assertEqual(seen, [], "no answer may be sent on a mint failure")

    def runResponder(self, prompts):
        seen = []
        t = threading.Thread(target=_mock_mgmt, args=(self.sock, prompts, seen), daemon=True)
        t.start()
        time.sleep(0.3)
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "autovpn.py"), "--responder",
             "--mgmt", self.sock, "--env", self.envf],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t.join(15)
        time.sleep(0.5)
        proc.terminate()
        out, err = proc.communicate(timeout=10)
        self.assertEqual(err, b"", "responder must not write to stderr: %r" % err)
        # stdout may log event TAGS only — never username, password, or token
        for secret in ("s0000001", "pwtop"):
            self.assertNotIn(secret, out.decode(), "responder stdout leaked a secret")
        import re as _re
        self.assertNotRegex(out.decode(), r"\b\d{6}\b", "responder stdout logged a token")
        return seen

    def test_known_prompts(self):
        tok = autovpn.totp_code(RFC_SECRET, _mid_window_now())
        seen = self.runResponder([
            "OUTPUT_USERNAME username",
            "OUTPUT_PASSWORD password",
            "OUTPUT_STATIC_CHALLENGE Enter your OTP:",
            "OUTPUT_PROMPT Enter your password + OTP code:",
        ])
        self.assertEqual(len(seen), 4)
        # unframed: OUTPUT_* prompts are answered with the bare credential
        self.assertEqual(seen[0], "s0000001")
        self.assertEqual(seen[1], "pwtop")
        # OTP-only prompt -> token alone
        self.assertEqual(seen[2], tok)
        # combined password+OTP prompt -> pw+token
        self.assertEqual(seen[3], "pwtop" + tok)

    def test_unknown_prompt_answered(self):
        tok = autovpn.totp_code(RFC_SECRET, int(time.time()))
        # a prompt with NO recognized keyword -> fallback = full challenge response
        seen = self.runResponder(["OUTPUT_PROMPT Please enter your response:"])
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0], "pwtop" + tok)

    def test_otp_only_prompt_gets_token_only(self):
        # mint the expected token for the MIDDLE of the current window: the
        # responder mints ~2 s later, so a naive time.time() here races the
        # 30 s boundary (flaky: code minted across a window edge differs).
        tok = autovpn.totp_code(RFC_SECRET, _mid_window_now())
        seen = self.runResponder(["OUTPUT_STATIC_CHALLENGE Enter your OTP:"])
        payload = seen[0]
        self.assertEqual(payload, tok)

    def test_scrv1_password_query(self):
        """OpenVPN 2.6 static-challenge via management: '>PASSWORD:Need 'Auth'
        username/password SC:1,<text>' must be answered with
        username Auth <u> + password Auth SCRV1:b64(pw):b64(token)."""
        import base64
        tok = autovpn.totp_code(RFC_SECRET, _mid_window_now())   # window-safe
        b64pw = base64.b64encode(b"pwtop").decode()
        seen = self.runResponder([
            (">PASSWORD:Need 'Auth' username/password SC:1,Enter your OTP:", 2)])
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0], "username Auth s0000001")
        self.assertEqual(seen[1],
                         "password Auth SCRV1:%s:%s" % (b64pw, base64.b64encode(tok.encode()).decode()))

    def test_3line_with_skew_uses_bytecount_framing(self):
        """VPN_AUTH_FORMAT=3line + TOTP_SKEW_WINDOWS: the answer carries several
        lines, so it MUST be sent in the '+' bytecount form ('+N:<payload>\n'),
        never as bare lines that OpenVPN would read as separate commands."""
        with open(self.envf, "a") as f:
            f.write("VPN_AUTH_FORMAT=3line\nTOTP_SKEW_WINDOWS=2\n")
        base_t = _mid_window_now()
        cur = [autovpn.totp_code(RFC_SECRET, base_t + k * 30) for k in range(3)]
        nxt = [autovpn.totp_code(RFC_SECRET, base_t + 30 + k * 30) for k in range(3)]
        # responder mints ~2 s later: if the 30 s window edge falls in that
        # gap, every code shifts one window — accept either trio (the '+'
        # framing + bytecount + shape are the point; codes are window-safe).
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.sock)
        srv.listen(1)
        raw = []

        def serve():
            conn, _ = srv.accept()
            conn.settimeout(10)
            conn.sendall(b">INFO:OpenVPN Management Interface Version 5\n")
            conn.sendall(b"OUTPUT_PROMPT Enter your password + OTP code:\n")
            buf = b""
            while b"\n" not in buf:
                buf += conn.recv(4096)
            raw.append(buf)
            srv.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "autovpn.py"),
                                 "--responder", "--mgmt", self.sock, "--env", self.envf],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t.join(15)
        proc.terminate()
        proc.communicate(timeout=10)
        self.assertEqual(len(raw), 1)
        line = raw[0].rstrip(b"\n")
        self.assertTrue(line.startswith(b"+"), f"multi-line answer must use '+' framing: {line!r}")
        head, _, payload = line.partition(b":")
        declared = int(head[1:])
        self.assertEqual(len(payload), declared, "bytecount prefix must match the payload length")
        parts = payload.decode().split("\n")
        self.assertEqual(parts[0], "pwtop")
        self.assertIn(parts[1:], (cur, nxt),
                      "3line answer = password, then current + skew-window codes "
                      "(same window, or all shifted one window at an edge)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
