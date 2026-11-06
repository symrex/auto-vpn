#!/usr/bin/env python3
"""Tests for the init_setup.sh support layer (stdlib unittest, no root, no systemd).

init_setup.sh itself is a root-only installer and cannot be executed in a test.
Its two testable parts were extracted for exactly that reason:
  scripts/lib_report.sh    — the [OK]/[WARN]/[FAIL] counters and the report helper
  scripts/validate_env.py  — the .env value validator
Both are covered here, including the `cond && ok || bad` trap that the shell
checks must not reintroduce.
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import validate_env  # noqa: E402

BASH = "/bin/bash"
LIB = os.path.join(ROOT, "scripts", "lib_report.sh")
VALIDATE = os.path.join(ROOT, "scripts", "validate_env.py")

GOOD_ENV = """
VPN_USER=s0000001
VPN_PASSWORD=pw123
TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
TOTP_ALGO=sha1
TOTP_PERIOD=30
TOTP_DIGITS=6
MGMT_SOCKET=/run/autovpn/mgmt.sock
"""


def run_bash(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True)


def write_env(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".env")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class TestReportHelpers(unittest.TestCase):
    def test_counters(self):
        p = run_bash(f'source {LIB}; ok a; bad b; warn c; echo "$PASS $FAIL $WARN"')
        self.assertEqual(p.stdout.strip().splitlines()[-1], "1 1 1")

    def test_labels(self):
        p = run_bash(f'source {LIB}; ok "x"; bad "y"; warn "z"')
        out = p.stdout
        self.assertIn("[ OK ] x", out)
        self.assertIn("[FAIL] y", out)
        self.assertIn("[WARN] z", out)

    def test_report_helper_success_and_failure(self):
        p = run_bash(f'source {LIB}; report 0 "works" "detail"; report 1 "broken"')
        out = p.stdout
        self.assertIn("[ OK ] works — detail", out)
        self.assertIn("[FAIL] broken", out)
        self.assertIn("1 1 0", run_bash(f'source {LIB}; report 0 a; report 1 b; echo "$PASS $FAIL $WARN"').stdout)

    def test_passing_check_never_reports_failure(self):
        """The trap: `cond && ok x || bad y` runs bad when ok returns non-zero.
        The if/else form must never emit both lines for one check."""
        good = run_bash(f'source {LIB}; if true; then ok "check"; else bad "check"; fi; echo "$PASS $FAIL"')
        self.assertIn("[ OK ] check", good.stdout)
        self.assertNotIn("[FAIL]", good.stdout)
        self.assertEqual(good.stdout.strip().splitlines()[-1], "1 0")

    def test_ok_is_exit_zero_safe(self):
        """ok/bad must be usable as the last command of a function under set -e."""
        p = run_bash(f'set -e; source {LIB}; f() {{ ok "x"; }}; f; echo survived')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("survived", p.stdout)

    def test_and_ok_or_bad_shorthand_reports_both_when_ok_fails(self):
        """The trap, deterministically: `cond && ok x || bad y` runs bad whenever
        ok returns non-zero (closed pipe/EPIPE, a failing command inside ok), so
        one passing check is reported as [ OK ] AND [FAIL] and the exit code flips.
        The if/else form used by init_setup.sh must report the check once."""
        trap = run_bash(f'''
            source {LIB}
            ok() {{ printf '[ OK ] %s\\n' "$*"; PASS=$((PASS+1)); return 1; }}
            true && ok "check" || bad "check"
            echo "$PASS $FAIL"''')
        self.assertIn("[ OK ] check", trap.stdout)
        self.assertIn("[FAIL] check", trap.stdout)
        self.assertEqual(trap.stdout.strip().splitlines()[-1], "1 1")

        fixed = run_bash(f'''
            source {LIB}
            ok() {{ printf '[ OK ] %s\\n' "$*"; PASS=$((PASS+1)); return 1; }}
            if true; then ok "check"; else bad "check"; fi
            echo "$PASS $FAIL"''')
        self.assertIn("[ OK ] check", fixed.stdout)
        self.assertNotIn("[FAIL]", fixed.stdout)
        self.assertEqual(fixed.stdout.strip().splitlines()[-1], "1 0")


class TestValidateEnv(unittest.TestCase):
    def setUp(self):
        self.paths = []

    def tearDown(self):
        for p in self.paths:
            os.unlink(p)

    def env(self, text: str) -> dict:
        path = write_env(text)
        self.paths.append(path)
        return validate_env.parse_env(path)

    def test_good_env_passes(self):
        fails, _ = validate_env.validate(self.env(GOOD_ENV))
        self.assertEqual(fails, [])

    def test_missing_user_and_password(self):
        fails, _ = validate_env.validate(self.env("TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n"))
        self.assertTrue(any("VPN_USER" in f for f in fails))
        self.assertTrue(any("VPN_PASSWORD" in f for f in fails))

    def test_bad_base32_secret(self):
        fails, _ = validate_env.validate(self.env(GOOD_ENV.replace("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "1111INVALID")))
        self.assertTrue(any("base32" in f for f in fails))

    def test_otpauth_uri_secret_accepted(self):
        env = self.env("VPN_USER=u1\nVPN_PASSWORD=p\n"
                       "OTPAUTH_URI=otpauth://totp/VPN?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
        fails, _ = validate_env.validate(env)
        self.assertEqual(fails, [])

    def test_clock_offset_out_of_clamp_is_hard_fail(self):
        fails, _ = validate_env.validate(self.env(GOOD_ENV + "TOTP_CLOCK_OFFSET=7200\n"))
        self.assertTrue(any("TOTP_CLOCK_OFFSET" in f for f in fails))

    def test_clock_offset_small_is_note_only(self):
        fails, notes = validate_env.validate(self.env(GOOD_ENV + "TOTP_CLOCK_OFFSET=45\n"))
        self.assertEqual(fails, [])
        self.assertTrue(any("TOTP_CLOCK_OFFSET" in n for n in notes))

    def test_skew_windows_rejects_out_of_range(self):
        fails, _ = validate_env.validate(self.env(GOOD_ENV + "TOTP_SKEW_WINDOWS=9\n"))
        self.assertTrue(any("TOTP_SKEW_WINDOWS" in f for f in fails))
        for ok_val in ("0", "1", "2"):
            fails, _ = validate_env.validate(self.env(GOOD_ENV + f"TOTP_SKEW_WINDOWS={ok_val}\n"))
            self.assertEqual(fails, [])

    def test_nonpositive_period_digits_fail(self):
        """autovpn.totp_code raises on period/digits <= 0 at MINT time; the
        validator must catch it at setup time."""
        for key in ("TOTP_PERIOD", "TOTP_DIGITS"):
            fails, _ = validate_env.validate(self.env(GOOD_ENV + f"{key}=0\n"))
            self.assertTrue(any(key in f for f in fails), f"{key}=0 not rejected")
        fails, _ = validate_env.validate(self.env(GOOD_ENV + "TOTP_PERIOD=30\n"))
        self.assertEqual(fails, [])

    def test_tcp_mgmt_requires_opt_in(self):
        fails, _ = validate_env.validate(self.env(GOOD_ENV + "MGMT_SOCKET=127.0.0.1:11999\n"))
        self.assertTrue(any("MGMT_ALLOW_TCP" in f for f in fails))

    def test_tcp_mgmt_opt_in_must_be_loopback(self):
        fails, _ = validate_env.validate(self.env(
            GOOD_ENV + "MGMT_SOCKET=10.0.0.5:11999\nMGMT_ALLOW_TCP=1\n"))
        self.assertTrue(any("loopback" in f for f in fails))
        fails, _ = validate_env.validate(self.env(
            GOOD_ENV + "MGMT_SOCKET=127.0.0.1:11999\nMGMT_ALLOW_TCP=1\n"))
        self.assertEqual(fails, [])

    def test_unix_socket_needs_no_opt_in(self):
        fails, _ = validate_env.validate(self.env(GOOD_ENV))
        self.assertEqual(fails, [])

    def test_missing_config_file_fails(self):
        fails, _ = validate_env.validate(self.env(GOOD_ENV + "OPENVPN_CONFIG=/nonexistent/x.ovpn\n"))
        self.assertTrue(any("OPENVPN_CONFIG" in f for f in fails))

    def test_cli_exit_codes(self):
        good = write_env(GOOD_ENV)
        self.paths.append(good)
        bad = write_env("VPN_USER=\n")
        self.paths.append(bad)
        self.assertEqual(subprocess.run([sys.executable, VALIDATE, good],
                                        capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run([sys.executable, VALIDATE, bad],
                                        capture_output=True).returncode, 1)

    def test_validator_never_prints_secret_values(self):
        """AGENTS.md rule 3: values must never reach the console."""
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        path = write_env(f"VPN_USER=s0000001\nVPN_PASSWORD=sup3rs3cret\nTOTP_SECRET={secret}\n"
                         "TOTP_ALGO=md5\nTOTP_SKEW_WINDOWS=7\n")
        self.paths.append(path)
        out = subprocess.run([sys.executable, VALIDATE, path], capture_output=True, text=True)
        self.assertEqual(out.returncode, 1)
        for leak in ("sup3rs3cret", secret, "s0000001"):
            self.assertNotIn(leak, out.stdout, "validator printed a secret value")


def unguarded_grep_lines(src: str) -> list:
    """Line numbers where a grep runs inside $( ... ) without a '|| true' guard.

    A not-found probe (grep) exits 1 exactly when the check PASSES; under
    set -euo pipefail an unguarded grep in a command substitution ends the
    whole script at that moment (the CT211 selftest died on precisely this).
    Greps in if/!/while conditions are exempt: the conditional context
    neutralises set -e. Quoted strings are masked first so parens inside
    quotes do not skew the $()-depth; a block counts as guarded when
    '|| true' appears anywhere in the substitution span."""
    import re as _re
    _quotes = _re.compile('"[^"]*"' + "|" + "'[^']*'")
    src = _quotes.sub('""', src)
    out, depth = [], 0
    block = None  # [grep_line, guard_seen]
    for n, line in enumerate(src.splitlines(), 1):
        line = line.split("#")[0]
        cond = line.lstrip().startswith(("if ", "elif ", "while ", "!")) \
            or "if " in line.split("grep")[0]
        i = 0
        while i < len(line):
            if line.startswith("$(", i):
                depth += 1
                if depth == 1 and block is None:
                    block = [None, False]
                i += 2
                continue
            if line.startswith("grep", i) and depth > 0 and not cond \
                    and block is not None and block[0] is None:
                block[0] = n
            if "|| true" in line and block is not None:
                block[1] = True
            if line[i] == ")" and depth > 0:
                depth -= 1
                if depth == 0 and block is not None:
                    if block[0] is not None and not block[1]:
                        out.append(block[0])
                    block = None
            i += 1
    return out


class TestInitSetupScript(unittest.TestCase):
    """Static checks on init_setup.sh: the trap must stay gone, the validator
    must be wired in, and the script must pass shellcheck if it is installed."""

    def setUp(self):
        with open(os.path.join(ROOT, "init_setup.sh"), encoding="utf-8") as f:
            self.src = f.read()

    def test_no_and_ok_or_bad_pattern(self):
        for n, line in enumerate(self.src.splitlines(), 1):
            if "&& ok" in line and "|| bad" in line:
                self.fail(f"init_setup.sh:{n} reintroduces the '&& ok || bad' trap: {line}")

    def test_grep_in_command_substitution_is_guarded(self):
        """grep exits 1 on NO match — for a not-found probe that is the PASSING
        case. Under set -euo pipefail an unguarded grep inside $() kills the
        script mid-run (selftest died exactly this way on CT211). A grep in a
        command substitution needs '|| true'; a grep inside if/! conditions is
        protected by the conditional itself and must stay unguarded."""
        # regression: the detector must SEE the historical CT211 bug form
        buggy = ('hits=$(tr \'\\0\' \'\\n\' < f | grep -oE "^X=" | tr -d "="\n'
                 '            | sort -u)\n')
        self.assertEqual(unguarded_grep_lines(buggy), [1],
                         "detector blind to the multi-line $() grep bug")
        guarded = buggy.replace("sort -u)", "sort -u || true)")
        self.assertEqual(unguarded_grep_lines(guarded), [])
        cond = 'if grep -qE \'^x\' f; then ok y; fi\n'
        self.assertEqual(unguarded_grep_lines(cond), [],
                         "conditional greps must not be flagged")
        hits = unguarded_grep_lines(self.src)
        if hits:
            n = hits[0]
            self.fail(f"init_setup.sh:{n} unguarded grep in $() (set -e kills the "
                      f"script on the PASSING no-match case): {self.src.splitlines()[n-1]}")

    def test_no_and_or_guard_pattern(self):
        """The [ A ] && [ B ] || { ...; } guard is the same SC2015 trap: the
        block runs when A is true and B fails. init_setup.sh uses explicit if."""
        for n, line in enumerate(self.src.splitlines(), 1):
            if "] && [" in line and "|| {" in line:
                self.fail(f"init_setup.sh:{n} reintroduces the 'A && B || C' trap: {line}")

    def test_validator_is_wired_in(self):
        self.assertIn("scripts/validate_env.py", self.src)
        self.assertIn("scripts/lib_report.sh", self.src)

    def test_kill_is_warned(self):
        self.assertIn("killing the OpenVPN process", self.src)

    def test_shellcheck_clean(self):
        p = subprocess.run(["shellcheck", "-S", "info", "-x",
                            os.path.join(ROOT, "init_setup.sh"),
                            os.path.join(ROOT, "scripts", "lib_report.sh"),
                            os.path.join(ROOT, "scripts", "watchdog.sh"),
                            os.path.join(ROOT, "scripts", "env-reload.sh"),
                            os.path.join(ROOT, "scripts", "totp_auth.sh"),
                            os.path.join(ROOT, "scripts", "mgmt_responder.sh")],
                           capture_output=True, text=True)
        if p.returncode == 127:      # shellcheck not installed on this host
            self.skipTest("shellcheck not installed")
        self.assertEqual(p.returncode, 0, p.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
