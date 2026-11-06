#!/usr/bin/env bash
# lib_report.sh — the [OK]/[WARN]/[FAIL] reporting helpers used by init_setup.sh.
# Sourced, not executed: keeping them in one place makes them unit-testable
# (tests/test_init_setup.py) without running a root-only setup script.
#
# Reporting rule: every check uses an explicit if/then/else. The common
# `cond && ok x || bad y` shorthand is a trap — when `cond` is true and `ok`
# returns non-zero, `bad` runs as well, so a passing check is reported as a
# failure. Never reintroduce it.

PASS=0
FAIL=0
WARN=0

ok()   { printf '[ OK ] %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '[FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }
warn() { printf '[WARN] %s\n' "$*"; WARN=$((WARN+1)); }

# report <rc> "subject" ["detail"] — the if/else form of a single check, for a
# captured exit code. Use this instead of inline `cond && ok x || bad y`.
report() {
    local rc=$1 subject=$2 detail=${3:-}
    if [ "$rc" = "0" ]; then
        ok "$subject${detail:+ — $detail}"
    else
        bad "$subject${detail:+ — $detail}"
    fi
}
