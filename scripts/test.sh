#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="$SCRIPT_DIR/analyze.py"

PASS=0
FAIL=0
TMPDIR_TEST=$(mktemp -d /tmp/log-analyzer-test.XXXXXX)

cleanup() {
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

pass() {
    PASS=$((PASS + 1))
    echo "  PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1"
    echo "        $2"
}

# =========================================================================
# Gate 1: Smoke
# =========================================================================
echo ""
echo "=== Gate 1: Smoke ==="

# Create a simple JSON lines log
cat > "$TMPDIR_TEST/simple.jsonl" << 'LOG'
{"timestamp": "2025-01-15T10:00:00", "level": "info", "message": "Application started"}
{"timestamp": "2025-01-15T10:00:01", "level": "info", "message": "Listening on port 8080"}
{"timestamp": "2025-01-15T10:00:05", "level": "error", "message": "Connection refused to database"}
{"timestamp": "2025-01-15T10:00:06", "level": "error", "message": "Connection refused to database"}
{"timestamp": "2025-01-15T10:00:07", "level": "warn", "message": "Retry attempt 1"}
{"timestamp": "2025-01-15T10:00:10", "level": "error", "message": "Connection refused to database"}
{"timestamp": "2025-01-15T10:00:12", "level": "error", "message": "Timeout waiting for response"}
{"timestamp": "2025-01-15T10:00:15", "level": "info", "message": "Connection restored"}
LOG

OUTPUT=$(python3 "$ANALYZER" "$TMPDIR_TEST/simple.jsonl" 2>&1) || true

# Smoke check: output contains total lines
if echo "$OUTPUT" | grep -qF -- "Total lines parsed: 8"; then
    pass "Total lines parsed is 8"
else
    fail "Total lines parsed" "Expected 'Total lines parsed: 8', got: $(echo "$OUTPUT" | head -3)"
fi

# Smoke check: output contains ERROR count
if echo "$OUTPUT" | grep -qF -- "ERROR :"; then
    pass "Output contains ERROR level count"
else
    fail "ERROR level count" "Output missing ERROR line"
fi

# Smoke check: error count is 4
if echo "$OUTPUT" | grep -qF -- "ERROR :     4"; then
    pass "ERROR count is 4"
else
    fail "ERROR count" "Expected ERROR count 4 in output"
fi

# Smoke check: patterns section exists
if echo "$OUTPUT" | grep -qF -- "Top"; then
    pass "Output contains top patterns section"
else
    fail "Top patterns section" "Output missing Top patterns"
fi

echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "Gate 1 FAILED ($FAIL failures). Stopping."
    exit 1
fi
echo "Gate 1 passed ($PASS tests)."

# =========================================================================
# Gate 2: Contract
# =========================================================================
echo ""
echo "=== Gate 2: Contract ==="

# Contract: empty input via stdin should fail with exit 1
EMPTY_OUT=$(echo "" | python3 "$ANALYZER" 2>&1) && EMPTY_RC=$? || EMPTY_RC=$?
if [ "$EMPTY_RC" -eq 1 ]; then
    pass "Empty stdin returns exit code 1"
else
    fail "Empty stdin exit code" "Expected 1, got $EMPTY_RC"
fi

# Contract: non-existent file should fail with exit 2
NOFILE_OUT=$(python3 "$ANALYZER" "/tmp/no-such-file-ever-exists-xyz.log" 2>&1) && NOFILE_RC=$? || NOFILE_RC=$?
if [ "$NOFILE_RC" -eq 2 ]; then
    pass "Non-existent file returns exit code 2"
else
    fail "Non-existent file exit code" "Expected 2, got $NOFILE_RC"
fi

# Contract: JSON output is valid JSON
JSON_OUT=$(python3 "$ANALYZER" --format=json "$TMPDIR_TEST/simple.jsonl" 2>&1) || true
if echo "$JSON_OUT" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "JSON output is valid JSON"
else
    fail "JSON output validity" "Output is not valid JSON"
fi

# Contract: JSON output has expected keys
HAS_KEYS=$(echo "$JSON_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
needed = {'total_lines', 'levels', 'top_patterns', 'time_range'}
missing = needed - set(d.keys())
if missing:
    print('missing: ' + str(missing))
    sys.exit(1)
print('ok')
" 2>&1) && KEYS_RC=$? || KEYS_RC=$?
if [ "$KEYS_RC" -eq 0 ]; then
    pass "JSON output has all required keys"
else
    fail "JSON keys" "$HAS_KEYS"
fi

# Contract: --level with unknown value fails
UNK_OUT=$(python3 "$ANALYZER" --level=potato "$TMPDIR_TEST/simple.jsonl" 2>&1) && UNK_RC=$? || UNK_RC=$?
if [ "$UNK_RC" -eq 1 ]; then
    pass "Unknown --level value returns exit code 1"
else
    fail "Unknown --level exit code" "Expected 1, got $UNK_RC"
fi

echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "Gate 2 FAILED ($FAIL failures). Stopping."
    exit 1
fi
echo "Gate 2 passed ($PASS tests)."

# =========================================================================
# Gate 3: Integration
# =========================================================================
echo ""
echo "=== Gate 3: Integration ==="

# --- Apache format ---
cat > "$TMPDIR_TEST/access.log" << 'LOG'
192.168.1.1 - - [15/Jan/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.2 - - [15/Jan/2025:10:00:01 +0000] "GET /api/users HTTP/1.1" 200 567
192.168.1.3 - - [15/Jan/2025:10:00:02 +0000] "POST /api/login HTTP/1.1" 401 89
192.168.1.4 - - [15/Jan/2025:10:00:03 +0000] "GET /missing HTTP/1.1" 404 0
192.168.1.5 - - [15/Jan/2025:10:00:04 +0000] "GET /api/data HTTP/1.1" 500 0
192.168.1.6 - - [15/Jan/2025:10:00:05 +0000] "POST /api/submit HTTP/1.1" 503 0
192.168.1.7 - - [15/Jan/2025:10:00:06 +0000] "GET /health HTTP/1.1" 200 15
LOG

APACHE_OUT=$(python3 "$ANALYZER" "$TMPDIR_TEST/access.log" 2>&1) || true
if echo "$APACHE_OUT" | grep -qF -- "Total lines parsed: 7"; then
    pass "Apache: parsed 7 lines"
else
    fail "Apache line count" "Expected 7 lines"
fi

if echo "$APACHE_OUT" | grep -qF -- "ERROR :     2"; then
    pass "Apache: 2 errors (500, 503)"
else
    fail "Apache error count" "Expected 2 errors for 5xx status codes"
fi

if echo "$APACHE_OUT" | grep -qF -- "WARN  :     2"; then
    pass "Apache: 2 warnings (401, 404)"
else
    fail "Apache warn count" "Expected 2 warnings for 4xx status codes"
fi

# Apache time range
APACHE_JSON=$(python3 "$ANALYZER" --format=json "$TMPDIR_TEST/access.log" 2>&1) || true
APACHE_TR=$(echo "$APACHE_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
tr = d.get('time_range')
if tr and tr.get('first') and tr.get('last'):
    print('ok')
else:
    print('missing')
" 2>&1) || true
if [ "$APACHE_TR" = "ok" ]; then
    pass "Apache: time range extracted"
else
    fail "Apache time range" "Time range missing or incomplete"
fi

# --- Syslog format ---
cat > "$TMPDIR_TEST/syslog.log" << 'LOG'
Jan 15 10:00:00 webserver nginx[1234]: Starting nginx
Jan 15 10:00:01 webserver nginx[1234]: Listening on 0.0.0.0:80
Jan 15 10:00:05 webserver kernel: ERROR: out of memory
Jan 15 10:00:06 dbserver mysql[5678]: WARN: slow query detected
Jan 15 10:00:07 dbserver mysql[5678]: INFO: query completed
Jan 15 10:00:08 webserver nginx[1234]: ERROR: upstream timeout
LOG

SYSLOG_OUT=$(python3 "$ANALYZER" "$TMPDIR_TEST/syslog.log" 2>&1) || true
if echo "$SYSLOG_OUT" | grep -qF -- "Total lines parsed: 6"; then
    pass "Syslog: parsed 6 lines"
else
    fail "Syslog line count" "Expected 6 lines"
fi

if echo "$SYSLOG_OUT" | grep -qF -- "ERROR :     2"; then
    pass "Syslog: 2 errors found"
else
    fail "Syslog error count" "Expected 2 errors"
fi

# --- --level filter ---
LEVEL_OUT=$(python3 "$ANALYZER" --level=error "$TMPDIR_TEST/simple.jsonl" 2>&1) || true
# Should still show all level counts in summary but only error patterns
if echo "$LEVEL_OUT" | grep -qF -- "ERROR :     4"; then
    pass "--level=error: ERROR count still shows 4"
else
    fail "--level filter ERROR count" "Expected ERROR: 4"
fi

# Patterns should only include error-level items
LEVEL_JSON=$(python3 "$ANALYZER" --format=json --level=error "$TMPDIR_TEST/simple.jsonl" 2>&1) || true
PATTERN_CHECK=$(echo "$LEVEL_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
patterns = d.get('top_patterns', [])
if len(patterns) > 0:
    print('has_patterns')
else:
    print('no_patterns')
" 2>&1) || true
if [ "$PATTERN_CHECK" = "has_patterns" ]; then
    pass "--level=error: patterns present for error messages"
else
    fail "--level filter patterns" "Expected error patterns in output"
fi

# --- --top flag ---
TOP_JSON=$(python3 "$ANALYZER" --format=json --top=2 "$TMPDIR_TEST/simple.jsonl" 2>&1) || true
TOP_COUNT=$(echo "$TOP_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len(d.get('top_patterns', [])))
" 2>&1) || true
if [ "$TOP_COUNT" -le 2 ]; then
    pass "--top=2: at most 2 patterns returned ($TOP_COUNT)"
else
    fail "--top flag" "Expected at most 2 patterns, got $TOP_COUNT"
fi

# --- Mixed format resilience ---
cat > "$TMPDIR_TEST/mixed.log" << 'LOG'
{"timestamp": "2025-01-15T10:00:00", "level": "error", "message": "JSON error line"}
192.168.1.1 - - [15/Jan/2025:10:00:01 +0000] "GET /fail HTTP/1.1" 500 0
Jan 15 10:00:02 myhost app[99]: ERROR: syslog error line
2025-01-15 10:00:03 ERROR generic error line here
just a plain line with no structure
LOG

MIXED_OUT=$(python3 "$ANALYZER" "$TMPDIR_TEST/mixed.log" 2>&1) || true
if echo "$MIXED_OUT" | grep -qF -- "Total lines parsed: 5"; then
    pass "Mixed format: parsed 5 lines"
else
    fail "Mixed format line count" "Expected 5 lines. Got: $(echo "$MIXED_OUT" | head -2)"
fi

MIXED_JSON=$(python3 "$ANALYZER" --format=json "$TMPDIR_TEST/mixed.log" 2>&1) || true
MIXED_FMTS=$(echo "$MIXED_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
fmts = d.get('formats_detected', {})
count = len(fmts)
print(count)
" 2>&1) || true
if [ "$MIXED_FMTS" -ge 3 ]; then
    pass "Mixed format: detected $MIXED_FMTS distinct formats"
else
    fail "Mixed format detection" "Expected >= 3 formats, got $MIXED_FMTS"
fi

# --- Stdin piping ---
STDIN_OUT=$(cat "$TMPDIR_TEST/simple.jsonl" | python3 "$ANALYZER" 2>&1) || true
if echo "$STDIN_OUT" | grep -qF -- "Total lines parsed: 8"; then
    pass "Stdin pipe: parsed 8 lines"
else
    fail "Stdin pipe" "Expected 8 lines from piped input"
fi

# =========================================================================
# Summary
# =========================================================================
echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
echo "All gates passed."
exit 0
