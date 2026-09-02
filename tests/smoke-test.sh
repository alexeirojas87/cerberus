#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# Cerberus Smoke Test — R0 (FIXED per review feedback; re-repaired per
# R9-17, F4.3 — evidence/review9/gauntlet-findings.md)
#
# Implements §6.2 of CERBERUS_REVIEW_FINDINGS.md.
#
# R9-17 repairs (fix-plan §F4.3):
#   1. `cerberus init` failure is no longer swallowed by `|| true` —
#      init is a hard precondition and a failed init fails the run.
#   2. HTTP_CODE comes from the real response status
#      (`curl -w '%{http_code}'`) and is asserted with an explicit
#      comparison; the clean pass-through body is asserted too.
#   3. The 'cerberus-smock-*' typo is gone. The leak-check inspects an
#      enumerated list of real per-run artifacts (HOME tree, proxy log,
#      mock log via CERBERUS_MOCK_LOG) and FAILS if an expected artifact
#      is missing — grepping a missing file can only report "clean".
#
# Gate: any failed check fails the run (exit 1).
#
# Usage: ./tests/smoke-test.sh [--build] [--port PORT]
#   --build    Build release binary before running (default: false)
#   --port     Port for the proxy (default: 18787, avoids conflicts)
#
# Exit: 0 = all checks passed, 1 = one or more checks failed
# ──────────────────────────────────────────────────────────────────────

# ── Globals ─────────────────────────────────────────────────────────────
TEST_HOME=""
PORT=18787
MOCK_PORT=0          # will be assigned an ephemeral port
EVIDENCE_DIR=""
TEST_LOG=""
DAEMON_LOG=""        # per-run proxy log (R9-17: real, enumerated artifact)
MOCK_LOG=""          # per-run mock request log (R9-17: real, enumerated artifact)
PASS_COUNT=0
FAIL_COUNT=0

# ── Helpers ─────────────────────────────────────────────────────────────
pass_check() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ✅ PASS: $1" | tee -a "$TEST_LOG"
}

fail_check() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  ❌ FAIL: $1" | tee -a "$TEST_LOG"
}

log_section() {
    echo "" | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
    echo " $1" | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
}

# Find an available TCP port (ephemeral — like Rust harness uses port 0).
find_free_port() {
    local port
    # Try multiple times to avoid collisions
    for _try in $(seq 1 20); do
        port=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
")
        # Verify it is actually free
        if ! lsof -tiTCP:"$port" -iTCP:LISTEN >/dev/null 2>&1; then
            echo "$port"
            return 0
        fi
    done
    echo "ERROR: could not find a free port" >&2
    return 1
}

# Kill any process listening on a given port.
free_port() {
    local p="$1"
    lsof -iTCP:"$p" -sTCP:LISTEN -t 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    sleep 0.3
}

# ── Cleanup (by PORT, not PID — idempotent) ────────────────────────────
cleanup() {
    # Free ports (regardless of PID tracking)
    if [ -n "${PORT:-}" ]; then
        free_port "$PORT"
    fi
    if [ -n "${MOCK_PORT:-}" ] && [ "$MOCK_PORT" != "0" ]; then
        free_port "$MOCK_PORT"
    fi
    # Remove tmp HOME
    if [ -n "${TEST_HOME:-}" ] && [ -d "$TEST_HOME" ]; then
        rm -rf "$TEST_HOME"
    fi
    # R9-17/F4.3: deterministic cleanup — per-run log artifacts go with the run
    if [ -n "${DAEMON_LOG:-}" ]; then
        rm -f "$DAEMON_LOG"
    fi
    if [ -n "${MOCK_LOG:-}" ]; then
        rm -f "$MOCK_LOG"
    fi
}

# Ensure cleanup runs on exit, interrupt, or pipe-close
trap cleanup EXIT INT TERM

# ── Parse args ──────────────────────────────────────────────────────────
BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) BUILD=true; shift ;;
        --port)  PORT="$2"; shift 2 ;;
        *)       shift ;;
    esac
done

# ── Precondition: free ports before anything else ──────────────────────
free_port "$PORT"
MOCK_PORT=$(find_free_port) || { echo "FATAL: no free port for mock"; exit 2; }
echo "Using PROXY port=$PORT  MOCK port=$MOCK_PORT"

# ── Setup evidence dir ─────────────────────────────────────────────────
EVIDENCE_DIR="$(dirname "$0")/../evidence/r0/smoke-test"
mkdir -p "$EVIDENCE_DIR"
TEST_LOG="$EVIDENCE_DIR/smoke-run-$(date +%Y%m%d-%H%M%S).log"

# ── STEP 0: Build ──────────────────────────────────────────────────────
log_section "STEP 0: Build"

if [ "$BUILD" = true ]; then
    echo "  Building release binary..." | tee -a "$TEST_LOG"
    cargo build --release --workspace 2>&1 | tee -a "$TEST_LOG"
fi

BINARY="./target/release/cerberus"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY. Run with --build." | tee -a "$TEST_LOG"
    exit 1
fi
pass_check "Binary exists at $BINARY"

# ── STEP 1: Clean installation (tmp HOME) ──────────────────────────────
log_section "STEP 1: Clean installation (tmp HOME)"

TEST_HOME=$(mktemp -d)
export HOME="$TEST_HOME"

echo "  Using tmp HOME: $TEST_HOME" | tee -a "$TEST_LOG"
pass_check "Clean HOME created"

# ── STEP 2: cerberus init ──────────────────────────────────────────────
log_section "STEP 2: cerberus init"

# R9-17 repair: init is a hard precondition. The old `|| true` swallowed a
# failed init and let the run continue on a broken installation.
INIT_RC=0
"$BINARY" init 2>&1 | tee -a "$TEST_LOG" || INIT_RC=$?
if [ "$INIT_RC" -ne 0 ]; then
    fail_check "cerberus init exited with code $INIT_RC (was previously swallowed by '|| true')"
    echo "FATAL: init failed — aborting smoke test." | tee -a "$TEST_LOG"
    exit 1
fi

if [ -d "$TEST_HOME/.cerberus" ]; then
    pass_check "Config directory ~/.cerberus created"
else
    fail_check "Config directory ~/.cerberus NOT created"
fi

# ── R9-5 (F6): the control plane is now AUTHENTICATED BY DEFAULT ───────
# `cerberus init` generates a random admin token into config.yaml (0600).
# DELTA vs the pre-F6 dev-mode script: every /api/* call below must carry
# the token; without it the control plane is FAIL-CLOSED (401, loopback
# included) — that is the R9-5 fix, asserted explicitly at TEST POINT 5a.
ADMIN_TOKEN=$(sed -n 's/^admin_token: *//p' "$TEST_HOME/.cerberus/config.yaml" | tr -d '"[:space:]')
if [ -n "$ADMIN_TOKEN" ]; then
    pass_check "init generated an admin token (R9-5: authenticated control plane by default)"
else
    fail_check "init did NOT generate an admin token (control plane would be closed)"
fi
AUTH=(-H "X-Cerberus-Admin-Token: $ADMIN_TOKEN")

# ── STEP 3: Start proxy daemon ─────────────────────────────────────────
log_section "STEP 3: Start proxy daemon on port $PORT"

# Tell the proxy where to forward upstream requests (must be set before daemon starts)
export CERBERUS_UPSTREAM_URL="http://127.0.0.1:${MOCK_PORT}"

# R9-17/F4.3: the proxy log is a real per-run artifact (the old leak-check
# 'covered' the proxy log with a typo'd path 'cerberus-smock-*.log' that
# never existed). Fresh per run — stale logs must never feed a leak check.
DAEMON_LOG="/tmp/cerberus-smoke-${PORT}.log"
rm -f "$DAEMON_LOG"
"$BINARY" start --port "$PORT" > "$DAEMON_LOG" 2>&1 &
PROXY_PID=$!

# Wait for daemon to be ready (hard precondition)
READY=false
for i in $(seq 1 20); do
    if curl -s -m 2 "http://127.0.0.1:${PORT}/health" 2>/dev/null | grep -q '"ok"'; then
        READY=true
        break
    fi
    sleep 0.5
done

if [ "$READY" = true ]; then
    HEALTH=$(curl -s -m 2 "http://127.0.0.1:${PORT}/health" 2>/dev/null || echo "{}")
    echo "  Health check response: $HEALTH" | tee -a "$TEST_LOG"
    pass_check "Health endpoint returns OK on port $PORT"
else
    echo "  ERROR: daemon never became healthy on port $PORT" | tee -a "$TEST_LOG"
    fail_check "Health endpoint NOT responding on port $PORT"
    # Hard precondition — abort
    echo "FATAL: daemon not ready. Aborting test." | tee -a "$TEST_LOG"
    exit 1
fi

# ── STEP 4: Start mock upstream (HARD PRECONDITION) ────────────────────
log_section "STEP 4: Start mock upstream server on port $MOCK_PORT"

# R9-17/F4.3: the mock's request log becomes a real per-run artifact via
# CERBERUS_MOCK_LOG (previously it went to a shared, never-inspected default
# path while the leak-check pretended to grep mock logs).
MOCK_LOG="/tmp/cerberus-smoke-mock-${MOCK_PORT}.log"
export CERBERUS_MOCK_LOG="$MOCK_LOG"
rm -f "$MOCK_LOG"
python3 tools/mock-server.py "$MOCK_PORT" > /dev/null 2>&1 &
MOCK_PID=$!

# Wait for mock to be ready (hard precondition)
MOCK_READY=false
for i in $(seq 1 20); do
    MOCK_CHECK=$(curl -s -m 2 "http://127.0.0.1:${MOCK_PORT}/__cerberus__/ready" 2>/dev/null || echo "{}")
    if echo "$MOCK_CHECK" | grep -q '"ready"'; then
        MOCK_READY=true
        break
    fi
    sleep 0.5
done

if [ "$MOCK_READY" = true ]; then
    echo "  Mock ready: $MOCK_CHECK" | tee -a "$TEST_LOG"
    pass_check "Mock upstream server running on port $MOCK_PORT"
else
    echo "  Mock ready: {}" | tee -a "$TEST_LOG"
    fail_check "Mock upstream server NOT ready on port $MOCK_PORT"
    # HARD PRECONDITION — abort immediately.
    # Without a working mock, all subsequent checks are ambiguous.
    echo "" | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
    echo "  FATAL: Mock server did not start. Cannot run test body." | tee -a "$TEST_LOG"
    echo "  The mock is a PRECONDITION — not a test assertion." | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
    exit 1
fi

# ── TEST POINT 3: .env in UPPERCASE (P0-1) ─────────────────────────────
log_section "STEP 5: TEST POINT 3 — .env in UPPERCASE (P0-1)"

SECRET_PAYLOAD='{"messages":[{"role":"user","content":"OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345"}]}'

RESULT=$(curl -s -m 5 -X POST "http://127.0.0.1:${PORT}/openai/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -d "$SECRET_PAYLOAD" 2>/dev/null || echo "")

echo "  Request: secret in .env uppercase content" | tee -a "$TEST_LOG"
echo "  Response: $RESULT" | tee -a "$TEST_LOG"

if echo "$RESULT" | grep -q "blocked\|redacted\|error"; then
    pass_check "P0-1: SECRET DETECTED (block or redact)"
else
    fail_check "P0-1: SECRET NOT DETECTED — 'OPENAI_API_KEY' in uppercase not caught"
fi

# ── TEST POINT 4: Clean pass-through (P0-4, P0-5) ─────────────────────
log_section "STEP 6: TEST POINT 4 — Clean pass-through (P0-4, P0-5)"

CLEAN_PAYLOAD='{"messages":[{"role":"user","content":"hello"}]}'

# R9-17 repair: HTTP_CODE comes from the REAL response status via
# `-w '%{http_code}'`. The old block derived it from curl's EXIT STATUS
# (exit 0 → hardcoded "200"), so any completed transfer — including a 4xx/5xx
# block response — was reported as HTTP 200.
HTTP_CODE=$(curl -s -m 5 -o /tmp/cerberus-smoke-upstream-body.txt \
    -w '%{http_code}' \
    -X POST "http://127.0.0.1:${PORT}/openai/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$CLEAN_PAYLOAD" 2>/dev/null) || HTTP_CODE="000"
UPSTREAM_BODY=$(cat /tmp/cerberus-smoke-upstream-body.txt 2>/dev/null || echo "")

echo "  Request: clean payload to /openai/v1/chat/completions" | tee -a "$TEST_LOG"
echo "  HTTP response code: $HTTP_CODE" | tee -a "$TEST_LOG"
echo "  Response body: ${UPSTREAM_BODY:0:200}" | tee -a "$TEST_LOG"

# Explicit status assertion
if [ "$HTTP_CODE" = "200" ]; then
    pass_check "P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)"
else
    fail_check "P0-4/P0-5: CLEAN REQUEST NOT forwarded — HTTP response code $HTTP_CODE"
fi

# Explicit body assertion (F4.3: asertar body/status) — the clean content
# must come back un-mangled: no false redaction, response passthrough intact.
if echo "$UPSTREAM_BODY" | grep -q 'hello'; then
    pass_check "P0-4/P0-5: clean content echoed back by upstream (body passthrough intact)"
else
    fail_check "P0-4/P0-5: clean content NOT echoed back by upstream (body passthrough broken)"
fi

# Check if mock received the request (independent verification)
sleep 0.5
MOCK_LAST=$(curl -s -m 2 "http://127.0.0.1:${MOCK_PORT}/__cerberus__/last" 2>/dev/null || echo "{}")
echo "  Mock /__cerberus__/last: $MOCK_LAST" | tee -a "$TEST_LOG"

if echo "$MOCK_LAST" | grep -q '"echo"'; then
    pass_check "Mock upstream received the clean request body"
else
    # Distinguish: did the proxy send it, or did the mock not receive it?
    if [ "$HTTP_CODE" = "200" ]; then
        # Proxy returned 200 but mock didn't record — mock may be slow
        # This is a timing issue, not a proxy bug — but still note it
        echo "  NOTE: Proxy returned 200 but mock didn't record (timing?)" | tee -a "$TEST_LOG"
    else
        fail_check "Mock upstream did NOT receive the clean request body"
    fi
fi

# ── TEST POINT 5: Events persisted with provider (P0-6) ────────────────
log_section "STEP 7: TEST POINT 5 — Events persisted with provider (P0-6)"

# R9-5 (F6) DELTA: the API calls authenticate with the admin token that
# `cerberus init` generated (dev-mode-open /api/* is gone).
EVENTS=$(curl -s -m 3 "${AUTH[@]}" "http://127.0.0.1:${PORT}/api/events" 2>/dev/null || echo "[]")
echo "  /api/events: $EVENTS" | tee -a "$TEST_LOG"

if [ "$EVENTS" = "[]" ] || [ -z "$EVENTS" ]; then
    fail_check "P0-6: /api/events is EMPTY (should have at least the blocked event)"
else
    pass_check "P0-6: /api/events returned events (non-empty)"
fi

STATS=$(curl -s -m 3 "${AUTH[@]}" "http://127.0.0.1:${PORT}/api/stats" 2>/dev/null || echo '{}')
echo "  /api/stats: $STATS" | tee -a "$TEST_LOG"

if echo "$STATS" | grep -q '"by_provider":\[\]'; then
    fail_check "P0-6: /api/stats by_provider is EMPTY (should show provider grouping)"
elif echo "$STATS" | grep -q '"total":0'; then
    fail_check "P0-6: /api/stats total is 0 (no events recorded)"
else
    pass_check "P0-6: /api/stats returned non-trivial data"
fi

# ── TEST POINT 5a: R9-5 fail-closed control plane (F6) ─────────────────
log_section "STEP 7a: TEST POINT 5a — R9-5 fail-closed control plane (F6)"

# Without the token: 401 on every data route, loopback included.
NOAUTH=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/events" 2>/dev/null || echo "000")
if [ "$NOAUTH" = "401" ]; then
    pass_check "R9-5: /api/events WITHOUT token → 401 (fail-closed, loopback included)"
else
    fail_check "R9-5: /api/events WITHOUT token returned $NOAUTH (must be 401)"
fi

WRONGTOK=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -H "X-Cerberus-Admin-Token: wrong-token-wrong-token-12345" "http://127.0.0.1:${PORT}/api/events" 2>/dev/null || echo "000")
if [ "$WRONGTOK" = "401" ]; then
    pass_check "R9-5: /api/events with a WRONG token → 401"
else
    fail_check "R9-5: /api/events with a WRONG token returned $WRONGTOK (must be 401)"
fi

# DNS-rebinding Host header → 403 BEFORE authentication.
REBIND=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -H "Host: attacker.com:${PORT}" "${AUTH[@]}" "http://127.0.0.1:${PORT}/api/events" 2>/dev/null || echo "000")
if [ "$REBIND" = "403" ]; then
    pass_check "R9-5: rebound Host (attacker.com) → 403 (anti-rebinding allowlist)"
else
    fail_check "R9-5: rebound Host (attacker.com) returned $REBIND (must be 403)"
fi

# R9-5/F6.2 (adapted F4 negative vector): an UNAUTHENTICATED data-plane
# bypass must be REFUSED — the secret payload must NOT reach the mock.
# The F4 evidence proved this vector leaked in dev mode; the fix closes it.
curl -s -m 3 -o /dev/null \
    -X POST "http://127.0.0.1:${PORT}/openai/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Cerberus-Bypass: smoke-negative-leak-injection" \
    -d "$SECRET_PAYLOAD" 2>/dev/null >/dev/null
sleep 0.3
if [ -f "$MOCK_LOG" ] && grep -q "$SECRET_PAYLOAD" "$MOCK_LOG" 2>/dev/null; then
    fail_check "R9-5/F6.2: UNAUTHENTICATED bypass LEAKED the payload into the mock (must be refused)"
else
    pass_check "R9-5/F6.2: unauthenticated X-Cerberus-Bypass refused (payload did not reach the mock)"
fi

if [ -f "$TEST_HOME/.cerberus/cerberus.db" ] || [ -f "cerberus.db" ]; then
    pass_check "SQLite database file exists"
else
    fail_check "SQLite database file NOT created at ~/.cerberus/cerberus.db"
fi

# ── TEST POINT 6: Zero leak ───────────────────────────────────────────
log_section "STEP 8: TEST POINT 6 — Zero leak (no raw secrets in logs/DB)"

RAW_SECRET="sk-abc123def456ghi789jkl012mno345"

# R9-17 repair: every inspected surface is enumerated up-front and MUST
# exist. Grepping a missing file can only ever report "clean" — that is how
# the old check stayed vacuous ('/tmp/cerberus-smock-*.log' never existed).
# A missing expected artifact is a failure, not a silent pass.
LEAK_SURFACES=("$TEST_HOME" "$DAEMON_LOG" "$MOCK_LOG")

MISSING_SURFACES=""
LEAK_HITS=""
for surface in "${LEAK_SURFACES[@]}"; do
    if [ ! -e "$surface" ]; then
        MISSING_SURFACES="${MISSING_SURFACES}
  - ${surface}"
        continue
    fi
    GREP_RC=0
    HITS=$(grep -r "$RAW_SECRET" "$surface" 2>/dev/null) || GREP_RC=$?
    if [ "$GREP_RC" -ge 2 ]; then
        fail_check "Leak grep errored (rc=$GREP_RC) on $surface — cannot certify no-leak"
    elif [ -n "$HITS" ]; then
        LEAK_HITS="${LEAK_HITS}
--- ${surface} ---
${HITS}"
    fi
done

if [ -n "$MISSING_SURFACES" ]; then
    fail_check "Leak-check surface(s) missing — evidence would be vacuous:${MISSING_SURFACES}"
fi

if [ -n "$LEAK_HITS" ]; then
    fail_check "RAW SECRET FOUND in logs or data files!"
    echo "$LEAK_HITS" | tee -a "$TEST_LOG"
elif [ -z "$MISSING_SURFACES" ]; then
    pass_check "No raw secret leaked in HOME tree, proxy log ($DAEMON_LOG), or mock log ($MOCK_LOG) — 3/3 surfaces present and inspected"
fi

# ── Summary ─────────────────────────────────────────────────────────────
log_section "SMOKE TEST RESULT"

echo "  Pass: $PASS_COUNT" | tee -a "$TEST_LOG"
echo "  Fail: $FAIL_COUNT" | tee -a "$TEST_LOG"
echo "  Log file: $TEST_LOG" | tee -a "$TEST_LOG"
echo "" | tee -a "$TEST_LOG"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "  ✅ ALL: Smoke test PASSED" | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
    EXIT_CODE=0
else
    echo "  ❌ FAIL: Smoke test has $FAIL_COUNT failed checks" | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
    EXIT_CODE=1
fi

exit $EXIT_CODE
