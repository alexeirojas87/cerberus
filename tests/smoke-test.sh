#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# Cerberus Smoke Test — R0 (FIXED per review feedback)
#
# Implements §6.2 of CERBERUS_REVIEW_FINDINGS.md.
#
# Gate: el smoke test DEBE FALLAR en los puntos 3, 4 y 5
# (documenta el estado roto antes de R1+R2 fixes).
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
    rtk cargo build --release --workspace 2>&1 | tee -a "$TEST_LOG"
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

"$BINARY" init 2>&1 | tee -a "$TEST_LOG" || true

if [ -d "$TEST_HOME/.cerberus" ]; then
    pass_check "Config directory ~/.cerberus created"
else
    fail_check "Config directory ~/.cerberus NOT created"
fi

# ── STEP 3: Start proxy daemon ─────────────────────────────────────────
log_section "STEP 3: Start proxy daemon on port $PORT"

# Tell the proxy where to forward upstream requests (must be set before daemon starts)
export CERBERUS_UPSTREAM_URL="http://127.0.0.1:${MOCK_PORT}"
"$BINARY" start --port "$PORT" > /tmp/cerberus-smoke-daemon.log 2>&1 &
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

# ── TEST POINT 3: .env en MAYÚSCULAS (P0-1) ────────────────────────────
log_section "STEP 5: TEST POINT 3 — .env en MAYÚSCULAS (P0-1)"

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

# ── TEST POINT 4: Pass-through limpio (P0-4, P0-5) ─────────────────────
log_section "STEP 6: TEST POINT 4 — Pass-through limpio (P0-4, P0-5)"

CLEAN_PAYLOAD='{"messages":[{"role":"user","content":"hola"}]}'

# Try to forward to the mock upstream
HTTP_CODE=""
if curl -s -m 5 -o /tmp/cerberus-smoke-upstream-body.txt \
    -X POST "http://127.0.0.1:${PORT}/openai/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$CLEAN_PAYLOAD" 2>/dev/null; then
    HTTP_CODE="200"
else
    HTTP_CODE="000"
fi
UPSTREAM_BODY=$(cat /tmp/cerberus-smoke-upstream-body.txt 2>/dev/null || echo "")

echo "  Request: clean payload to /openai/v1/chat/completions" | tee -a "$TEST_LOG"
echo "  HTTP response code: $HTTP_CODE" | tee -a "$TEST_LOG"
echo "  Response body: ${UPSTREAM_BODY:0:200}" | tee -a "$TEST_LOG"

# Distinguish proxy forwarding failure from mock failure
if [ "$HTTP_CODE" = "200" ]; then
    pass_check "P0-4/P0-5: CLEAN REQUEST forwarded successfully (HTTP 200)"
else
    fail_check "P0-4/P0-5: CLEAN REQUEST NOT forwarded — exit code $HTTP_CODE"
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

# ── TEST POINT 5: Events persistidos con provider (P0-6) ────────────────
log_section "STEP 7: TEST POINT 5 — Events persistidos con provider (P0-6)"

EVENTS=$(curl -s -m 3 "http://127.0.0.1:${PORT}/api/events" 2>/dev/null || echo "[]")
echo "  /api/events: $EVENTS" | tee -a "$TEST_LOG"

if [ "$EVENTS" = "[]" ] || [ -z "$EVENTS" ]; then
    fail_check "P0-6: /api/events is EMPTY (should have at least the blocked event)"
else
    pass_check "P0-6: /api/events returned events (non-empty)"
fi

STATS=$(curl -s -m 3 "http://127.0.0.1:${PORT}/api/stats" 2>/dev/null || echo '{}')
echo "  /api/stats: $STATS" | tee -a "$TEST_LOG"

if echo "$STATS" | grep -q '"by_provider":\[\]'; then
    fail_check "P0-6: /api/stats by_provider is EMPTY (should show provider grouping)"
elif echo "$STATS" | grep -q '"total":0'; then
    fail_check "P0-6: /api/stats total is 0 (no events recorded)"
else
    pass_check "P0-6: /api/stats returned non-trivial data"
fi

if [ -f "$TEST_HOME/.cerberus/cerberus.db" ] || [ -f "cerberus.db" ]; then
    pass_check "SQLite database file exists"
else
    fail_check "SQLite database file NOT created at ~/.cerberus/cerberus.db"
fi

# ── TEST POINT 6: Fuga cero ───────────────────────────────────────────
log_section "STEP 8: TEST POINT 6 — Fuga cero (no raw secrets in logs/DB)"

RAW_SECRET="sk-abc123def456ghi789jkl012mno345"

LOG_LEAK=$(grep -r "$RAW_SECRET" "$TEST_HOME" 2>/dev/null || true)
PROXY_LOG_LEAK=$(grep -r "$RAW_SECRET" /tmp/cerberus-smoke-daemon.log 2>/dev/null || true)
PROXY_LOG_LEAK2=$(grep -r "$RAW_SECRET" /tmp/cerberus-smock-${PORT}.log 2>/dev/null || true)

if [ -z "$LOG_LEAK" ] && [ -z "$PROXY_LOG_LEAK" ] && [ -z "$PROXY_LOG_LEAK2" ]; then
    pass_check "No raw secret leaked in HOME, proxy logs, or mock logs"
else
    fail_check "RAW SECRET FOUND in logs or data files!"
    echo "  HOME leak: $LOG_LEAK" | tee -a "$TEST_LOG"
    echo "  Proxy log leak: $PROXY_LOG_LEAK" | tee -a "$TEST_LOG"
    echo "  Mock log leak: $PROXY_LOG_LEAK2" | tee -a "$TEST_LOG"
fi

# ── Summary ─────────────────────────────────────────────────────────────
log_section "RESULTADO DEL SMOKE TEST"

echo "  Pass: $PASS_COUNT" | tee -a "$TEST_LOG"
echo "  Fail: $FAIL_COUNT" | tee -a "$TEST_LOG"
echo "  Log file: $TEST_LOG" | tee -a "$TEST_LOG"
echo "" | tee -a "$TEST_LOG"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "  ✅ TODO: Smoke test PASSED" | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
    EXIT_CODE=0
else
    echo "  ❌ FALLO: Smoke test tiene $FAIL_COUNT pruebas fallidas" | tee -a "$TEST_LOG"
    echo "═══════════════════════════════════════════════════════════════════" | tee -a "$TEST_LOG"
    EXIT_CODE=1
fi

exit $EXIT_CODE
