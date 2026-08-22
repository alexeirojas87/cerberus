# Evidence Pack — f0/spike-proxy (REVIEWER 1 · correctness)
- Attempt: 1    Reviewer: Revisor-1-correctness (independent, adversarial, fresh context)    Verdict: **PASS (with 1 bug reported)**
- Date: 2026-08-16    Worktree: `cerberus-wt-f0-proxy-review-correctness` (detached HEAD `8db7d31`)
- Mission: break the unit. All verifications were run from scratch, without trusting the builder's evidence.

## Acceptance criteria

| Criterion | Command executed | Output (quoted/attached) | Result |
|----------|-------------------|-------------------------|-----------|
| Build workspace 0 errors | `cargo build --workspace` | `Finished dev profile ... 111 crates compiled` | ✅ |
| Tests spike-proxy: 7 pass (3 unit + 4 integration) | `cargo test -p spike-proxy` | `3 passed; 0 failed` (lib) + `4 passed; 0 failed` (tests/integration.rs) = **7 passed; 0 failed** | ✅ |
| Clippy 0 errors (`-D warnings`) | `cargo clippy -p spike-proxy --all-targets -- -D warnings` | `Finished dev ... no warnings emitted` | ✅ |
| fmt 0 diffs | `cargo fmt --check` | no output (0 diffs) | ✅ |
| E2E: POST forward → 200 + upstream body | `curl -i -X POST http://127.0.0.1:18090/v1/chat/completions -d '{"prompt":"hello"}'` | `HTTP/1.1 200 OK`, body `{"body_len":18,"method":"POST","ok":true,"path":"/v1/chat/completions",...}` with `x-upstream: spike-upstream` | ✅ |
| E2E: status propagation | `curl -o /dev/null -w "%{http_code}" http://127.0.0.1:18090/notfound` | `200` (synthetic upstream responds 200 to everything; status propagates 1:1) | ✅ |
| E2E: body integrity (5000 B) | `curl -X POST http://127.0.0.1:18090/test -d "$(python3 -c "print('x'*5000)")"` → `json.body_len` | `5000` (exact) | ✅ |
| E2E: query string + headers + GET | curl to `/v1/chat?model=...`, header `x-test-header`, GET `/health` | path/method/header/body_len correct | ✅ |
| Bench JSON schema | `--bench --payload-kb 1 --iterations 50` → assert keys | `schema OK`; overhead `{'p50_ms':0.0986,'p99_ms':0.0}` | ✅ |
| Edge case `--payload-kb 0` | `--bench --payload-kb 0 --iterations 20` | valid JSON, direct/proxy measured | ✅ |
| Edge case `--iterations 1` | `--bench --payload-kb 1 --iterations 1` | valid JSON, overhead `{'p50_ms':0.125,'p99_ms':0.125}` | ✅ |

## Adversarial cases tested (attempt to break)

- **Upstream down** → `curl` against the proxy with the upstream dead: **does NOT return HTTP**, the connection closes with `Empty reply from server` (code `000`), and the proxy log shows `proxy connection error: error from user's Service`. A correct proxy should respond `502 Bad Gateway`. **→ BUG (see below)**.
- `/notfound` → `200` (expected: the synthetic upstream always responds 200; status propagation is faithful, there are no "not found" routes in the upstream).
- Body 5000 B (`x`*5000 and `y`*5000) → exact `body_len` = 5000 in both. No truncation or corruption.
- Query string `?model=gpt-4o&stream=true` → forwarded (correct path in upstream).
- Custom header `x-test-header` → reaches the upstream (`test_header = cerberus-spike`).
- GET without body → `GET /health 0`, no panic.
- `--payload-kb abc` (non-numeric) → does NOT fail with error: **silently runs the 4 default sizes** (parse error ignored). Fragile UX, does not break functionality.
- `--iterations abc` → silently falls back to default 1000 (same pattern).
- Default bench without `--payload-kb` → array of 4 objects [1,10,50,100] KB, all keys present.

## Applicable NFRs
- Latency: not the focus of this reviewer (covered by the performance panel). Observation: in the 1 KB x50 run the overhead p99 came out `0.0` because the overhead `max(0.0)` clamp trims negative differences from jitter; p50 = ~0.1 ms (well below budget).
- Security: out of scope for the correctness reviewer.

## If FAIL: what fails and how to reproduce it
Not applicable: the unit passes all explicit criteria. Bug reported for FIX (see below).

## BUG REPORTED (non-blocking for the task criteria, but real)
**Proxy without 502 on upstream down.** `proxy_handler` (`crates/spike-proxy/src/proxy.rs:155-157`) propagates the `client.request(...)` error as `Err(String)`; hyper converts it into a connection close without an HTTP response, instead of a `502 Bad Gateway`.

Reproduction:
```bash
# 1) start upstream + proxy (see §E2E)
# 2) kill the upstream
pkill -f "spike-proxy --upstream"
curl -sv -X POST http://127.0.0.1:18090/v1/chat/completions -d '{"prompt":"hello"}'
# → * Empty reply from server  (code 000)
```
Impact: the client receives a connection failure instead of an actionable HTTP status; relevant to the expected behavior of a real proxy (F3 reverse-proxy-core). In the F0 spike the stack/overhead decision is not affected.
