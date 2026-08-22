# Evidence Pack — r0/smoke-test (R2 FINAL)

- **Attempt: 5** (R1 → build fix + retry → R2 full integration + test suite fix → final)
- **Builder:** R2 build agent
- **Reviewer:** Automated smoke test (11 assertions)
- **Verdict: PASS ✅** (11/11, idempotent across 2 clean runs)

## R2 summary (SQLite Store Patching)

### Problems detected
1. **`AuditStore` was not `Send + Sync`**: rusqlite's `Connection` uses `RefCell` internally → not thread-safe → `tokio::spawn` failed in the proxy handler.
2. **Daemon died on startup**: `handle.await` blocked `start()` → `main()` never returned → the tokio runtime was destroyed → the proxy died.
3. **Duplicate `cerberus-store` dependency** in the workspace Cargo.toml.

### Fix #1: Channel-based `AuditStore` (Send + Sync)
Complete rewrite of `crates/cerberus-store/src/store.rs`:
- `AuditStore` is now a *wrapper* of MPSC channels + `Arc<JoinHandle>` — naturally Send+Sync.
- An independent writer task (spawned in `open()`) has exclusive access to the SQLite connection.
- The external API uses `mpsc::Sender<WrapperMsg>` (write) and `mpsc::Sender<QueryMsg>` (read queries via oneshot).
- Written: `write_event_async()`, `recent_events()`, `event_count()` (all async via channel).

### Fix #2: Daemon lifecycle (no more `handle.await` hang)
- `start()` now uses `loop { tokio::time::sleep(...) }.await` — keeps the process alive indefinitely.
- `stop()` kills the process via the PID file → terminates proxy and daemon.
- Added the missing `config_file()` function.
- Removed `unreachable!()` in the store error handle → now uses `unwrap_or_else` + the Option pattern.

### Fix #3: `crberus-store` wiring in `api.rs`
- `record_event()` now writes to the SQLite store via `store.write_event_async(event).await`.
- `ApiContext::with_store_opt()` constructor to accept `Option<Arc<AuditStore>>`.
- Events persisted to `~/.cerberus/cerberus.db` from the first request.

## Smoke test evolution

| Phase | P0-1 (.env UPPERCASE) | P0-4/P0-5 (pass-through) | P0-6 (events) | SQLite DB | Zero leak | Total |
|------|------------------------|--------------------------|---------------|-----------|-----------|-------|
| Pre-R0 | ❌ FAIL | ❌ FAIL | ❌ FAIL | ❌ | ✅ PASS | 1/6 |
| Post-R1 | ✅ PASS | ❌ FAIL | ❌ FAIL | ❌ | ✅ PASS | 2/6 |
| Post-R2 | ✅ PASS | ✅ PASS | ✅ PASS | ✅ | ✅ PASS | 6/6 |

## Acceptance criteria (R2 FINAL)

| Criterion | Status |
|----------|--------|
| Workspace build `cargo build --release --workspace` | ✅ Clean |
| Binary exists `./target/release/cerberus` | ✅ |
| `cerberus init` creates config dir `~/.cerberus` | ✅ |
| Health endpoint `curl /health` → 200 OK | ✅ |
| Mock upstream ready | ✅ |
| P0-1: SECRET DETECTED (env_block + openai_api_key) | ✅ |
| P0-4/P0-5: CLEAN REQUEST forwarded HTTP 200 | ✅ |
| Mock upstream received the clean body (echo) | ✅ |
| P0-6: /api/events NOT empty (2 events) | ✅ |
| P0-6: /api/stats with `by_provider` grouping | ✅ total: 2 |
| SQLite DB exists at `~/.cerberus/cerberus.db` | ✅ |
| No raw secret leaked in HOME/logs/DB | ✅ |
| **Total** | **11 PASS / 0 FAIL** |

## Transcript — Final R2 run (Attempt 4)

```
  Pass: 11
  Fail: 0
```

### Step by step

**STEP 0: Build** → cargo build release OK

**STEP 1: Clean HOME** → tmp HOME created, no prior config

**STEP 2: cerberus init** → config dir `~/.cerberus` created, 13 rules loaded

**STEP 3: Start proxy daemon** → health check `{"status":"ok",...}` OK on 127.0.0.1:18787

**STEP 4: Start mock upstream** → mock server listening on an ephemeral port

**STEP 5: P0-1 SECRET** → `{"error":"blocked","flag":"secret.openai_api_key"}` — PASS

**STEP 6: P0-4/P0-5 PASS-THROUGH** → HTTP 200, mock received clean body `{"mock":true,"echo":...}`

**STEP 7: P0-6 EVENTS** → 
- `/api/events` → 2 events (1 blocked, 1 warn) with correct flags, counts, hashes, severity
- `/api/stats` → `{"total":2,"by_provider":[{"provider":"openai","total":1,...},{"provider":"local","total":1,...}],...}`
- SQLite database exists at `~/.cerberus/cerberus.db` → ✅

**STEP 8: ZERO LEAK** → grep found no raw secret in HOME, proxy logs, or mock logs

## Transcript — Verification run (Attempt 5, idempotency)

```
  Pass: 11
  Fail: 0
```
Identical result to the previous run — **idempotency confirmed**.

## Detailed R2 changes

### `crates/cerberus-store/src/store.rs` — total rewrite (180+ lines)
- `AuditStore` is now `Send + Sync` via a channel architecture
- Writer task with exclusive SQLite connection
- Query channel for reads (recent_events, event_count)
- `write_event_async()`, `recent_events()`, `event_count()` — async public API

### `crates/cerberus-proxy/src/api.rs` — record_event → SQLite
- `record_event()` now calls `store.write_event_async(event).await`
- `with_store_opt()` new constructor for `Option<Arc<AuditStore>>`

### `crates/cerberus/src/daemon.rs` — lifecycle fix
- `config_file()` function added
- `loop { sleep }.await` replaces `handle.await` (which hung forever)
- Store created with `unwrap_or_else` + Option, not `unreachable!()`

### `crates/cerberus/Cargo.toml` — duplicate fix
- Removed the duplicate line `cerberus-store = { path = "../cerberus-store" }`

## R2 lessons learned

> 1. **Auto-traits (Send, Sync) can't be `impl`'d manually**: rusqlite's `Connection`
>    uses `RefCell` internally → not Sync → `AuditStore` wasn't Send+Sync → `Arc`
>    wasn't Send. Solution: restructure the architecture so the writer task has
>    exclusive access to SQLite, and the public struct only holds MPSC + JoinHandle
>    (naturally Send + Sync).

> 2. **`handle.await` in `main()` blocks forever**: if the spawned task has an
>    infinite loop, the `JoinHandle` never completes → `start()` never returns →
>    `main()` never returns → the tokio runtime is destroyed → the spawned task
>    DIES. Solution: `start()` keeps the process alive via `loop { sleep }.await`.

> 3. **`tokio::spawn` requires `Send + 'static`**: any closure that captures
>    `Arc<T>` where `T: !Send` → compilation error.

## Archive

- R2 run logs: `evidence/r0/smoke-test/smoke-run-20260817-173423.log`, `smoke-run-20260817-173440.log`
- Pack: `evidence/r0/r0-smoke-test.md`

## R0 status

**R0 CLOSED — ✅ ALL FAILURES FIXED**

- P0-1 (case-insensitive): ✅ FIXED in R1
- P0-4/P0-5 (pass-through): ✅ FIXED in R2 (routing + lifecycle)
- P0-6 (event persistence): ✅ FIXED in R2 (SQLite store wiring)
- Zero leak: ✅ ALWAYS PASS
- Smoke test: 11/11 PASS, idempotent, 0 orphans
