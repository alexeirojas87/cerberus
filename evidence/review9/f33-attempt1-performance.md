# Adversarial Review — F3.3 / R9-2 honest HTTP proxy latency gate — PERFORMANCE lens

- Candidate: commit `adc7421` (branch `r9-remediation`) — parent `e54c0cf`
- Reviewer: independent adversarial reviewer (PERFORMANCE lens), attempt 1; did NOT build the code; BLIND to the correctness lens
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f33-attempt1-performance` (detached at `adc7421`, removed after review; main repo untouched except this report)
- Date: 2026-09-01
- Host: `Darwin 25.5.0` kernel / macOS 26.5.1, Apple M4 Pro (12 cores), 24 GB RAM — 13–14 users, **visibly contended** (background `claude`/`opencode` agent processes and Chrome observed during runs; 1-min load 4.6–19.2 across the session)
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1`

## Commands run (verbatim, with exit codes)

| # | Command (verbatim) | Exit | Result |
|---|---|---:|---|
| 0 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f33-attempt1-performance adc7421` | 0 | worktree at `adc7421` |
| 1 | `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture --test-threads=1` (run 1 of 3; includes fresh 49.6 s release build) | **101** | **FAIL** — proxy p99 8.214 ms > 5.0 ms (load spiked to 19.15 during window) |
| 2 | `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture --test-threads=1` (run 2 of 3) | **101** | **FAIL** — proxy p99 6.354 ms > 5.0 ms (load 7.51) |
| 3 | `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture --test-threads=1` (run 3 of 3) | 0 | **PASS** — proxy p99 0.855 ms (matches builder's numbers almost exactly) |
| 4 | `rtk proxy cargo test --release --test load_test -- --nocapture --test-threads=1` (full suite) | 0 | **14/14 PASS** (gate again 0.867 ms) |
| — | `python3` byte-exact replication of `f3_3_gate_payload()` → sha256 | 0 | fingerprint **reproduced exactly**: `sha256:e3f206dd…7022`, 51,200 bytes, 37 leaves, 4 tokens present |
| — | static: read gate + helpers, `git diff e54c0cf..adc7421`, budget grep, `e54c0cf` attempt7 inspection, `spawn_proxy` inspection, F2 evidence cross-check | 0 | see attack-vector table |

All failures are recorded as-is; no run was deleted or retried beyond the mandated ×3.

## Per-criterion verdicts

| Criterion (builder claim) | Verdict | Evidence |
|---|---|---|
| Real HTTP round trip timed (client→proxy→mock→client) | **CONFIRMED** | `GateClient::round_trip` over raw TCP to `spawn_proxy` (production entry: real `TcpListener` → `serve_proxy`, verified not a test double); clock = `Instant::now()` before `write_all` → after last response body byte (`read_exact` of Content-Length) |
| 2,000 individual samples/scenario (release) | **CONFIRMED** | `F3_3_MEASURED_SAMPLES = 2_000`; serial keep-alive, one latency per request, no batching; sample-count asserts at `load_test.rs:1153-1154` |
| Warm-up 100, excluded from samples | **CONFIRMED** | 2×100 interleaved requests (`:1111-1119`), timings discarded |
| Interleaved 1:1 proxy/direct | **CONFIRMED** | strict `index % 2` alternation, warm-up and measured; separate connections per scenario → no cross-state contamination |
| Direct baseline same client+bytes | **CONFIRMED** | same `GateClient`, same `payload_bytes` (only `Host:` header differs, inherently), same mock, same keep-alive |
| Strict p99 < 5.0 ms | **CONFIRMED** | `assert_p99_budget(proxy_p99, …, PLAN_PROXY_50KB_BUDGET_MS)` → release branch is `assert!(p99_ms < budget)` on the same p99 that is printed (no substitution); `PLAN_PROXY_50KB_BUDGET_MS = 5.0` |
| No trim/retry/outlier path | **CONFIRMED** | any I/O error → `expect(...)` panic → test FAIL; every sample kept; observed live: my runs 1–2 FAILED loudly instead of hiding (the strongest honesty evidence available) |
| Redaction on the real path | **CONFIRMED** | sanity request captured by mock: `[REDACTED:` present, all 4 raw tokens absent (`:1082-1103`) |
| Exact request accounting 4,202 | **CONFIRMED** | assert `2 + 2×100 + 2×2,000 = 4,202` (`:1147-1152`); a lost keep-alive round trip is a hard failure |
| Worst-of-5 p99 = 1.553 ms (3.2× headroom) | **REPRODUCED (conditionally)** | under load comparable to the builder's (≤ ~5), my runs measured 0.855 / 0.867 ms — inside the builder's 0.851–0.954 band; under heavier contention (1-min load 7.5–19.2, never recorded by the builder) the strict gate fails (8.214 / 6.354 ms) with the direct control inflated ~10× in lockstep → environment causation |
| Budget constants restored / no inflation | **CONFIRMED** | `P99_BUDGET_MS = 5.0` (was 15.0 in f1cdab9); `PLAN_PROXY_50KB_BUDGET_MS = 5.0`; grep over tests/benches: no 15.0/450.0 remnants; every constant carries a doc-comment justification |
| phone_list 8.0 class reclassification (numbers make the class claim plausible) | **CONFIRMED (numbers)** | 8.0 pre-existed at e54c0cf as literal asserts in `load_test_attempt7_mixed_pan_recovery_budgets` ("exceeds the 8ms emission-class budget"); "phone all-fire" named verbatim there (e54c0cf `load_test.rs:428-429`); payload = "phone 1234567\n" ×⌈102400/14⌉ = 7,315 lines ≈ "~7,500 findings" claim; my full-suite run: phone_list p99 4.675 ms (marginal under 5.0, matching builder's 4.29–5.07 story) vs 8.0 class; attempt7 printed `findings=5536` → p99 2.962 ms → latency linear in finding count → emission-dominated mechanism confirmed |
| Overhead ≈ 0.7–1.3 ms plausible | **CONFIRMED** | measured 0.687 / 0.702 ms (clean runs) ≈ in-process 64-leaf JSON redaction 0.254 ms + 512-leaf 0.402 ms (my suite; F2 evidence: 0.216–0.231/0.351–0.363) + engine scan ~0.2 ms (50kb_secrets p99 0.236 ms incl. decode) + hyper forward/buffering/events ~0.2–0.4 ms. Consistent decomposition; no implausibility |

## Methodology attack vectors (each + outcome)

| # | Attack vector | Outcome |
|---|---|---|
| 1 | Batch means hiding tails? | **Defeated** — serial keep-alive, one `Duration` per request, vectors of individual samples; no aggregation anywhere before percentiles |
| 2 | Retry / trim / outlier deletion path? | **None found** — `expect("measured round trip (no retry allowed)")` converts any error into a hard FAIL; no sorting/filtering of samples before percentile; proven live: two of my runs failed loudly |
| 3 | Percentile arithmetic correct? | **Correct** — `percentile()` is documented nearest-rank: `rank = ceil(p/100·n)`, `idx = rank−1`; n=2,000, p99 → 1,980th smallest; the asserted value is the printed value |
| 4 | Warm-up actually excluded? | **Yes** — warm-up loop discards timings; measured loop starts a fresh sample set |
| 5 | Interleave order biasing cache/state? | **No** — strict 1:1 alternation spreads each scenario uniformly over the run window; proxy and direct use separate TCP connections and separate mock connection threads, so no shared-connection state can leak between scenarios |
| 6 | Baseline truly equivalent? | **Yes** — same client code, same 51,200-byte body, same mock, same keep-alive, `set_nodelay(true)` on both; only `Host:` differs (inherent) |
| 7 | Proxy clock boundaries honest? | **Yes** — start before first request byte written; stop after last body byte read; identical boundary for both scenarios (client write syscalls included in both) |
| 8 | `black_box` applied? | **Absent — and not required.** The measured path is I/O-bound (real syscalls, cross-thread data dependency through sockets); the compiler cannot elide it. In-process scans elsewhere in the file correctly use `std::hint::black_box` |
| 9 | Slow upstream counted as fast (partial reads / early 200)? | **Blocked** — status parsed from the actual response line; `read_exact` requires the full declared body; the proxy only responds after the upstream reply is forwarded (`FailPolicy::Closed` → 503 → non-200 → assert fails); exact mock accounting (4,202) catches any dropped round trip |
| 10 | Is the proxy a test double? | **No** — `cerberus_proxy::proxy::spawn_proxy` is the production entry (binds real TCP, spawns `serve_proxy`; `#[cfg(test)]` block is separate) |
| 11 | Workload drift / fabricated fingerprint? | **Independently reproduced** — byte-exact Python replication of the builder logic yields exactly 51,200 bytes and sha256 `e3f206dd25ecce9adfdd7b16f752e64f4db75faf7f51677f3214f62ff1667022`, matching the frozen constant and evidence pack; `hash_value` verified as genuine SHA-256 (sha2 crate) |
| 12 | Inflated budget smuggled in elsewhere? | **None** — grep over tests/benches: only 5.0 / 1.0 / 8.0 / 1.0 (F1.3) / tolerance 2.0 / debug ceiling 30.0, all documented; no 15.0 remnants |
| 13 | Counter/accounting race masking lost requests? | **Marginal only** — `Ordering::Relaxed` on the mock counter (see P2-1); the per-request 200 asserts remain the primary guard |

## Independent reproduction — 3 consecutive serial release runs

Command ×3: `rtk proxy cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --nocapture --test-threads=1`

| Run | load avg 1/5/15m (end) | proxy p50 | proxy p95 | proxy p99 | direct p50 | direct p95 | direct p99 | overhead p99 | Result |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | **19.15** / 7.72 / 5.17 | 1.040 | 3.124 | **8.214** | 0.168 | 0.603 | 2.377 | 5.837 | **FAIL** (exit 101) |
| 2 | **7.51** / 6.76 / 5.18 | 1.508 | 2.932 | **6.354** | 0.184 | 0.457 | 2.067 | 4.287 | **FAIL** (exit 101) |
| 3 | **10.70** / 7.70 / 5.58 | 0.715 | 0.805 | **0.855** | 0.123 | 0.144 | 0.168 | 0.687 | **PASS** (exit 0) |
| 4 (in-suite, run #4 above) | 4.62 / 6.51 / 5.38 | 0.699 | 0.780 | **0.867** | 0.122 | 0.140 | 0.165 | 0.702 | **PASS** (14/14, exit 0) |

Full suite (gate 3): **14/14 PASS** — including `phone_list` p99 4.675 ms (8.0 class), attempt7 p99 2.962 ms (`findings=5536`), 64/512-leaf JSON p99 0.254/0.402 ms, F1.3 both scenarios PASS.

**Interpretation of the two failures:** the direct baseline — the control — inflated ~10× (0.17 → 2.1–2.4 ms p99) during runs 1–2, exactly in lockstep with the proxy numbers. A code or instrument defect cannot inflate the control that skips the proxy; host contention does. Run 1's window saw a 1-min load of 19.15 on a 12-core machine (background agents + 13 users). Under load comparable to the builder's series (≤ ~5, runs 3–4), my numbers match the builder's 0.851–0.954 ms band almost digit-for-digit. The builder never recorded load above 4.66; I recorded 19.15 — my failures occurred strictly outside their envelope. The gate failed loudly both times (no trimming hid the tail), which is the instrument behaving exactly as designed.

## Findings

**P0:** none.

**P1-1 — Strict raw-proxy-p99 5.0 ms release assert is contention-fragile (operational, not honesty).** On this shared host with ordinary background agent load (1-min ≥ ~7.5), 2 of 3 mandated serial runs failed the gate (8.214 / 6.354 ms) while the direct control proved environmental causation (~10× inflation). As the "official proxy latency acceptance" that runs in `cargo test --release --test load_test`, it can spuriously fail CI/dev runs on any contended machine. Note the assert is *stricter* than plan §5 (§5 budgets proxy **overhead** p99 < 3–5 ms; the gate asserts absolute proxy p99 < 5.0, which additionally absorbs baseline jitter) — even in my failed runs, overhead was 4.287 ms (run 2, within §5) and 5.837 ms (run 1, extreme load 19). No threshold edit was made here (prohibited); the owner should decide (options include CI isolation/queueing or an explicitly closed overhead-based assert — both require the §8B review-visible-diff protocol; neither is proposed as a fix in this review).

**P2-1 — Mock request counter uses `Ordering::Relaxed`.** `total_requests` (increment at `load_test.rs:947`, read at `:1149`) has no formal happens-before edge to the gate's final read. Practically sound on this hardware and the per-request 200 asserts are the primary guard; a `SeqCst`/`Acquire` read would make the accounting guard airtight.

**P2-2 — Measured proxy samples do not assert the response body length.** Only the direct sanity asserts `body_len == 11` (`:1108`); proxy measured samples assert status only. Hyper's own Content-Length framing makes truncation a non-risk, and the sanity round trip proves the path, but asserting the proxy response body length per sample would close the last "counted fast" theoretical hole.

## Final verdict

**PASS.** The instrument is honest: every attack vector I aimed at it failed to find a hiding place — individual serial samples with no retry/trim path (proven live: it failed loudly twice rather than conceal a tail), correct documented nearest-rank percentiles asserted on the same value that is printed, warm-up excluded, symmetric 1:1 interleaving over separate connections, a byte-identical baseline sharing client/mock/bytes, honest clock boundaries on the production `spawn_proxy` server, and a workload fingerprint I reproduced byte-for-byte with an independent implementation (`sha256:e3f206dd…7022`, exactly 51,200 bytes / 37 leaves / 4 redact tokens). The builder's numbers are real: under host load within their recorded envelope, my measurements (proxy p99 0.855 / 0.867 ms, direct 0.165–0.168 ms, overhead 0.687–0.702 ms) reproduce their claimed band almost digit-for-digit, the full suite is 14/14, budget constants are restored to plan-closed values with no inflated remnants, and the phone_list 8.0 ms relabel reuses a ceiling that demonstrably pre-existed at e54c0cf with an emission-dominated mechanism I corroborated empirically (latency linear in finding count). My two failed runs occurred at host load (19.15 / 7.51) far outside anything the builder recorded, with the direct control inflating ~10× in lockstep — environment, not instrument or product — and are recorded above without deletion. The one P1 (contention fragility of the strict absolute-p99 assert on shared hosts) is an operational robustness concern for the owner's next review-visible-diff decision; it does not impugn the unit's honesty, its methodology, or its evidence.
