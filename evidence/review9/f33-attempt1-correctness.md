# F3.3 (R9-2) — Adversarial Review, Attempt 1 — CORRECTNESS + SECURITY lens

- Candidate: **commit `adc7421`** ("fix(f3): F3.3 R9-2 — honest HTTP proxy latency gate…") on `r9-remediation`
- Parent: **`e54c0cf`** ("gate(f2): F2 phase gate CLOSED…")
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f33-attempt1-correctness` (detached HEAD at `adc7421`, tree clean)
- Date: 2026-09-01
- Host: Darwin 26.5.0, arm64 (Apple M4 Pro class). **Not idle**: 1-min load averages 3.20–3.50 during gate runs (recorded honestly; matches the builder's disclosed background-contention condition).
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`, host `aarch64-apple-darwin`
- Reviewer: independent adversarial reviewer (correctness+security lens), blind to the sibling performance lens. Builder pack: `evidence/f3/r9-honest-latency-gate.md`. Finding text: `evidence/review9/gauntlet-findings.md` §R9-2.

## Commands run (verbatim, with exit codes)

| # | Command (worktree cwd) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach …/f33-attempt1-correctness adc7421` | 0 | worktree created |
| 2 | `rtk cargo fmt --all -- --check` | 0 | clean |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 issues |
| 4 | `rtk cargo test --workspace --all-targets` (debug) | 0 | **681 passed** (25 suites, 50.4 s) — matches builder claim exactly |
| 5 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** |
| 6 | `rtk proxy cargo test --release --test load_test -- --test-threads=1 --nocapture` | 0 | **14/14**; gate: proxy p99 **0.868 ms** / direct p99 0.166 ms / overhead 0.702 ms; `phone_list` p99 **5.091 ms** (see 6a) |
| 7 | `cargo test --release --test load_test load_test_f3_3_honest_http_round_trip_gate -- --test-threads=1 --nocapture` ×2 (stability re-runs) | 0 | 2/2 PASS; proxy p99 0.934 / 0.873 ms (load 3.20–3.50) |
| 8 | `rtk git diff --check e54c0cf..adc7421` (+ raw `git diff --check`) | 0 / 0 | no whitespace errors |
| 9 | `shasum -a 256` on the 4 files frozen in the pack | 0 | **all 4 hashes match** the pack byte-for-byte |
| 10 | standalone fingerprint probe (`cargo run` in `/var/folders/…/opencode/f33-fp-probe/`, outside the repo; serde_json+sha2 only, no repo code) | 0 | **fingerprint MATCH** — see 6c |

Supporting read-only inspection: `git show e54c0cf:tests/load_test.rs`, `git log -S P99_BUDGET_MS -- tests/load_test.rs`, `git show 01d27a8:tests/load_test.rs`, `git show f1cdab9` diff, `CERBERUS_PRODUCT_BUILD_PLAN.md` §5/§9 #2, `crates/cerberus-proxy/src/{decoder,json_redact,proxy,config}.rs`, `crates/cerberus-engine/src/engine.rs` (`hash_value`).

## Per-criterion verdicts

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | `cargo fmt --check` | **PASS** | exit 0 |
| 2 | `clippy -D warnings` | **PASS** | exit 0, 0 issues |
| 3 | `cargo test --workspace --all-targets` (debug) | **PASS** | **681 passed / 0 failed** (builder claimed 681 — exact match; +1 vs parent baseline = exactly the new gate; parent file has 13 `#[test]`, candidate has 14) |
| 4 | `production_pack_pr` | **PASS** | 19/19 |
| 5 | Full load suite, release, serial | **PASS** | 14/14; gate proxy p99 0.868 ms < 5.0 strict (5.7× headroom); gate printed `samples_per_scenario=2000 interleaving=proxy_direct_1to1 warmup=100 payload_bytes=51200 leaves=37` |
| 6a | Threshold governance / `phone_list` reclassification | **PASS — honest reclassification** (explicit verdict below) | see dedicated section |
| 6b | New dependencies | **PASS** | see dedicated section |
| 6c | Gate honesty (banned patterns) | **PASS** (2 P2 notes) | see dedicated section |
| 6d | Failure semantics | **PASS** (1 P2 note) | see dedicated section |
| 6e | Determinism / hygiene / docs-only evidence change | **PASS** | `git diff --check` clean; `evidence/f9/load-test.md` diff = 10-line SUPERSEDED blockquote added after line 3, **zero existing lines modified**; all 4 frozen SHA-256 match |

## 6a — THRESHOLD GOVERNANCE: the `phone_list` reclassification (explicit verdict)

**VERDICT: honest reclassification of an emission-dominated scan-only probe to its documented, pre-existing class ceiling — NOT disguised threshold inflation.** Evidence chain:

1. **No §5 product budget moves.** `PLAN_PROXY_50KB_BUDGET_MS = 5.0` and `PLAN_SCAN_100KB_BUDGET_MS = 1.0` are untouched context lines in the diff. `P99_BUDGET_MS` is **restored** 15.0→5.0 — I traced the full history: original `01d27a8` = **5.0**, interim `90023e7` = 7.0 (undocumented CI bump), `f1cdab9` = 15.0 (the R9-2-flagged inflation). The restore returns to the original closed value and is **stricter than every intermediate state**.
2. **The class ceiling is pre-existing, not invented.** At parent `e54c0cf`, `load_test_attempt7_mixed_pan_recovery_budgets` already asserts `p50 < 8.0` and `p99 < 8.0` with the message "exceeds the 8ms emission-class budget", and its doc comment names the **"phone all-fire"** class *verbatim* as emission-dominated — exactly the `phone_list` shape. The builder extracted that pre-existing inline literal into `EMISSION_CLASS_100KB_BUDGET_MS = 8.0`; the value is unchanged, only labeled.
3. **The reclassified probe genuinely fits no closed §5 criterion.** `load_test_100kb_phone_list` is a 100 KB (not ≤ 50 KB) in-process `engine.scan()` probe where every line fires `pii.phone_number` (~7,500 findings/scan). §5's two closed criteria are proxy overhead p99 < 3–5 ms for ≤ 50 KB prompts (§9 #2) and **clean** ~100 KB scan < 1 ms. Neither speaks to a 100 KB all-fire emission workload; the probe was previously mislabeled under the generic file-wide constant.
4. **The marginality claim is empirically reproducible, not narrative.** In my own independent release run (gate 5, command #6), `phone_list` measured p99 = **5.091 ms — above the restored 5.0**. Had the builder kept the mislabel, my run would have been 13/14. The two honest options were relabeling to the documented class or shipping a flaky gate; the banned option (raising `P99_BUDGET_MS`) was not taken.
5. **Direction and completeness.** The probe's effective budget went 15.0 → 8.0 (a *strictening* of the current state). A grep of the final file shows no remaining inflated budget: the constants in force are 5.0 (×2), 1.0 (×2), 8.0 (pre-existing class), plus the pre-existing documented `PLAN_CI_TOLERANCE = 2.0` (attempt 6, release-CI bound only) and debug-only 30× pathology ceiling — all pre-existing and review-visible. The six sibling tests that keep `P99_BUDGET_MS` (1kb/10kb/50kb/100kb clean, decode_and_scan, scan_and_redact) now enforce the restored strict 5.0 and **passed in my release run**.
6. **One honest nuance, recorded:** relative to the pre-`f1cdab9` file-wide value (7.0), 8.0 is nominally 1 ms looser for this one probe. But 7.0 was itself an undocumented CI bump of a generic file-wide constant, never a closed criterion for this shape, while 8.0 is the class budget closed in committed code with the class documented. The closed product budgets are untouched and now enforced at their original values. This does not change the verdict.

## 6b — New dependencies

- Root `Cargo.toml` +3 lines: `tokio = { version = "1", features = ["full"] }` under **`[dev-dependencies]`** of the root package `cerberus-hardening`, whose `[lib]` is `src/lib_stub.rs` (no runtime code). The three workspace crates are untouched. Justified: the gate drives the real async server (`cerberus_proxy::proxy::spawn_proxy`) on a multi-thread runtime — `spawn_proxy` at `proxy.rs:214` is the genuine shipped listener/serve stack.
- `Cargo.lock` +1 line: exactly the dependency edge `"tokio"` added to the root package's dep list. tokio **1.53.1 already existed** in the lockfile (cerberus-proxy dependency) — no new package entry, no version change, no surprise upgrades anywhere in the diff.
- Scope: build/test-only. It does not enter any runtime dependency graph (verified: no `[dependencies]` change; workspace members' manifests untouched).

## 6c — Gate honesty (banned-pattern hunt over `load_test_f3_3_honest_http_round_trip_gate` and helpers)

| Banned pattern | Found? | Evidence |
|---|---|---|
| Trimming / retry / outlier deletion | **NO** | every sample kept; `round_trip` errors go through `expect("measured round trip (no retry allowed)")`; no retry path exists |
| Percentile substitution | **NO** | the asserted p99 is the same p99 printed; `overhead_p99` is reported only, never asserted or substituted for the budget |
| Non-200 tolerance | **NO** | `assert_eq!(status, 200)` on sanity, warm-up, and every measured sample |
| Warm-up abuse | **NO** | 100/scenario, declared, unmeasured, on the *same* keep-alive connections later measured |
| Batch means | **NO** | one request in flight, one `Instant` per `round_trip`, one `Duration` per sample |
| Missing sample-count assertions | **NO** | `assert_eq!(proxy_timings.len(), samples)` + `assert_eq!(direct_timings.len(), samples)` |
| Non-strict budgets | **NO** | `assert_p99_budget` release branch: `assert!(p99_ms < budget)` — strict `<` against 5.0 |
| Missing fingerprint assertion | **NO — and independently verified** | my out-of-repo replication of `f3_3_gate_payload` (no repo code; serde_json+sha2 only) produced body_len=51200, 37 leaves, top-level JSON array, all 4 raw tokens present, and **exactly** `sha256:e3f206dd25ecce9adfdd7b16f752e64f4db75faf7f51677f3214f62ff1667022` — the fingerprint assert is genuine and load-bearing, not self-consistent theater |
| Request accounting | **VERIFIED** | release expected = 2 sanity + 2×100 warm-up + 2×2,000 = **4,202** mock requests, exact equality (extra upstream requests would also fail — the mock counts every body fully read); debug variant 602 |
| Redaction sanity on real path | **VERIFIED** | capture-once mock body must parse utf8, contain `[REDACTED:`, and contain none of the 4 raw tokens |
| Payload-content logging | **NONE** | output = percentiles, sizes, counts, fingerprint (a hash) only |
| Wrong code path (my own attack) | **DISPROVED** | the payload is a top-level JSON *array* of 37 strings; I verified `decoder::decode` classifies it `ContentType::Json` with `parsed: Some(...)`, and `redact_body → redact_json → redact_value` recurses `Value::Array` and scans **each string leaf** with `scan_with_context_analyzer` — the gate measures the real R9-1 per-leaf JSON path, and the sanity capture proves redaction fired on it |

P2 notes (non-blocking): (i) the proxy-leg **response body** is never verified — the sanity proxy round trip discards body length and measured samples discard it; (ii) `GateClient` has no read timeout — a hung proxy hangs the gate (fails closed via external CI timeout; can never false-PASS).

## 6d — Failure semantics (can the gate pass on a broken proxy?)

Attacked scenarios; each is caught unless noted:

- **Proxy skips scan/redaction (pass-through)**: sanity capture asserts `[REDACTED:` present and no raw token at the upstream → **FAIL**.
- **Proxy returns 200 without forwarding**: mock count falls short of 4,202 → exact accounting → **FAIL**.
- **Proxy errors / upstream 500 / fail-closed non-200**: relayed status fails the per-request `assert_eq!(status, 200)` → **FAIL**. Connection errors and truncated bodies under declared Content-Length hit `expect`/`read_exact` EOF → **FAIL** (no swallow, no retry).
- **Proxy internally retries**: mock over-counts vs 4,202 → **FAIL** (accounting is exact, both directions).
- **Response-body corruption with self-consistent 200 framing**: **NOT caught** — the one reasoned false-PASS requires the proxy to forward the request correctly (redaction + accounting + status all pass) while mangling/truncating the relayed response. This is a response-relay correctness defect outside the gate's stated scope (request-path latency budget) and covered by the existing proxy integration suite → recorded as P2-1, not a gate-invalidating finding.
- **Empty/missing Content-Length responses**: hard error ("response without content-length") → **FAIL**.
- **Debug profile**: all correctness guards (exact size, fingerprint, redaction proof, accounting, per-request 200) run in debug with 200 samples; timing is log-only + 30× pathology ceiling — the disclosed file-wide convention, not a new softening.

## Findings

- **P0:** none.
- **P1:** none.
- **P2-1:** F3.3 gate never asserts the proxy-leg response body (sanity discards it; measured samples discard it). A proxy that forwards correctly but corrupts response bodies with self-consistent framing would pass. Cheap hardening: assert `response_body_len == 11` on the sanity proxy round trip (optionally per-sample). No evidence of such a defect; the existing proxy integration suite covers response relay.
- **P2-2:** No read timeout on `GateClient` — a hung proxy hangs the gate indefinitely instead of failing fast. Cannot produce a false PASS; operational nit for CI.

## Final verdict

**PASS.** All five mechanical gates reproduce on an independent machine with the builder's exact claimed numbers (681 debug / 19/19 / 14/14; fmt, clippy, `git diff --check` clean; all four frozen SHA-256 hashes match byte-for-byte). The new gate measures the real shipped path — verified down to the decoder/redactor code to confirm a top-level JSON array exercises the per-leaf `scan_with_context_analyzer` path — with individual serial keep-alive samples, 1:1 interleaved direct baseline, warm-up, exact 4,202-request accounting, strict release `p99 < 5.0 ms` (measured 0.868–0.934 ms across 3 independent runs under visibly loaded host conditions), a workload fingerprint I independently reproduced out-of-repo, and no banned methodology pattern found. The only reasoned false-PASS scenario (response-body corruption) is out of the gate's stated scope, recorded as P2-1 with a one-line suggested hardening; it does not undermine the unit's purpose. The 15.0→5.0 restore is complete and returns to the original closed value; no §5 product budget moved in either direction.

**On the `phone_list` reclassification (the decisive judgment call):** honest, not disguised threshold inflation. The 8.0 ms ceiling pre-exists at the parent in closed, documented code that names the "phone all-fire" class verbatim; the probe (100 KB, ~7,500 findings/scan, scan-only, emission-dominated) fits neither closed §5 criterion; no product budget moved; the effective budget for the probe *strictened* (15.0→8.0) while the product constants returned to their original values; and my own run reproduced the marginality (p99 5.091 ms > 5.0) that made the old mislabel a flaky gate. The full reasoning is review-visible in the test's doc comment and the Evidence Pack. This is precisely the "label the microbench as what it is" outcome fix-plan F3.3 asked for.

Reviewer note: I did not read the sibling performance-lens report; this verdict is fully independent.
