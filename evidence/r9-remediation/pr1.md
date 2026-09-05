# PR-1 Evidence Pack — review-findings-remediation (proxy data plane: F1, F6, F7)

Branch `r9-remediation`, work units as local commits. Mode: STRICT TDD (RED → GREEN per unit).
Scope note: the 450-line slice cap triggered the pre-agreed contingency — **F4 (tasks 1.4–1.6: vault
minimal-splice + roundtrip suite + bench) → PR-1b**. This pack covers F1, F6, F7 (tasks 1.1–1.3, 1.7–1.12).

## TDD Cycle Evidence

| Task | RED (test written first, watched fail) | GREEN (impl passes) | REFACTOR |
|---|---|---|---|
| 1.1 decoder suffix matrix | `cargo test -p cerberus-proxy --lib f1_` → 2 FAILED: junk suffix matched `Some(0)`; kinds `[PartHeaders, Payload, Epilogue]` | 2 passed; `--lib multipart` 30 passed (no legit-boundary regression) | none needed |
| 1.2 find_delimiter :392 | same RED run (1.1 fails against unfixed code) | `f1_` 2 ok; full `-p cerberus-proxy` 220 lib + 12 + 73 harness ok | clippy redundant-clone fixed |
| 1.3 smoke e2e junk boundary | `cargo test -p cerberus-proxy --test smoke_harness f1_junk` → FAILED: forwarded binary contained `[REDACTED:test.redact]` spliced into bytes (epilogue misread corruption) | 1 passed (binary byte-exact) | none |
| 1.7 api F6-reject/accept | `cargo test -p cerberus-proxy --lib f6_` → reject FAILED: got `200`, want `400` (brick went through); accept ok (regression guard) | 2 passed; `--lib api` 43 ok | fmt reflow only |
| 1.8 api.rs :861 | same RED run | as above | — |
| 1.9 json_redact F7 | `cargo test -p cerberus-proxy --lib f7_` → both FAILED: cross-region finding dropped (1 vs 2) | 2 passed; lib 224 ok | — |
| 1.10 json_redact :211 | same RED run | as above | — |

## file:line mapping (obs #447 → change)

| Finding (obs #447) | Site | Fix |
|---|---|---|
| F1 delimiter suffix unvalidated → scan bypass | `crates/cerberus-proxy/src/decoder.rs` `find_delimiter` (:392–404 pre-fix) | + `delimiter_suffix_is_valid` (design verdict table); invalid → `None`, scan continues `i+=1`; open-at-EOF rejected fail-safe (over-scan fallback) |
| F1 e2e (epilogue misread) | `crates/cerberus-proxy/tests/smoke_harness.rs` `f1_junk_close_boundary_stays_in_part_payload_no_epilogue_misread` | discriminator: binary part after junk `--FB1--junk` line stays byte-exact |
| F6 reload AND-of-both-empty → upstreams:{} brick | `crates/cerberus-proxy/src/api.rs` `apply_reload` (:861–863 pre-fix) | `candidate.upstreams.is_empty()` independent of live map; 400 + live retained |
| F7 dedup key lacks region index | `crates/cerberus-proxy/src/json_redact.rs` `multipart_scan_output` (:211–218 pre-fix) | 4-tuple `(flag, region_index, start, end)` mirroring `scan_multipart_regions` :178 |

## Gate (task 1.12) — real outputs

```
$ cargo test --workspace        → 38× "test result: ok", 0 FAILED, 0 error (incl. 224 proxy lib,
                                  73 smoke_harness, 94/69/233 engine-store-cli suites)
$ make lint                     → "Finished `dev` profile ... in 6.05s" (clippy nursery -D warnings)
$ cargo fmt --check             → clean (after one fmt/clippy conformance commit d4c3873)
```

Task 1.6 (`make bench`, F4-neutral perf) is deferred with F4 → PR-1b.

## Work units / commits

- `d47cf76` fix(r9-remediation): F1 delimiter suffix validation (tests+impl+e2e)
- `a8c84f5` fix(r9-remediation): F6 reload rejects empty candidate upstreams unconditionally
- `cac07bb` fix(r9-remediation): F7 output-view dedup key carries the region index
- `d4c3873` style(r9-remediation): fmt + clippy conformance
- Rollback boundary: each commit reverts independently (decoder/e2e | api | json_redact | style) without touching unrelated work; proxy.rs call sites untouched.

---

# PR-1b Addendum — F4 minimal-splice (tasks 1.4–1.6, attempt rf-remed-pr1b-attempt1)

Mode: STRICT TDD. Scope: `crates/cerberus-engine/src/vault.rs` only (impl + inline tests);
`proxy.rs:1099-1102` call site verified UNCHANGED (content-length recompute `:1112-1116` consumes the
returned buffer length, so the splice needs no call-site edit). No e2e added to `smoke_harness.rs`:
the `Vault::unredact(&[u8]) -> Vec<u8>` unit boundary is exactly what the proxy calls; the spec
scenarios (F4-roundtrip, F4-neutral) are fully decidable at that boundary — unit coverage chosen to
respect the slice cap.

## TDD Cycle Evidence (Work Unit Evidence)

| Evidence | Required value |
|---|---|
| Focused test command + exact result | `cargo test -p cerberus-engine vault` → RED `32b6cef`: 19 passed; **3 FAILED** (roundtrip / key-parity / mixed — raw splice broke JSON validity); GREEN `d712d8f`: **22 passed; 0 failed** (16 pre-existing + 6 F4) |
| Runtime harness + exact result | `cargo test --workspace` → 38 suites ok / 0 FAILED; `cargo test --release --test load_test -- --nocapture` → **14 passed; 0 failed**, `f3_3_http_round_trip: proxy p99=0.989ms strict budget 5.0ms result=PASS` (boundary note: the F3.3 workload is the enforce-redact path; the reversible splice itself is exercised at the exact `unredact` unit boundary the proxy invokes — proxy.rs:1100) |
| Rollback boundary | Revert `32b6cef`/`d712d8f`/`c87642e` (vault.rs only). Raw path for non-JSON bodies is byte-identical pre/post F4; no other crate touched. |

| Task | RED (watched fail) | GREEN (passes) | REFACTOR |
|---|---|---|---|
| 1.4 vault F4 suite | 3 pinning tests FAILED: `Error("expected , or }", column 20)` (roundtrip), `Error("expected :", column 6)` (key), `Error("expected , or }", column 13)` (mixed) — raw substitution inserted an unescaped `"`/LF into JSON strings; 4 parity guards passed (neutral byte-identity, unknown-token no-burn, non-JSON raw path, consume-once) | all 6 pass | fmt reflow + 2 `doc_markdown` backticks (`c87642e`) |
| 1.5 vault :318-530 splice | same RED run | `unredact` gains the parse gate (`serde_json::from_slice::<Value>`, :329); `unredact_json` :398 (pass 1 locked → pass 2 unlocked splice → pass 3 locked consume); `find_token_spans_in_strings` :453 (escape-aware string-leaf scan, find_token_ids semantics); `json_escape_str` :562. Unknown-token JSON → byte-identical, no burn; parse-fail → raw path verbatim, no burn | clippy/fmt only |
| 1.6 PERF | N/A (perf) | see bench section below | — |

## file:line mapping (obs #447 F4 → change)

| Finding (obs #447) | Site | Fix |
|---|---|---|
| F4 raw `String::replace` over serialized JSON breaks escape-bearing secrets | `crates/cerberus-engine/src/vault.rs` `unredact` (:318 pre-fix raw path) | parse gate → minimal in-place splice of `json_escape(secret)` at token spans inside JSON string leaves; full reserialize rejected (serde_json lacks `preserve_order`); untouched regions byte-identical |
| F4 consume-once preservation | `unredact_json` pass 3 (:398-451) | burn only after output built; parse-fail and unknown-token paths never enter pass 3 |

## PERF (task 1.6) — honest record

- `make bench` (`cargo bench --workspace`) RAN but measures nothing in this workspace: there are no
  `#[bench]`/criterion targets; under the bench harness every `#[test]` is reported ignored
  (`0 passed; 94 ignored`, `0 passed; 239 ignored`, ...). Recorded verbatim — NOT counted as a PASS.
- The repo's documented release gate (`load_test.rs` header: guards run in
  `cargo test --workspace --release`) was executed instead:
  `cargo test --release --test load_test -- --nocapture` → 14 passed / 0 failed. Key numbers:
  - `f3_3_http_round_trip` proxy p50=0.697 p95=0.793 **p99=0.989 ms** < 5.0 ms budget → PASS (direct p99=0.175 ms; overhead_p99=0.815 ms)
  - `50kb_secrets p99=0.266 ms`, `100kb_clean p99=0.197 ms`, `json_many_leaf_50kb p99=0.228/0.378 ms`, F1.3 throughput gates p99=0.197/0.296 ms — all PASS.
- F4-neutral structurally: token-free bodies never pass the TOKEN_PREFIX guard → `body.to_vec()`
  byte-identical (unit-proven); the splice path is opt-in reversible mode only and bounded by
  `max_body_bytes`.

## Gate (PR-1b)

```
$ cargo test --workspace   → 38 suites ok / 0 FAILED (incl. engine lib 239 tests, 22 vault)
$ make lint                → clippy nursery+pedantic -D warnings clean
$ cargo fmt --check        → clean
```

## Work units / commits (PR-1b)

- `32b6cef` test(r9-remediation): F4 RED suite (task 1.4) — 107 insertions
- `d712d8f` fix(r9-remediation): F4 minimal-splice JSON-aware unredaction (task 1.5) — 158 ins / 3 del
- `c87642e` style(r9-remediation): fmt + clippy conformance — 7 ins / 15 del
- Net tree diff vs PR-1 head (`00222e3`): **257 ins + 3 del = 260 changed lines** — 10 lines over the
  250 cap. Honest accounting: the 3-pass mechanism, escape-aware scanner and escape helper are the
  design-mandated mechanism; the 6-test suite covers every task-1.4 scenario; doc comments are
  required by the workspace lint set (`missing_docs = deny`, clippy pedantic/nursery). No comments,
  docs or tests were compressed to reach the cap (budget rule). → `size:exception` recommended for
  the ledger; further splitting would break the cohesive splice work unit.
- Rollback boundary: revert the three commits (vault.rs only); PR-1 commits and proxy.rs untouched.
