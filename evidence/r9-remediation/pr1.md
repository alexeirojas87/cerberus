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
