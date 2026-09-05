# Independent Review — F2.1 / R9-1 JSON dataplane repair (attempt 1) — CORRECTNESS lens

- Candidate: `e8c1eb5` ("fix(f2): F2.1 R9-1 JSON dataplane — single-parse reconciliation + residual repair"), branch `r9-f2-attempt1`, parent `74e9c9a` (verified: `git log` — direct parent chain e8c1eb5 → 74e9c9a → e619475)
- Prior attempt: none (attempt 1)
- Base: `74e9c9a` (branch `r9-remediation`, per builder pack)
- Builder pack audited: `evidence/f2/r9-json-redaction.md`; R9-1 finding text: `evidence/review9/gauntlet-findings.md`
- Frozen SHA-256 re-verified by reviewer: `decoder.rs` = `295958b0…97afa`, `json_redact.rs` = `539176cb…185f` — **both match the builder pack exactly**
- Blindness: the sibling lens report `evidence/review9/f21-attempt1-security.md` was **NOT read** (list of the directory was seen; contents untouched)
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f21-attempt1-correctness` (detached at e8c1eb5)
- Date: 2026-08-31 (21:30–22:05 UTC)
- Host: `Darwin 25.5.0 arm64` (macOS 26.5.1, M-series) — same host class as the builder; runs kept serial where timing-sensitive
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`

## Commands run (verbatim, with exit codes)

| # | Command | Result / Exit |
|---|---|---|
| 1 | `git -C …/Cerberus worktree add --detach …/f21-attempt1-correctness e8c1eb5` | created; exit 0 |
| 2 | `git diff 74e9c9a..e8c1eb5` | decoder.rs + json_redact.rs + evidence pack only; exit 0 |
| 3 | `shasum -a 256 crates/cerberus-proxy/src/{decoder,json_redact}.rs` | both match frozen hashes; exit 0 |
| 4 | `rtk cargo fmt --all -- --check` | clean; **exit 0** |
| 5 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | "No issues found"; **exit 0** |
| 6 | `rtk cargo test --workspace --all-targets` (run 1) | 1 timing failure: `load_test_attempt6_pan_path_plan_budgets` — `attempt6_nbsp_only_100kb: debug p50 36.935ms exceeds CI pathology ceiling 30ms` (load_test.rs:113); binary exit nonzero (rtk compressed log, exit not captured) |
| 7 | `rtk cargo test -p cerberus-hardening --test load_test load_test_attempt6_pan_path_plan_budgets -- --test-threads=1 --nocapture` | **1 passed**, exit 0 (flake confirmed under contention) |
| 8 | `rtk proxy cargo test --workspace --all-targets` (run 2, quiet host, full log captured) | **666 passed; 0 failed; 0 ignored**; **TEST_EXIT: 0** |
| 9 | `rtk proxy cargo test -p cerberus-proxy` | 139 + 38 + 0 = **177 passed; 0 failed**; exit 0 |
| 10 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19 passed**; exit 0 |
| 11 | A/B probe: `cargo build --release` + `./target/release/f21-ab-probe` (throwaway crate in temp dir, old path vendored verbatim from `git show 74e9c9a:crates/cerberus-proxy/src/json_redact.rs`) | **25/25 PASS NEW-vs-OLD byte-identical; 25/25 fallback-vs-OLD asserted; 21 JSON-path tree-equality assertions; 0 FAIL**; exit 0 |
| 12 | `rtk proxy cargo test --release --test load_test json -- --nocapture --test-threads=1` | **1 passed**; exit 0; 64-leaf p50 0.206 / **p99 0.252 ms**; 512-leaf p50 0.327 / **p99 0.370 ms** (budget 5 ms) |
| 13 | `rtk proxy cargo test --release --test load_test -- --nocapture --test-threads=1` (full release suite) | 12/13; `load_test_attempt7_mixed_pan_recovery_budgets`: `p99 8.085ms exceeds the 8ms emission-class budget` (load_test.rs:466); exit 101 |
| 14 | `rtk proxy cargo test --release --test load_test load_test_attempt7_mixed_pan_recovery_budgets -- --test-threads=1 --nocapture` (re-run, same binary) | **1 passed**; p99 3.173 ms; exit 0 |
| 15 | `rtk cargo test -p cerberus-engine kind_change` / `unicode` | **1 passed** (FrankenPAN control) / **8 passed** (unicode offsets); exit 0 ×2 |
| 16 | Greps (see Attack vectors) + `git diff --check` | all corroborating; exit 0 |

## Per-criterion verdicts

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | `cargo fmt --all -- --check` | **PASS** | exit 0 (#4) |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** | 0 issues (#5) |
| 3 | `cargo test --workspace --all-targets` (debug) | **PASS** | **666/666** on quiet-host re-run (#8) — matches builder's claim exactly (664 baseline + 2 new). Run 1 hit one debug timing flake (#6), same disclosed F1.2 contention class; passes serially (#7) |
| 4 | `cargo test -p cerberus-proxy` (full suite) | **PASS** | **177/177** (#9) — matches builder |
| 5 | `cargo test -p cerberus-packs --test production_pack_pr` | **PASS** | **19/19** (#10) |
| 6 | Byte-identity of redaction outputs (old vs new paths) | **PASS** | 25 adversarial shapes, true A/B against vendored pre-change code: **0 divergences** (#11, details below) |
| 6a | `parsed: None` fallback ≡ pre-change path | **PASS** | Fallback IS the old parse (`from_slice`, same bytes, same parser) — code-identity by inspection + 25/25 asserted A/B incl. Text/BOM/over-deep/invalid-UTF-8 shapes (#11) |
| 6b | No shared-mutable-state leak (clone safety) | **PASS** | `serde_json::Value`/`Bytes` have no interior mutability; `redact_body` takes `&DecodedBody`; probe asserts retained tree byte-equal to fresh parse **after** redaction on all 21 JSON cases; no aliasing possible |
| 6c | Single-parse is real; no third re-parse site | **PASS** | Dataplane parse sites: `decoder.rs:50` (decode; was :45 at parent) and `json_redact.rs:69` (defensive fallback only). Production `redact_body` called at exactly one site, `proxy.rs:602`, receiving the **same** `&body_bytes` that `decode` consumed at `proxy.rs:541`; no mutation between the two lines. `api.rs` `from_slice` sites are control-plane (config/allowlist handlers); `adapters.rs` takes an already-parsed `&Value` and has **0 references** outside its own file (grep `adapters::` / `use crate::adapters` → none) — builder's audit confirmed |
| 7 | Permanent 64/512-leaf JSON gate (release, serial) | **PASS** | 64-leaf **p99 0.252 ms**, 512-leaf **p99 0.370 ms** vs 5 ms budget (#12); within builder's reported band (0.216–0.231 / 0.351–0.363). Gate body (`tests/load_test.rs:474-521`) verified to exercise the exact repaired path (`decode` → `redact_body` with retained tree) |
| 8 | F1.2 corpus fingerprints still pass (FrankenPAN controls, unicode offsets) | **PASS** | `kind_change_splits_only_between_complete_pans` 1/1; `unicode` filter 8/8 (#15); all inside the 666 |
| 9 | Builder numbers reproducible | **PASS** | 666 / 177 / 19 reproduced exactly; JSON-gate p99s reproduced within noise |

## Attack vectors tried

1. **True A/B byte-identity (beyond the builder's test).** Vendored the ENTIRE pre-change `redact_body`/`redact_json`/`redact_value` from `74e9c9a` into a throwaway probe crate (`…/opencode/f21-ab-probe/`, path-deps into the candidate worktree; zero repo edits), plus the parent's `decode()`. Ran 25 shapes through OLD and NEW (`e8c1eb5` crate) and compared bytes (and Err strings): nested objects/arrays; unicode keys/leaves (CJK, emoji, combining, RTL); duplicate keys in both orders (secret-first → overwritten, secret-last → redacted); escape sequences (`\n \t \" \\ \u0001 \ud83d\ude00`, `\u00e9`, `\u4e2d\u6587`); escaped-space inside a matched token; numbers at precision edges (`u64::MAX`, `i64::MIN`, `1.7976931348623157e308`, `5e-324`, `9007199254740993`, 30-digit int, `1e2`, `1.0`, `-0.0`); null/bool leaves; top-level scalars (`"str"`, `42`, `true`, `null`); empty object/array; secret in a KEY name; 120-deep nesting (inside serde's 128 limit); 200-deep (over limit → Text fallback, identical); BOM-prefixed JSON (→ Text fallback, identical); pretty-printed; two secrets in one leaf; block-rule → **identical Err string** (fail-policy input preserved); 50 KB / 512-leaf body; array of strings; invalid UTF-8; plain text. **Result: 25/25 byte-identical, 0 divergences.** Two probe WARNs (google-key survives in `nested_objects_arrays` / `array_of_strings`) were investigated and are rule semantics (`contextKeywords` unsatisfied → no redaction by design), **identical on both paths** — not a divergence and not a regression.
2. **Fallback path proof.** For every shape, hand-built `DecodedBody { parsed: None }` through the NEW crate vs vendored OLD: **25/25 asserted identical** (bytes and Err messages). Production reachability: `DecodedBody` is constructed **only** inside `decode()` (grep across workspace; the only other construction is the builder's own test) — so `parsed: None` with `content_type == Json` is unreachable in production; the fallback is purely defensive, exactly as claimed.
3. **Tree-exactness of the retained parse.** For all 21 JSON-valid shapes: `decoded.parsed` == fresh `serde_json::from_slice(body)` (deep equality), and **still equal after** `redact_body` ran — the clone is a copy, the caller's tree is never mutated. `PartialEq`-derived `DecodedBody` retained.
4. **Aliasing / stale parse.** Traced `proxy.rs:541→602`: same `body_bytes` value; `Bytes` immutable; nothing reassigns `decoded` or `body_bytes` in the window; engine snapshot cloned once per request (no mid-request pack swap). No interior mutability anywhere on the path. A stale-`parsed` hazard would require a body mutation between decode and redact — none exists.
5. **Re-parse-removal audit (builder's core claim).** Parent citations verified: `decoder.rs:45` and `json_redact.rs:55` were indeed the double parse (read both parent files). Grep for `from_slice|serde_json::from_str` across `crates/cerberus-proxy/src`: dataplane hits are only `decoder.rs:50` (kept, single parse) and `json_redact.rs:69` (fallback). `api.rs` parses are control-plane request handlers; `config.rs:147` is config load; `adapters.rs` `from_str` are test-only and the module is unwired (0 external refs). **No third dataplane re-parse site exists.**
6. **Timing-flake forensics (two independent failures, both ruled out as F2.1 regressions).** (a) Debug `attempt6` NBSP p50 36.9 > 30 ceiling — passed on serial re-run and in the clean full suite. (b) Release `attempt7` mixed-PAN p99 8.085 > 8.0 — a 1% overshoot; passed on serial re-run at 3.173 ms on the same binary (variance = host noise). Structurally: `load_test_attempt7` calls **only** `engine.scan()` (`tests/load_test.rs:432-470`) — the F2.1 diff (`decoder.rs`/`json_redact.rs`) is outside its call graph, so the candidate cannot cause it. The JSON gate itself passed in **all three** of my release measurements. Consistent with the contention sensitivity the builder already disclosed for F1.2-class gates.
7. **Format-string / provenance checks.** Frozen hashes match; branch pointer contains e8c1eb5; `git diff --check` clean; serde_json default features (no `preserve_order`/`arbitrary_precision` divergence possible between paths — both share the same crate build).

## Findings

**P0:** none. **P1:** none.

**P2 (observations, non-blocking; no code/test/threshold edits made):**
1. **Implicit API contract on `redact_body`.** The new code trusts `decoded` to correspond to `body`: if a future caller passed a mismatched pair, the new path would silently redact the *retained* tree instead of the *given* bytes (old path parsed the given bytes). Today there is exactly one production call site (`proxy.rs:602`) and it passes the same `&body_bytes`; the fallback covers nothing here. Hardening suggestion only (e.g., debug_assert or doc contract), not required for this unit.
2. **Memory on the JSON redact path.** JSON bodies now retain `text` + parsed tree (and a transient clone during redaction) — roughly 2–3× body bytes held per redacted request. Not observable in any gate (p99 0.252/0.370 ms) and acceptable for MVP; worth remembering if 64 MiB bodies become a real case.
3. **Pre-existing timing-gate sensitivity (not this attempt's regression).** Two unrelated gates flaked once each on this host (debug `attempt6` NBSP 30 ms ceiling; release `attempt7` PAN 8 ms bound by 1%), both outside the F2.1 call graph, both passing on serial re-run. Matches the sensitivity the builder disclosed. No threshold was moved.

## Final verdict: **PASS**

Every gate ran and passed on this host with independently captured exit codes: fmt and clippy clean; workspace suite **666/666** (matching the builder's count exactly), proxy suite **177/177**, production-pack PR **19/19**; the permanent release JSON gate passed at **64-leaf p99 0.252 ms / 512-leaf p99 0.370 ms** (budget 5 ms), measured through the exact repaired `decode → redact_body` path. The builder's core claim — byte-identical redaction outputs — survived a true adversarial A/B: I vendored the pre-change redaction code from `74e9c9a` verbatim and ran 25 hostile shapes (unicode, duplicate keys, escapes and surrogate pairs, precision-edge numbers, over-recursion-depth, BOM, invalid UTF-8, top-level scalars, secrets in key names, block-rule error identity, 50 KB bodies) through both implementations with **zero divergences**, proved the `parsed: None` fallback is byte-equivalent to the old parse on all 25 shapes while being unreachable in production (only `decode()` constructs `DecodedBody`), confirmed the retained tree is never aliased or mutated, and verified by call-graph trace that the double parse (`decoder.rs:45` + `json_redact.rs:55` at base) is really gone with no third dataplane re-parse site. The two timing failures encountered (debug attempt6, release attempt7) are host-contention flakes in engine-scan gates structurally outside the F2.1 call graph — both pass on serial re-run and neither was touched by this diff. No P0/P1 findings; the three P2 observations are hardening notes only.
