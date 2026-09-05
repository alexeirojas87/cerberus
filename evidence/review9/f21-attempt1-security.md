# Independent Adversarial Review — F2.1 (R9-1 JSON dataplane repair), attempt 1 — SECURITY lens

- Candidate: commit `e8c1eb5` on branch `r9-f2-attempt1` ("fix(f2): F2.1 R9-1 JSON dataplane — single-parse reconciliation + residual repair")
- Prior evidence: `evidence/f2/r9-json-redaction.md` (builder pack, attempt 1, returns-to-VERIFY)
- Base: `74e9c9a` (parent of candidate; pre-fix state measured in the builder pack)
- Reviewer: independent security-lens subagent (did NOT build the code; blind to the correctness lens report)
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f21-attempt1-security` (detached HEAD at `e8c1eb5`, clean tree; main repo untouched except this report file)
- Date: 2026-08-31 (17:20–17:50 local)
- Host: `Darwin Alexei-MacBook-Pro.local 25.5.0 arm64` (Apple M-series, 12 logical CPUs; **shared host — 35 users, load avg 17.94→7.15 during the session**)
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)` (matches builder toolchain)

## Commands run (verbatim, with exit codes)

| # | Command | Result / Exit |
|---|---|---|
| 0 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/.../f21-attempt1-security e8c1eb5` | created, EXIT=0 |
| 1 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | `No issues found`, EXIT=0 |
| 2 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | **11 passed; 0 failed**, EXIT=0 (11/11, serial) |
| 2b | `rtk proxy cargo test --release --test redos_fuzz -- --test-threads=1` (name capture) | 11 `ok` lines listed individually, EXIT=0 |
| 3 | `rtk cargo test -p cerberus-proxy` | **177 passed** (3 suites), EXIT=0 |
| 3b | `rtk cargo test -p cerberus-proxy json_redact` | **7 passed**, 170 filtered out, EXIT=0 (7/7) |
| 4 | `rtk cargo test -p cerberus-engine` | **237 passed** (4 suites), EXIT=0 |
| 5 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | **19 passed** (19/19), EXIT=0 |
| 6 | `rtk cargo run` (reviewer-built adversarial harness, throwaway crate in temp; drives the production dataplane `decode()`→`redact_body()` from outside the workspace) | first attempt EXIT=101 = compile error **in the reviewer's own harness** (RTL codepoints in a Rust literal, `text_direction_codepoint_in_literal`); fixed in harness; re-run: **ALL ATTACK SCENARIOS PASSED (0 failures)**, EXIT=0 |
| 7a | `rtk cargo test --release --test load_test -- --test-threads=1 --nocapture` (run 1; load avg 17.94) | `test result: FAILED. 12 passed; 1 failed` — failing test **`load_test_100kb_phone_list`** p99=89.479 ms vs 15 ms (NOT an F2.1 gate); **the F2.1 JSON gate passed**: `load_test_json_many_leaf_50kb` 64-leaf p50=0.208 / p99=0.240 ms, 512-leaf p50=0.328 / p99=0.353 ms |
| 7b | same command (run 2 — protocol-mandated serial re-run; load avg 11.61) | rtk summary: **13 passed (1 suite, 5.92 s)**, EXIT=0 |
| 7c | same command unpiped (run 3 — exit-code capture; load avg 7.15) | **13 passed (1 suite, 5.73 s)**, EXIT=0 |
| 7d | `rtk proxy cargo test --release --test load_test load_test_json_many_leaf_context_reuse -- --test-threads=1 --nocapture` (per-number evidence capture; load avg 9.84) | `1 passed; 0 failed`, EXIT=0 — **64-leaf p50=0.209 / p99=0.224 ms; 512-leaf p50=0.322 / p99=0.354 ms** |

Recording note: commands 7a/7b were piped through `tail`, which masked cargo's process exit code; their pass/fail state is taken from the captured test output (`test result: FAILED. 12 passed; 1 failed` / rtk summary `13 passed`). Runs 7c/7d were captured unpiped with clean exit codes. The single 7a failure is analyzed under "Findings" (contention flake, non-F2.1 gate, passed on both subsequent runs).

## Per-criterion verdicts

| # | Criterion | Evidence | Verdict |
|---|---|---|---|
| G1 | Clippy `-D warnings` clean on workspace, all targets | #1: 0 issues | **PASS** |
| G2 | ReDoS fuzz 11/11, release, serial | #2/#2b: 11/11 (incl. `keyword_dense_phone_list_linear`, `multibyte_entropy_window_straddle`, `malformed_pem_multiline`) | **PASS** |
| G3 | cerberus-proxy full suite 177 + `json_redact` filter 7/7 | #3/#3b: 177 passed; 7/7 (5 pre-existing + 2 new F2.1 tests) | **PASS** |
| G4 | cerberus-engine 237 | #4: 237 passed | **PASS** |
| G5 | packs `production_pack_pr` 19/19 | #5: 19 passed | **PASS** |
| G6a | REDACTION BYPASS: no leaf redactable on the old path passes unredacted on the retained-parse path | 20-scenario adversarial harness (#6): reuse-path output **byte-identical** to fallback-path output on every scenario, and the fallback arm is **verbatim** the base `redact_json` prologue (verified by `git show 74e9c9a:...json_redact.rs` — only the `parsed: Some(v) => v.clone()` arm was added); secret-absence asserted in every scenario, incl. the review-2 P0 shape (context keyword in another field) | **PASS** |
| G6b | Parsed-tree staleness vs body bytes | Static: `DecodedBody` is constructed **only** inside `decode()` (production); `body_bytes` is built once (`proxy.rs:484`), immutable (`Bytes`), and passed by reference to both `decode` (`:541`) and `redact_body` (`:604`) with no mutation in between; nothing mutates `decoded`. Worst case (hand-forged mismatch, production-unreachable) proven non-leaking: output is the redacted decoded tree; foreign body bytes are never forwarded (harness `mismatch_simulation`) | **PASS** |
| G6c | Duplicate-key parity (serde keeps last) | Harness `duplicate_keys_secret_first/_last`: byte-identical between paths; both parse with the same parser on the same bytes | **PASS** |
| G6d | Numbers/escapes normalization parse-once vs parse-twice | Harness `numeric_edges` (1e999, u64::MAX, i64::MIN−1, 1.0, −0.0, 0.30000000000000004, 1e-400) and `escape_obscured_secret` (`A\u0049za…`): byte-identical; serde_json 1.0.151, no `preserve_order`/`arbitrary_precision` in the lockfile | **PASS** |
| G6e | PANIC/DoS surface: malformed fallback, deep nesting, huge bodies, adversarial unicode | Harness: malformed bytes on fallback branch → `Ok(None)` → text fallback, no panic; 130-deep (over serde recursion limit) degrades to Text and still redacts the secret via the text path; 120-deep valid redacts (clone/walk/Drop recursion bounded by serde's 128-depth parse limit); 5 MB / 6000-leaf body byte-identical with all secrets removed; lone surrogates, RTL overrides, combining marks, ZWSP, CJK all identical; non-UTF8, empty, BOM bodies all safe | **PASS** |
| G6f | No new `unwrap`/`expect` reachable from the request path | Full read of both changed files: production code of `decoder.rs`/`json_redact.rs` contains zero `unwrap`/`expect`/`panic!` (all in `#[cfg(test)]`); error propagation via `Result` unchanged (`decide_redact_result` semantics intact, `proxy.rs:424-440`) | **PASS** |
| G6g | Scan semantics unchanged: analyzer text and leaf text cannot diverge between paths | `body_text = String::from_utf8_lossy(body)` is computed **once, after** the parsed/fallback branch, from the same raw bytes in both paths (`json_redact.rs:75`); leaf text comes from the Value tree (identical between paths per G6a-d). Behaviorally proven: `context_other_field_redacts`, `no_context_parity`, `escaped_context_keyword_parity` all byte-identical | **PASS** |
| G6h | No secret-material logging in the new path | Zero log/print/Debug statements in the production code of both changed files; no `{:?}`/Debug use of `DecodedBody` anywhere in `proxy.rs` (grep-verified); `RedactError::Blocked` Display carries only the rule flag, never the secret (checked `redact.rs:41`); harness confirms error strings are secret-free | **PASS** |
| G7 | Permanent JSON gate: 64/512-leaf, release, serial, budget 5 ms | 64-leaf p99 = 0.240 / 0.224 ms; 512-leaf p99 = 0.353 / 0.354 ms (two runs) — **~20× under budget**, consistent with builder (0.216–0.231 / 0.351–0.363). Host was NOT quiet (load 17.94→7.15, 35 users); the only timing failure in the suite was a non-F2.1 gate flake (see findings), and the F2.1 gate passed in every run including the contended one | **PASS** |

## Attack vectors tried (throwaway harness `f21-sec-attack`, drives the exact production dataplane)

1. **Reuse-vs-fallback byte-identity** on: duplicate keys (secret first / secret last); escape-obscured secret (`A\u0049za…`); lone-surrogate leaf (`\uD800`) + paired surrogate emoji; adversarial unicode (RTL override/pop, combining marks, ZWSP, CJK); numeric edge shapes; 130-deep nesting (over serde limit); 120-deep valid (secret at deepest leaf); 5 MB / 6000-leaf body with ~1500 planted secrets; empty body; non-UTF8 body; BOM-prefixed JSON; whitespace-padded JSON; empty/null/bool/array/object leaves. **All byte-identical; all planted secrets absent from outputs.**
2. **Bypass probes**: context keyword in another field (review-2 P0 shape) → redacted on the reuse path; negative control (key with no context) → identical non-redaction on both paths (constraint semantics preserved, no over-redaction introduced).
3. **Staleness/failure-mode probes**: forged `parsed`≠body mismatch (production-unreachable) → output is the redacted decoded tree, foreign secret bytes never forwarded; hand-built `Json`+`parsed:None` over malformed bytes → `Ok(None)` → text fallback, no panic (defensive branch behaves as documented).
4. **Error-channel probe**: block-rule leaf → `Err` propagates identically on both paths, error text contains no secret material.
5. **Static blast-radius review**: full read of the diff and both files; `git show 74e9c9a` comparison proving the fallback arm and all downstream logic (`body_text`, analyzer, `redact_value`, `to_vec`, `decide_redact_result`) are verbatim-unchanged; grep for call sites, hand-built `DecodedBody`, `unwrap/expect/log/Debug` in the request path.

## Findings

**P0: none. P1: none.**

- **P2 (resource, introduced by this change, bounded): transient memory amplification on the retained-parse path.** During `redact_json`, a request now simultaneously holds body + `decoded.parsed` tree + the clone. At the 64 MiB `max_body_bytes` cap a `serde_json::Value` tree typically costs several × body bytes, so worst-case transient memory during redact roughly doubles vs the pre-change redact phase (order of +10¹–10² MB per max-size JSON request, scaling with in-flight request count). No correctness or leak impact; bounded by `max_body_bytes` and request lifetime; not observable in the gates. Follow-up suggestion (out of F2.1 scope): redact in place via ownership transfer — `decoded` has no uses after `proxy.rs:605`, so `redact_body` could take ownership and eliminate the clone.
- **P2 (pre-existing, NOT a regression of this unit; parity verified): JSON object keys are never scanned.** A secret placed in a key name transits unredacted on BOTH the base and candidate paths (harness `secret_in_key_parity`: outputs byte-identical, key untouched). `redact_value` walks values only. Out of F2.1 regression scope (the old path behaves identically) but a real redaction-bypass class — recommend the plan owner track it as a separate backlog item.
- **P2 (pre-existing, parity verified): keyword constraints match the RAW body text.** A context keyword written as `\uXXXX` JSON escapes is invisible to the `ContextAnalyzer` on both paths identically (harness `escaped_context_keyword_parity`). Same backlog class as the previous item; no divergence introduced by F2.1.
- **Contention flake (documented, no action):** `load_test_100kb_phone_list` failed once (p99 89.479 ms vs 15 ms) at load average 17.94 with 35 users on this shared host, then passed on both subsequent serial runs (loads 11.61 / 7.15) with no code or threshold change. This is the same host-contention class the builder disclosed for the F1.2 NBSP gate (which passed in my run 1 at p99 1.718 ms); the sensitivity appears suite-wide, not gate-specific. The F2.1 JSON gate itself never flaked. No threshold was touched by this review.
- **Hygiene note (no current exposure):** `DecodedBody`'s new `parsed` field widens its `Debug` footprint (adds keys and non-string values beyond what `text` exposes). Nothing in the repository Debug-logs `DecodedBody` today (verified); future patches must keep it that way.

## Final verdict

**PASS.** All five build/test gates are green (clippy 0 issues; ReDoS fuzz 11/11 serial; cerberus-proxy 177 with `json_redact` 7/7; cerberus-engine 237; packs 19/19), and the key adversarial objective — redaction-bypass on the retained-parse path — was attacked from 20 empirical angles plus static pipeline review and held: the reuse path's output is byte-identical to the fallback path's on every adversarial shape (duplicate keys, escapes, surrogates, unicode attacks, numeric edges, 130/120-deep nesting, 5 MB bodies, non-UTF8/BOM/empty/malformed inputs), the fallback arm is verbatim the base code so reuse-vs-fallback identity is equivalent to old-vs-new identity, the production pipeline cannot produce a stale `parsed` (single immutable `Bytes` shared by `decode` and `redact_body`, `DecodedBody` constructed only in `decode()`), no panic/DoS surface was added (clone recursion bounded by serde's parse-depth limit; malformed/deep/oversized inputs degrade safely), the scan analyzer is built from the same raw bytes on both paths, no new `unwrap`/`expect`/logging touched the request path, and the permanent JSON gate passed in every run at p99 0.224–0.240 ms (64-leaf) and 0.353–0.354 ms (512-leaf) against the 5 ms budget on a host that was anything but quiet. The two P2 items are non-blocking (one bounded resource note introduced by the change, two pre-existing parity-verified observation classes out of F2.1 scope), and the single load-test flake occurred on a non-F2.1 gate under load 17.94 and passed twice immediately after, matching the builder's disclosed contention sensitivity — no threshold was moved by anyone in this review.
