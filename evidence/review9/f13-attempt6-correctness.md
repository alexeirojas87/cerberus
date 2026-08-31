# Evidence — F1.3 attempt-6 verification panel — CORRECTNESS lens

- Candidate: commit `fdebc39` (branch `r9-remediation`); prior approved baseline `3e20fd6` (attempt 5); original base `fccd9e4`
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f13-attempt6-correctness` (detached HEAD at `fdebc39`, clean at end: `git status --porcelain` empty)
- Date: 2026-08-31
- Host: macOS 26.5.1 (build 25F80), arm64, Apple M4 Pro
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`, host `aarch64-apple-darwin`
- Reviewer: independent adversarial CORRECTNESS lens; every builder claim re-verified by running code, not trusted. Blind to sibling lenses (only `evidence/review9/f13-attempt5-security.md`, `evidence/review9/fix-plan.md` and the worktree's own evidence pack were read; no `f13-attempt6-*` sibling file was opened).
- No code, test, or threshold file was edited anywhere. Throwaway artifacts: probe crate `/var/folders/…/opencode/f13-foldprobe/` and payloads `/var/folders/…/opencode/f13-payloads/` (both outside the worktree and the main repo).

## Commands run

| # | Command (verbatim) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f13-attempt6-correctness fdebc39dbf974892337ee5f20162e0480708249f` | 0 | worktree at `fdebc39` |
| 2 | `rtk cargo fmt --all -- --check` | 0 | clean |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | `cargo clippy: No issues found` |
| 4 | `rtk cargo test --workspace --all-targets` | 0 | **664 passed** (25 suites, 50.28s), 0 failed — matches builder claim (659 + 5 new) |
| 5 | `rtk cargo test -p cerberus-engine` | 0 | **237 passed** (4 suites) — matches builder claim (232 + 5 new) |
| 6 | `rtk proxy cargo test -p cerberus-engine --lib` (filtered) | 0 | all 5 new tests listed and `ok`: `entropy_fold_source_bucket_matches_regex_folding_tables_exactly`, `entropy_presence_gate_ascii_keyword_control_detected`, `entropy_presence_gate_unicode_casefold_longs_s_keyword_detected`, `entropy_presence_gate_unicode_casefold_kelvin_sign_keyword_detected`, `entropy_presence_gate_unicode_casefold_detected_on_separate_context_leaf` (lib total 217 = 212 + 5) |
| 7 | `rtk proxy cargo test -p cerberus-engine --lib engine::tests::<each new test> -- --exact` × 5 | 0 | each: `1 passed; 0 failed` |
| 8 | `rtk cargo test -p cerberus-packs --test production_pack_pr` | 0 | **19/19** |
| 9 | `cargo build --release --offline` in throwaway probe crate pinned `regex = "=1.13.1"`, `regex-syntax = "=0.8.11"` | 0 | probe compiled against the exact lockfile versions |
| 10 | `./target/release/f13-foldprobe` | 0 | **fold-closure re-derivation: ALL CHECKS PASSED** (details below; full output `f13-foldprobe/probe-out.txt`) |
| 11 | `cargo tree -p cerberus-engine -i regex-syntax` | 0 | single node `regex-syntax v0.8.11`, already depended on by `regex v1.13.1` and `regex-automata v0.4.18`; cerberus-engine adds a direct edge to the **same** version — no duplication, no bump |
| 12 | `git diff 3e20fd6..fdebc39 -- tests/load_test.rs` | 0 | **empty** — `load_test.rs` byte-identical to the approved attempt-5 baseline |
| 13 | `grep -n "b632f5a6…5220f\|40884edf…5992" tests/load_test.rs` | 0 | both fingerprints asserted at `tests/load_test.rs:57-58` |
| 14 | `shasum -a 256 crates/cerberus-packs/src/default_pack.rs tests/load_test.rs crates/cerberus-engine/src/engine.rs crates/cerberus-engine/src/entropy.rs crates/cerberus-engine/Cargo.toml Cargo.lock` | 0 | `default_pack.rs` `66679c8a…` and `load_test.rs` `cb13bf7e…` match the attempt-5 frozen hashes exactly; `engine.rs` `87bacec2…`, `entropy.rs` `36e956db…`, `Cargo.toml` `58a05566…`, `Cargo.lock` `583ec84c…` match the attempt-6 frozen hashes in the evidence pack |
| 15 | `awk '/pub fn scan_with_context/{in_scan=1} /fn make_finding/{in_scan=0} in_scan && /Regex::new/{found=1} END{if(found) exit 1; print "PASS: scan and scan_with_context contain no Regex::new"}' crates/cerberus-engine/src/engine.rs` | 0 | PASS (this range covers `scan_with_context`→`make_finding`, i.e. `scan_inner`, `scan_inner_prepared`, `presence_scan`, the entropy gate and the context fallback) |
| 16 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1` | 0 | **11/11** |
| 17 | `rtk cargo test -p cerberus-proxy json_redact` | 0 | 5 passed, 170 filtered out |
| 18 | `rtk cargo test -p cerberus-engine --test integration_test` | 0 | 15 passed |
| 19 | `rtk cargo test --test load_test -- --test-threads=1` (debug) | 0 | **13/13** — fingerprint/pattern-count asserts run in both profiles; frozen pan-path budget gate included |
| 20 | determinism × 2 runs: `rtk proxy cargo test -p cerberus-engine --lib engine::tests::compiled_multiline_and_entropy_state_is_reused_across_scans -- --exact`; `rtk proxy cargo test -p cerberus-engine --lib pan_candidate_ranges_match_reference -- --nocapture`; `rtk proxy cargo test -p cerberus-engine --lib context_prefilter_unicode_fallback -- --nocapture` | 0 | all pass identically on both runs; the payment-card differential oracle is seeded (`seed = 0x9E37_79B9_7F4A_7C15`) and runs 2 × 5,000 = 10,000 randomized trials per invocation (engine.rs:1868, 1895) — builder's "10,000 randomized trials" claim accurate |
| 21 | `rtk cargo run -q -p cerberus --bin cerberus -- scan <payload>` × 5 adversarial payloads (table below) | 0 | CLI differential, see Attack vectors |
| 22 | `git status --porcelain` / `git diff --check` (worktree) | 0 | clean — reviewer modified nothing |

Not re-run: the F1.3 release throughput gate. That instrument belongs to the performance lens; no correctness verdict below rests on wall-clock timing (same panel-concurrency discipline as the attempt-5 security lens).

## Gate 6 — fold-closure re-derivation (the key adversarial task)

Method: a throwaway probe crate pinned to the exact lockfile versions (`regex 1.13.1`, `regex-syntax 0.8.11`, resolved offline; verified in the probe's own `Cargo.lock`) that does NOT reuse any builder logic as evidence:

1. **Exhaustive ground truth by actual matching**: for every Unicode scalar value 0..=0x10FFFF (surrogates excluded), test `Regex::new("(?i:[a-z])").is_match(char)` with the real regex 1.13.1 engine, then disambiguate per letter with `(?i:<letter>)` regexes. Result: the ONLY non-ASCII scalars matchable are **U+017F (ſ → s)** and **U+212A (KELVIN SIGN → k)**. No other ASCII letter has any non-ASCII fold-match.
2. **Derivation equality**: re-implemented the builder's algorithm (parse `(?i:<letter>)` with `regex-syntax`, keep non-ASCII Unicode-class members) independently in the probe and compared per letter and overall with ground truth — **identical for all 26 letters**. The engine's `fold_to_ascii_source_patterns()` (entropy.rs:163) therefore derives exactly the matchable set; under-admission is ruled out by exhaustion over the whole code space, not by sampling.
3. **Real-keyword differential**: rebuilt the exact entropy keyword regex from the actual 21 `KEYWORDS` (entropy.rs:28-50, same escape/sort/join construction) and tested substitutions.
   - Positive: ſ into every `s` position and KELVIN into every `k` position of every keyword — 22/22 matched the isolated per-keyword regex (`(?i)\b(<kw>)\b`).
   - Negative: 62,580 substitutions of non-closure suspicious characters (fullwidth U+FF21-FF5A, circled U+24B6-24E9, math bold/italic/sans/monospace alphanumerics, small capitals, modifiers, ß, ẞ, İ, ı, ẛ U+1E9B, Ω, Å, subscript/superscript ranges, extended-Latin additions) at every letter position of every keyword — **all correctly rejected**. Zero matchable spellings outside the derived bucket.
   - **ß/ss full-folding attack** (the one class per-char brute force cannot see): `paßword`, `paẞword`, `paßwd`, `acceßs_key` do NOT match (regex 1.13.1 does not apply text-side full case folding to ASCII pattern letters); `paſſword`/`paſsword`/`ſecret`/`ſECRET`/KELVIN-`ey`/`apiꞰey` DO match; `apİey`/`apıey`/fullwidth `paｓｓword` do NOT. The soundness claim survives the full-folding edge exactly because keyword letters are ASCII (no multi-char folds expand the pattern side).
4. **Canary validity**: `entropy_fold_source_bucket_matches_regex_folding_tables_exactly` (engine.rs:1369) reads the LIVE `fold_to_ascii_source_patterns()` and asserts `decoded == ["\u{017f}", "\u{212a}"]` plus 6 behavioral non-match spellings. Since the bucket is derived (probe-proven equal to matcher truth), any future regex-table change automatically changes the derivation and trips the exact-set assertion. Canary is genuine.

**Verdict: builder claim CONFIRMED — the fold closure is exactly {U+017F, U+212A}.**

Bucket completeness (code audit, engine.rs:95-151, 357-397, 521-533, 647-659):
- All 21 entropy keywords are appended **unconditionally** (`entropy_ids` = full contiguous range) — no keyword dropped, no cross-bucket dedup that could remove an id. Aho-Corasick assigns ids in insertion order and `find_overlapping_iter` reports every pattern occurrence, so bucket-id → `presence[id]` mapping is exact; duplicate patterns (e.g. a context keyword equal to an entropy keyword) coexist with distinct ids.
- Context bucket uses the same filter/sort/dedup semantics as the standalone prefilter; the separate-buffer path keeps its own `context_keywords_may_match` and the same-buffer path keeps the `!context.is_ascii()` conservative fallback (engine.rs:489) — attempt-5 approved behavior untouched.
- Fold bucket: non-ASCII multi-byte patterns cannot byte-collide with ASCII keywords/prefixes; sort+dedup within the set; empty-bucket case degrades to the attempt-5 gate but is pinned non-empty by the canary. Fold bytes (`c5 bf`, `e2 84 aa`) appear in valid UTF-8 iff the character appears, so no spurious marking of ASCII payloads — the attempt-5 ASCII gate decision is byte-for-byte preserved.
- Over-admission: none exists (derived set == matchable set); even hypothetical over-admission is safe (presence hit → regex runs → regex rejects → no finding). Under-admission: excluded by the exhaustive probe.

## Per-criterion verdicts

| Criterion | Verdict | Evidence |
|---|---|---|
| fmt | **PASS** | Cmd 2: exit 0 |
| clippy | **PASS** | Cmd 3: exit 0, `No issues found`, workspace + all targets, `-D warnings` |
| workspace debug 664 | **PASS** | Cmd 4: 664 passed (25 suites), 0 failed — exact match with builder claim |
| engine 237 + the 5 new P1 tests | **PASS** | Cmds 5-7: 237 passed; all 5 new tests exist, individually run with `--exact`, each `1 passed`. Names match the claimed set: U+017F test, U+212A test, leaf-path test (`scan_with_context` AND `scan_with_context_analyzer`), ASCII control, exact-set canary |
| pack 19/19 | **PASS** | Cmd 8: 19 passed |
| fold-closure re-derivation {U+017F, U+212A} | **PASS (confirmed)** | Gate 6 above: exhaustive 1.1M-scalar brute force + derivation equality + 22 positive / 62,580 negative substitutions + ß-ss/İ/ı/fullwidth batteries; closure is exactly {U+017F, U+212A} under regex 1.13.1 / regex-syntax 0.8.11 |
| bucket completeness vs ASCII keywords | **PASS** | Gate 6 code audit: all 21 keywords unconditional in automaton; contiguous insertion-ordered ids; no dedup collisions possible (non-ASCII vs ASCII bytes); empty-bucket handled; context-path mapping shared and unchanged; ASCII control test + CLI control confirm presence answers |
| Cargo.toml change explained | **PASS** | Adds `regex-syntax = "0.8"` (with explanatory comment) as a normal dependency of `cerberus-engine`, used by `fold_to_ascii_source_patterns()` at **engine-build time only** (HIR parse in `EngineBuilder::build`, never per scan). `cargo tree` proves it resolves to the already-pinned 0.8.11 that `regex 1.13.1`/`regex-automata 0.4.18` already used — zero new crates, zero version changes, `Cargo.lock` diff is exactly the one dependency-list line. Runtime dependency graph unchanged in any way that could affect matching semantics (regex/aho-corasick untouched); no finding or performance-semantics impact beyond the build |
| fingerprints unchanged | **PASS** | Cmds 12-14: `tests/load_test.rs` byte-identical to `3e20fd6`; both fingerprints asserted at lines 57-58; `default_pack.rs` and `load_test.rs` SHAs equal the attempt-5 frozen hashes — rules/payload bytes did not move in attempt 6 (diff touches only engine.rs, entropy.rs, engine Cargo.toml, Cargo.lock, evidence pack) |
| determinism | **PASS** | Cmds 19-21: multiline state-reuse, 10,000-trial seeded payment-card differential oracle, and unicode-fallback focal test all pass identically twice; CLI battery consistent (same value hash `3427c5f1…` across ſ/KELVIN/ASCII detections) |
| no-Regex::new structural | **PASS** | Cmd 15: required awk PASS (range covers the whole scan region); no regex compilation anywhere on the scan path — the only new compile-time regex work is the build-time HIR parse in the constructor path |
| (bonus) ReDoS release suite | **PASS** | Cmd 16: 11/11 with the two extra automaton patterns |
| (bonus) json_redact + integration suites | **PASS** | Cmds 17-18: 5 passed / 15 passed |
| (bonus) debug load suite incl. fingerprint asserts + frozen pan-path gate | **PASS** | Cmd 19: 13/13 |

## Attack vectors tried

| # | Vector | Payload (under `/var/folders/…/opencode/f13-payloads/`, bytes verified with `xxd`) | Outcome |
|---|---|---|---|
| V1 | P1 replication end-to-end (attempt-5 security lens's own payloads, re-run against attempt-6 CLI) | `v1_longs_secret.txt` = `ſecret=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE` (`c5 bf` + `ecret=`); `v1b_kelvin_key.txt` = KELVIN+`ey=…` (`e2 84 aa` + `ey=`) | **Both DETECTED**: `entropy.high_entropy_secret`, spans `pos 8..38` and `pos 6..36`, value hash `3427c5f1…` identical to the ASCII control — the exact payloads attempt 5 demonstrably lost now fire through the shipped binary. P1 closed end-to-end, not just in unit tests |
| V2 | ASCII control | `p1_control.txt` = `password=<same value>` | DETECTED, same hash — control intact |
| V3 | JSON leaf path via unit tests | covered by `entropy_presence_gate_unicode_casefold_detected_on_separate_context_leaf` (both `scan_with_context` and `scan_with_context_analyzer`) + json_redact suite | PASS — the gate funnels the leaf path |
| V4 | ß/ss full-folding detection gap (pattern `ss` vs text `ß`) — the one attack the per-char closure cannot exclude | `v5_passzword_ss_attack.txt` = `paßword=<secret>` via CLI; `paẞword`/`paßwd`/`acceßs_key` via probe | **Refuted**: regex 1.13.1 does not full-fold ASCII pattern letters; no match, CLI reports "No sensitive data detected" — parity with base `fccd9e4` (whose identical regex also does not match) |
| V5 | İ / ı / fullwidth / circled / math-alphanumeric / small-caps / modifier keyword spellings | 62,580 isolated per-keyword substitutions (probe) + canary's 6 behavioral spellings | All rejected — no matchable spelling outside {ſ, KELVIN}; no under-admission |
| V6 | Alternation substring collision (found in my own probe, not the engine): `auth-t<garbled>ken` "matched" because standalone `auth` matches inside it | probe 4b initially flagged ~hundreds of false "gaps" on `auth-t<c>ken` strings | **Probe artifact, not an engine gap**: the match comes from the all-ASCII keyword `auth`, whose spelling the ASCII-CI keyword bucket marks present (the automaton contains `auth` too), so the detector runs and the regex behaves exactly as at base. Fixed the probe to per-keyword isolated regexes; re-run clean (exit 0) |
| V7 | Over-admission / spurious presence from the two new patterns | code audit + probe: fold patterns are non-ASCII multi-byte; cannot match ASCII text; UTF-8 self-synchronization prevents byte-subsequence confusion | No ASCII-path behavior change (attempt-5 gate preserved byte-for-byte); hypothetical over-admission would only add safe regex rejections |
| V8 | Dedup / empty-bucket / id-mapping hazards | code audit of `merged_presence_buckets` (engine.rs:109-151) and `presence_scan` (engine.rs:521-533) | No keyword excluded; ids contiguous and insertion-ordered; sort+dedup inside fold set; `.any()` on empty vec safe; canary pins the set non-empty and exact |
| V9 | Can the fix reopen under a regex upgrade? | canary reads the live derivation and asserts the exact set | Change of folding tables ⇒ derivation changes ⇒ canary trips. Drift-proof by construction |

## Findings

**none** (no P0, no P1, no P2).

Notes, none rising to a finding:
- The builder's "pre-fix proof" (new tests fail on attempt-5 code) could not be re-executed by this lens without editing code (forbidden). It is nonetheless corroborated by independent evidence: the attempt-5 security lens differentially proved those payloads were lost at `3e20fd6`, and this lens confirms the same payloads are detected at `fdebc39` through the shipped CLI — the tests assert exactly that differential.
- The performance-side claims (56.4 ms unconditional-fallback pathology, 5-run stability series, ~2-7 µs median cost) were NOT re-measured here — timing is the performance lens's instrument; this report takes no position on them.

## Final verdict: PASS

All ten required criteria pass with exact, independently obtained counts: fmt and clippy clean; workspace debug 664/664 and engine 237/237 with all five new P1 regression tests present, individually executed, and passing; production pack 19/19; the fold closure independently re-derived by exhaustive brute force over every Unicode scalar with the real regex 1.13.1 engine and confirmed to be exactly {U+017F, U+212A}, with the HIR derivation proven equal to matcher ground truth and 62,580 adversarial substitutions (including the ß/ss full-folding class, İ/ı, fullwidth, circled and math-alphanumeric spellings) unable to find any matchable keyword spelling outside the derived bucket; bucket construction verified complete for all 21 ASCII keywords with sound id mapping; the Cargo.toml addition shown by `cargo tree` to bind the already-pinned regex-syntax 0.8.11 with a one-line lock change and no runtime-graph effect; workload fingerprints and frozen file hashes byte-identical to the approved attempt-5 baseline; determinism reproduced across repeated seeded-oracle, multiline-reuse and unicode-fallback runs; and the scan paths still contain no regex compilation. The original P1 is closed where it matters — both folded-keyword payloads that attempt 5 demonstrably lost now fire through the shipped CLI with the same finding hash as the ASCII control, while the ß/ss attack and no-keyword controls correctly stay silent in parity with base. The builder's different fix mechanism (derived fold-source presence bucket instead of an unconditional non-ASCII fallback) is not merely acceptable but arguably stronger: it is derived from the matcher's own tables, canary-guarded against future drift, and preserves the attempt-5 gate byte-for-byte on ASCII payloads. F1.3 attempt 6 PASSES the correctness lens.
