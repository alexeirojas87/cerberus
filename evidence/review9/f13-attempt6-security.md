# Evidence — F1.3 attempt-6 verification panel — SECURITY lens

- Candidate: commit `fdebc39dbf974892337ee5f20162e0480708249f` (r9-remediation); prior rejected: `3e20fd6`; base `fccd9e4`
- Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f13-attempt6-security` (detached HEAD at `fdebc39`); Date: 2026-08-31
- Host: `25.5.0 arm64` (macOS 26.5.1, Apple M4 Pro); Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`
- Reviewer: independent adversarial security lens; this is the lens whose attempt-5 report (`evidence/review9/f13-attempt5-security.md`) found the P1. All builder claims re-executed, not trusted. `git status --porcelain` in the worktree: clean — no code/test/threshold was edited by the panel.
- Frozen-integrity: SHA-256 of `crates/cerberus-engine/src/engine.rs` (`87bacec2…ded36e8`), `crates/cerberus-engine/src/entropy.rs` (`36e956db…cdb285`), `crates/cerberus-engine/Cargo.toml` (`58a05566…bb57`), `Cargo.lock` (`583ec84c…c9`) match the attempt-6 pack hashes exactly; `crates/cerberus-packs/src/default_pack.rs` (`66679c8a…5610`) and `tests/load_test.rs` (`cb13bf7e…b15`) match the attempt-5 frozen hashes (pack and load tests untouched).
- Lockfile versions verified in the candidate `Cargo.lock`: `regex 1.13.1`, `regex-syntax 0.8.11`, `aho-corasick 1.1.5` — identical to the attempt-5 differential-proof conditions; the fix adds `regex-syntax` as a direct dependency of `cerberus-engine` but resolves to the already-pinned 0.8.11 (Cargo.lock diff is exactly one dependency-list line).

## Commands run

| # | Command (verbatim) | Exit | Result |
|---|---|---|---|
| 1 | `git -C /Users/alexeirojas/Work/Personal/Cerberus worktree add --detach /var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f13-attempt6-security fdebc39dbf974892337ee5f20162e0480708249f` | 0 | worktree at `fdebc39` |
| 2 | `git diff 3e20fd6..fdebc39 --stat` / full diff of `engine.rs`, `entropy.rs`, `Cargo.toml`, `Cargo.lock` | 0 | fix = derived fold-to-ASCII presence bucket + gate OR-term + 5 tests + docs; no threshold/pack/test changes |
| 3 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | `cargo clippy: No issues found` |
| 4 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | 11 passed (rtk); raw re-capture: `11 passed; 0 failed … finished in 0.17s`, incl. `redos_fuzz_multibyte_entropy_window_straddle`, `redos_fuzz_separated_pan_classes` |
| 5 | `rtk proxy cargo test -p cerberus-engine` | 0 | 217 + 15 + 5 = **237 passed, 0 failed** (4 suites); all 5 new P1 tests pass **by name**: `entropy_presence_gate_unicode_casefold_longs_s_keyword_detected`, `entropy_presence_gate_unicode_casefold_kelvin_sign_keyword_detected`, `entropy_fold_source_bucket_matches_regex_folding_tables_exactly`, `entropy_presence_gate_ascii_keyword_control_detected`, `entropy_presence_gate_unicode_casefold_detected_on_separate_context_leaf` |
| 6 | `rtk proxy cargo test -p cerberus-proxy json_redact` | 0 | 5 passed / 0 failed (132 filtered in lib + 38 in integration binary = the 170 "filtered" of attempt 5; proxy package untouched by diff) |
| 7 | `rtk proxy cargo test -p cerberus-packs --test production_pack_pr` | 0 | `19 passed; 0 failed` |
| 8 | `printf` + `xxd`/`python3` byte-verification of 12 throwaway payloads in `/var/folders/…/opencode/payloads-a6/` | 0 | every payload code-point-verified (caught and fixed one panel-side byte error: `e284a2`=™ vs `e284aa`=KELVIN) |
| 9 | `rtk proxy cargo run -q -p cerberus --bin cerberus -- scan <payload>` × 11 | 0 | CLI differential table below |
| 10 | `rtk proxy cargo run -q --offline` (throwaway probe crate `foldcheck6` in `/var/folders/…/opencode/foldcheck6`, pinned `regex =\"=1.13.1\"`, `regex-syntax =\"=0.8.11\"`, `aho-corasick =\"=1.1.5\"`) | 0 | independent fold-closure proof over ALL 1,113,984 non-ASCII scalars — see criterion rows |
| 11 | `rtk proxy cargo test -p cerberus-engine --lib context_prefilter_unicode_fallback_preserves_casefold_and_boundaries -- --nocapture` | 0 | `1 passed` (focal U+0130 context-fallback test) |
| 12 | `rtk cargo test --test load_test -- --test-threads=1` (debug) | 0 | 13 passed — fingerprint/drift asserts (tests/load_test.rs:592–618) execute in both profiles; `default sha256:b632f5a6…5220f`, `max sha256:40884edf…5992` asserted unchanged |
| 13 | `shasum -a 256` on the six frozen files | 0 | all match (above) |
| 14 | `grep -n "entropy_keyword_ids\|entropy_fold_source_ids\|detect_near_keywords" crates/cerberus-engine/src/engine.rs` | 0 | exactly ONE entropy gate (engine.rs:647–648), inside `scan_inner_prepared_with_presence` — the single funnel for `scan`, `scan_with_context`, `scan_with_context_analyzer`; no second unpatched gate |
| 15 | `grep -rn "println!\|eprintln!\|dbg!\|tracing::\|log::" crates/cerberus-engine/src/{entropy,engine}.rs` | 0 | zero hits — no logging in production engine code |

No code, test, or threshold file was edited anywhere; payloads and the probe crate live in `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/` (outside the worktree and the main repo).

## Per-criterion verdicts

| Criterion | Verdict | Evidence |
|---|---|---|
| clippy clean | **PASS** | Gate #3: `No issues found`, exit 0, workspace + all targets, `-D warnings` |
| ReDoS release 11/11 | **PASS** | Gate #4, raw re-capture confirms 11/0 on the shipped pack |
| engine 237/237 (incl. 5 new P1 regression tests) | **PASS** | Gate #5: 237 passed / 0 failed; all 5 new tests pass by name and codify exactly this panel's attempt-5 proof (folded ſ/KELVIN detection, exact-span asserts, ASCII control, leaf path, exact-set canary) |
| proxy json_redact 5/5 | **PASS** | Gate #6 |
| production pack 19/19 | **PASS** | Gate #7 |
| P1 fix confirmed via CLI differential | **PASS** | Table below. Canonical `ſecret=` (U+017F replacing s) and `<U+212A>ey=` both **DETECTED** with the same value hash as the ASCII control — the attempt-5 regression (both were `✓ No sensitive data detected.`) is gone |
| Fold-closure re-derivation | **PASS** | Independent probe (gate #10), NOT reusing builder code: (a) my own re-derivation from `(?i:{a..z})` HIR classes via regex-syntax 0.8.11 yields exactly {U+017F, U+212A}; (b) ground truth from the actual matcher — `Regex::new("(?i)^[a-z]$")` (regex 1.13.1) run over **all 1,113,984 non-ASCII Unicode scalars** — yields exactly {U+017F, U+212A}; (c) the two sets are EQUAL (`CLOSURE: derived set == regex matcher set — SOUND`). No code point matches the keyword regex while missing from the automaton. Completeness argument also holds structurally: keyword chars are a–z ∪ {`_`,`-`,`.`}; the non-letters have singleton `(?i)` classes, so only letter classes can admit non-ASCII text chars |
| ASCII presence preserved / additive-only | **PASS** | Fold-source patterns consist solely of non-ASCII bytes (c5 bf, e2 84 aa) and can never match ASCII text, so for ASCII payloads the new OR-term is constant-false and the gate decision is byte-identical to attempt 5. The diff changes no prefix/entropy/context bucket contents — only appends the fold bucket (`merged_presence_buckets`, engine.rs:95–150) and re-plumbs ids; ids remain aligned by construction order (prefixes, entropy, context, fold; engine.rs:372–378) |
| Conservative context guard coexistence | **PASS** | The two guards are independent and both live: the context-analyzer decision keeps `if !context.is_ascii() \|\| self.context_keyword_ids…` (engine.rs:489 — non-ASCII contexts always build the `ContextAnalyzer`), while the entropy gate (engine.rs:647–648) owns the fold bucket. Focal test `context_prefilter_unicode_fallback_preserves_casefold_and_boundaries` 1 passed; CLI `İ password=<value>` still detects |
| Over-admission safety (no finding without the regex) | **PASS** | Presence hits from fold ids can only trigger `detect_near_keywords_proven`, which runs the real regex; fold/context ids are beyond the `prefixed_entries` id range (entries vec is sized by prefix count only, engine.rs:340–345) so they cannot fabricate rule findings; the unprefixed loop is driven by its regex list, not by presence. Empirical: payload `ſsecret=…` (ſ *prepended* to the full word) marks the ASCII keyword bucket (it contains the literal `secret`), the regex then **legitimately rejects** it — ſ is a word character so `\bsecret\b` has no boundary there (probe case `ſsecret → false`) — and the engine emits no finding: presence hit → regex decides → no fabricated finding, correct parity with base (base's unconditional regex also does not match it) |
| Unicode edges (U+0130 / combining / ZWJ class) | **PASS** | Focal test 1 passed (gate #11); probe confirms İ/ß/fullwidth/circled/modifier do NOT fold onto ASCII under regex 1.13.1 (no over-marking pressure); ReDoS multibyte-straddle test passes; `éey=` boundary payload correctly undetected via CLI |
| KNOWN_SAFE_EXAMPLES scoped honestly | **PASS** | New doc comment (entropy.rs:61–82) declares what/why/risk and the layering follow-up. Suppression is EXACT-value only: `KNOWN_SAFE_EXAMPLES.contains(&value)` on the extracted value (entropy.rs:254). CLI spot-check: `password=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` → no finding; variant `…EXAMPLEKEZX` → `entropy.high_entropy_secret` fires (pos 9..50). Can not be abused to suppress different values |
| Panic / DoS surface of the new mechanism | **PASS** | New code contains no `unwrap()`/`expect()`/index-panic paths: HIR parse errors are mapped to `Err` and fail engine construction (fail-closed, same as every other compile error); `char::from_u32` is `if let`-guarded; class iteration is over single-letter `(?i)` classes (tiny, bounded). The derivation runs at BUILD time (26 HIR parses, once per engine build — CLI startup, not per scan); adversarial payloads cannot influence it. Per-scan cost is 2 extra AC patterns on a linear `find_overlapping_iter` pass; ReDoS release suite 11/11 |
| No secret-material logging in new paths | **PASS** | Gate #15 grep: zero logging statements in engine.rs/entropy.rs; CLI output prints only flag/pos/hash (hash-by-design, P1-12); new derivation prints nothing |
| Fingerprints asserted unchanged | **PASS** | tests/load_test.rs:57–58 define exactly `sha256:b632f5a6…5220f` / `sha256:40884edf…5992` (unchanged in diff); debug load run 13/13 exercises the asserts; frozen file hashes match the pack |

## P1 resolution

Original finding (attempt 5, this lens): the merged presence automaton is `ascii_case_insensitive` while the entropy keyword regex is Unicode-`(?i)`, so regex-matchable folded keyword spellings (`ſecret=…`, `<U+212A>ey=…`) never marked presence, the detector was skipped, and real high-entropy secrets near folded keywords were silently lost (CLI-confirmed: both payloads `✓ No sensitive data detected.` vs base detection).

Observed post-fix behavior (shipped CLI, exact bytes verified per payload):

| Payload | Bytes (head) | Attempt-5 result | Attempt-6 result |
|---|---|---|---|
| `p2c` `ſecret=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE` (U+017F replacing s) | `c5 bf 65 63 72 65 74 3d` | ✗ no detection (P1) | **✓ `[warn] entropy.high_entropy_secret (pos 8..38)`**, hash `sha256:3427c5f1…73c13` |
| `p3b` `<U+212A>ey=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE` | `e2 84 aa 65 79 3d` | ✗ no detection (P1) | **✓ `[warn] entropy.high_entropy_secret (pos 6..36)`**, same value hash |
| `p1` control `password=<same value>` | ASCII | ✓ detected | ✓ detected, same hash (control intact) |
| `j1` JSON leaf `{"body":"ſecret=…"}` (V4 class) | UTF-8 JSON | ✗ no detection | **✓ detected (pos 18..48)**, same hash |
| `a10` co-occurrence `ſecret=…` + `password=…` | mixed | 2 findings (gate per-file) | 2 findings — unchanged semantics |
| `a11` `İ password=<value>` (U+0130 context edge) | `c4 b0 …` | ✓ detected | ✓ detected (pos 12..42) |
| `b1/b2/b3` `ßecret=` / `Ｓecret=` (U+FF33) / `éey=` | `c3 9f` / `ef bc b3` / `c3 a9` | n/a | ✓ correctly undetected (not foldable under regex 1.13.1 — probe-confirmed) |
| `p2` `ſsecret=…` (ſ *prepended*; panel-constructed nuance payload) | `c5 bf 73 65 …` | n/a | ✓ no finding — correct: contains ASCII `secret` (bucket fires, detector runs) but `\b` fails after ſ (word char), so the regex legitimately rejects; base parity (base's unconditional regex also does not match) |

The regression is gone in the exact direction it existed: the two payloads that regressed at attempt 5 are detected again, with spans and hashes identical to the ASCII control's value hash, and the repair provably added no skip path (the gate can only gain triggers). The fix is also drift-proof: the bucket is derived from the matcher's own tables and the canary test (`entropy_fold_source_bucket_matches_regex_folding_tables_exactly`) pins the exact set, so a future regex upgrade that widens folding re-derives the bucket automatically and flags the change.

## Findings

- **none (new).** No P0, no P1 from the attempted vectors, the full-Unicode closure probe, the code audit of the new mechanism, or the gate re-runs.
- P2-1 (`extract_prefix` Latin-1 mojibake for non-ASCII literal prefixes, engine.rs:55) and P2-3 (`is_word_char('_') == false`, constraints.rs:31) remain pre-existing, declared out-of-scope follow-ups in the attempt-6 pack; both were verified unchanged by the diff and remain parity-neutral. Not re-adjudicated.
- Prior P2-2 (undocumented `KNOWN_SAFE_EXAMPLES` carve-out) is **resolved** as documented: the new doc comment matches the observed exact-match-only behavior (empirically re-verified with the `…EXAMPLEKEZX` variant).
- Informational, no action: the word-boundary nuance in payload `p2` (`ſ` prepended to a full keyword defeats `\b` because ſ is a word character) is correct regex semantics with base parity, but rule authors/pentesters should know that folding attacks require the folded character to *replace* a keyword letter, not precede it. The engine handles both soundly (one detected, one correctly rejected by the regex after a presence-triggered run).

## Final verdict: PASS

The P1 this lens raised at attempt 5 is genuinely fixed by the derived fold-to-ASCII presence bucket, and the replacement mechanism survives every adversarial check this panel could construct: the fold closure was re-derived independently and proven EXACTLY equal to the real matcher's fold-matchable set over all 1,113,984 non-ASCII Unicode scalars ({U+017F, U+212A} under the locked regex 1.13.1/regex-syntax 0.8.11 — no gap, no over-marking that matters, since every presence hit merely triggers the regex that then decides); ASCII payloads keep the byte-identical attempt-5 gate (fold patterns cannot match ASCII text); the conservative non-ASCII context guard coexists untouched at engine.rs:489; there is exactly one entropy gate and it funnels all three scan paths; build failures are fail-closed; the derivation is build-time-only with no panic or DoS surface; the JSON leaf path, co-occurrence semantics, U+0130 edges, and the exact-match-only KNOWN_SAFE_EXAMPLES carve-out all behave as documented. All suite gates pass with exact counts (clippy 0 issues; ReDoS 11/11; engine 237/237 including the five new regression tests that codify this panel's own differential proof; json_redact 5/5; production pack 19/19), the CLI differential shows both formerly-bypassed payloads detected with control-identical value hashes, workload fingerprints and frozen file hashes match the pack, and no secret material is logged. The builder's disclosed deviation from the suggested `is_ascii` runtime fallback is justified and does not weaken the security property — it preserves miss-proves-absence for every payload while keeping the frozen budgets intact. F1.3 passes the security lens; the unit may proceed to sign-off subject to the other lenses and the F1 integration reviewer.
