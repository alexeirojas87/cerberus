# F1.2 — Performance/ReDoS independent review, repair attempt 7

- Verdict: **PASS** — attempt-6 perf wins fully preserved (mixed-dense 100 KB p50 0.592 vs attempt-6 0.638); the two new attempt-7 worst cases (mixed-style recovery emission, max-gap-density split predicate) stay inside every §5 budget with margin; scaling linear 100 KB→1 MB on all 13 classes; allocation churn unchanged vs attempt 6; F1.1 invariant holds statically and at runtime. No repo files edited (review-only); probe + raw results in `target/audit-probe7/`.
- Reviewer terminal: term_3e827bd5-ce0b-4b59-873b-f39ea2203f8a · task_f77aeeb8332f · dispatch ctx_3a1913942aa1 · date 2026-08-28
- Host: macOS/Darwin arm64 (Apple M4 Pro), rustc/cargo 1.97.1, `--release`, `--test-threads=1` (serial), probe = min-p50 of 3 reps × 200 samples (host had concurrent opencode processes at 40–48 % CPU; min-of-3-reps de-noising verified by exact match of unchanged-scenario p50s to attempt-6 baselines).
- Base HEAD: fccd9e4 (docs/fix-install-commands), uncommitted attempt-7 worktree.
- Prior baseline: `evidence/review9/f12-attempt6-performance.md` (verdict PASS).

## 1. Frozen hash verification — ALL PASS (11/11)

| Artifact | Expected (prefix) | Observed |
|---|---|---|
| crates/cerberus-engine/src/engine.rs | 4c99ae8567c1d18e | match |
| crates/cerberus-engine/src/entropy.rs | 265bb24eb1547c4e | match |
| crates/cerberus-engine/src/validator.rs | 390f50a334e613b9 | match |
| crates/cerberus-engine/src/constraints.rs | 5f23d304082b93ca | match |
| crates/cerberus-packs/src/default_pack.rs | 29373725eb755888 | match |
| crates/cerberus-packs/tests/production_pack_pr.rs | 33dfae2ab4e50c95 | match |
| tests/corpus/product-gate/manifest-v1.json | ddbc3b2da5943dba | match |
| tests/corpus/negatives/05-attempt5-adversarial.txt | c780fb52966ce63d | match |
| tests/corpus/positives/07-separated-pans.txt | 62b392e817371bf4 | match |
| tests/load_test.rs | 7ac0663d711bf19d | match |
| evidence/f1/raw/production_pack_pr.json | b7effa21a34c740e | match |

entropy.rs, validator.rs, constraints.rs and 05-attempt5-adversarial.txt are byte-identical to the attempt-6 frozen set, as the builder stated.

## 2. Reproduced suites (release, serial, this worktree) — ALL PASS

```
cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1  → 19/0 (1.94s)
cargo test --release --test redos_fuzz -- --test-threads=1                            → 11/0 (0.05s)
cargo test --release --test load_test   -- --test-threads=1                           → 11/0 (1.21s)
cargo test --release -p cerberus-engine -- --test-threads=1                           → 203 lib + 15 integration + 5 unit-feature = 223/0
```

All four counts match the builder's claims exactly.

Reproduced guard numbers (load_test release serial, `--nocapture`):

| guard | p50 / p99 (ms) | builder claim | budget |
|---|---|---|---|
| attempt6 mixed_pan_dense_50kb | 0.297 / 0.404 | 0.295 / 0.362 | 5 |
| attempt6 mixed_pan_dense_100kb | 0.592 / 0.764 | 0.587 / 0.633 | 1 (2× CI tol) |
| attempt6 nbsp_only_100kb | 0.616 / 0.791 | 0.615 / 0.748 | 1 (2× CI tol) |
| attempt6 two_pan_one_line | 0.001 / 0.002 | 0.001 / 0.001 | 5 |
| attempt7 mixed_pan_recovery_100kb | 2.639 / 3.063 @ 5,536 findings | 2.586 / 2.791 @ 5,536 | 8 (emission class) |
| 1KB / 10KB / 50KB+secrets / 100KB clean | 0.006 / 0.066 / 0.385 / 0.565 p99 | 0.006 / 0.070 / 0.377 / 0.641 | 15 CI |
| 100KB phone-list | 4.482 p99 | 4.591 | 15 CI |
| decode+scan / scan+redact | 0.272 / 0.240 p99 | 0.265 / 0.368 | 15 CI |
| gate phone-list reject / all-fire | 2.069/2.559 · 4.220/5.188 | 2.031/2.434 · 4.178/4.483 | per-gate |

## 3. Attempt-7 changes — mechanism verified at source level

- **SEC-1 (mixed separator styles inside one PAN):** `partition_payment_card_run` (engine.rs:701–723) now splits only on `both_sides_complete && (last_separator.is_none() || separator_changed)` where `both_sides_complete = (13..=19).contains(digits_before) && digits_after >= 13` (engine.rs:710–712). **No rescan:** the predicate is O(1) per gap (two subtractions + range test), gaps are visited exactly once in one forward pass, `payment_card_valid` runs at most once per split + once for the final tail segment, each over ≤19 bytes — total work ≤ O(run bytes). Measured max split density (every gap both-sides-complete, "9"×13 + cycling seps): **0.274 ms/100 KB p50** (issuer-reject is cheap); max gap density with kind changes every 5 bytes ("9999.9-" repeated): **0.812 / 0.881 p50/p99** — within the 1 ms gate but the **thinnest non-emission margin (19 %)**; see finding 1.
- **SEC-2 (`\b` word-class parity):** `regex_word_char` (engine.rs:558–567) — ASCII resolves on a table-free fast path; non-ASCII consults a process-wide `OnceLock<Regex>` `\w` probe. **Probe cost is NOT per-scan and not even per-engine-build:** it is lazy once per process (first non-ASCII boundary check). Cold first CJK scan: 1.675 ms incl. one-time compile (3,107 allocs / 981 KB); the very next scan is back to **3 allocs**. Steady-state CJK stress (every PAN run boundary non-ASCII, 2 probe calls/unit ≈ 5,120/100 KB) p50 **0.710** vs prose 0.380 → **+0.33 ms/100 KB**, matching the builder's +0.32 claim. All inside the 1 ms/100 KB gate.
- **Debug load-guard honesty change** (`assert_plan_budgets`, tests/load_test.rs:77–101): debug now asserts only `p50 < 30 ms` pathology ceiling (logs p99); release still asserts **p50 < plan budget strictly** and **p99 < 2× plan budget** (documented `PLAN_CI_TOLERANCE=2.0`), on top of `assert_p99_budget`'s strict release p99 < 5 ms (standard) / 15 ms CI (phone-list). **Masking analysis:** a real debug-profile regression necessarily moves the median — the attempt-5 blocker class measures ≈100–300 ms debug p50 and trips the 30 ms ceiling 7–10× over; only pure-tail (p99-only) debug changes escape, and those are allocator/OS contention noise by construction (A/B in the builder evidence: attempt-6 code itself measures debug p50 16.1 / p99 48.5 today — the old p99-30 ms guard fails a clean attempt-6 reproduction). The §5 budget remains a **release** criterion and the release branch enforces both statistics strictly, so a real regression cannot ship through either branch. No threshold moved.

## 4. Probe measurements (release, full DEFAULT_PACK engine, 20 warmup, nearest-rank, min-p50 of 3 reps × 200 samples; counting global allocator; raw output `target/audit-probe7/probe7-results.txt`)

### 4a. Latency, ms, 200 samples

```
scenario                              size   findings  p50     p95     p99     gate check
mixed_pan_dense (attempt-6 payload)   50KB   0         0.298   0.311   0.364   ✓ p99 14× under 5
mixed_pan_dense                      100KB   0         0.592   0.622   0.642   1ms/100KB ✓ (36 % margin; attempt-6: 0.638/0.701 — faster, SEC-1 removes splits)
nbsp_run "4\u{a0}"                   100KB   0         0.616   0.730   0.770   ✓ (attempt-6: 0.641/0.778)
multibyte prose                      100KB   0         0.380   0.406   0.434   ✓ (attempt-6: 0.375/0.404)
cjk_stress 密钥4111… (new)           100KB   0         0.710   0.737   0.754   ✓ (builder: 0.700/0.782)
mixed_emission (new worst emission)  100KB   5120      2.467   2.564   2.616   emission class 8ms ✓ (≈0.48 µs/finding)
mixed_nearmiss Luhn-fail (new)       100KB   0         0.767   0.804   0.866   ✓ 1ms/100KB (13 % p99 margin)
visa_luhnfail dense (new)            100KB   0         0.558   0.582   0.606   ✓ max valid-call density ≈6.1k calls
ambig_poisoned (new, see §6.2)       100KB   1         0.683   0.733   0.880   ✓
half_glued ½ (new)                   100KB   5389      2.346   2.433   2.495   ✓ (builder: 2.317/2.507)
two_pan_dense                        100KB   5534      2.451   2.564   2.614   ✓ (attempt-6: 2.406/2.492)
ambig_maxsplit (new)                 100KB   0         0.274   0.289   0.298   ✓
ambig_incomplete (new)               100KB   0         0.812   0.846   0.881   ✓ thinnest margin 19 % — see §6.1
clean ASCII                          100KB   0         0.467   0.503   0.515   ✓ (attempt-6: 0.459)
phone_reject                         100KB   0         0.570   0.599   0.634   ✓ (attempt-6: 0.556/0.599)
dsoup_max 19×"9" cycling seps        100KB   0         0.462   0.483   0.491   ✓ unchanged (attempt-6: 0.467/0.509)
dsoup_dense_dot "9." giant run       100KB   0         0.751   0.854   0.921   ✓ unchanged (attempt-6: 0.789/0.948)
```

Every non-emission class holds the 1 ms/100 KB gate on **strict p99**; every emission class (5,120–5,534 findings) holds the panels' accepted 8 ms emission-class budget with ≥3× margin; §5 proxy ≤50 KB rows sit at 0.24–0.40 ms p99, 8–20× under the 3–5 ms proxy budget.

### 4b. Linearity, p50, 60 samples, 100/200/400/800/1024 KB, ratio(1024/100)

```
mixed 0.588→6.731 (×11.45)    mixed_emission 2.467→27.411 (×11.11, 52,428 findings)
mixed_nearmiss 0.766→8.505 (×11.10)   visa_luhnfail 0.565→5.790 (×10.25)
nbsp 0.606→8.092 (×13.36)     multibyte 0.385→3.931 (×10.22)
cjk 0.705→7.305 (×10.36)      half_glued 2.343→25.036 (×10.68, 55,188 findings)
two_pan 2.462→26.150 (×10.62, 56,679 findings)   ambig_maxsplit 0.271→2.826 (×10.44)
clean 0.469→4.802 (×10.23)    phone_reject 0.571→5.834 (×10.21)
dsoup_dense_dot 0.748→9.447 (×12.63)
```

10× size → 10.2–13.4× time on every class: **linear everywhere, no superlinear behavior, no ReDoS.** The ×13.36 (nbsp) and ×12.63 (dense-dot) factors are the known O(n) SepRun spill churn (transient, allocator-visible below), same signature as attempt-6 (×12.07) — still linear.

### 4c. Allocations per scan (counting global allocator; 50 iters; min == median ⇒ deterministic)

```
scenario                 allocs  bytes       attempt-6 baseline
clean / multibyte        3       ~102.5KB    3 / ~102.5KB  (unchanged)
mixed_pan_100kb          17      2.20MB      17 / 2.20MB   (unchanged)
nbsp_100kb               18      4.30MB      18 / 4.30MB   (unchanged — spill churn NOT worsened)
dsoup_dense_dot_100kb    18      4.30MB      18 / 4.30MB   (unchanged)
mixed_nearmiss_100kb     17      2.20MB      new shape, same as mixed
visa_luhnfail_100kb      15      0.63MB      new shape
ambig_incomplete_100kb   17      2.20MB      new shape
mixed_emission_100kb     25653   5.23MB      ≈5 allocs/finding, same class as two_pan
half_glued_100kb         26984   3.18MB      5,389 findings ≈5/finding
two_pan_100kb            27719   3.34MB      27,724 / 3.34MB (unchanged within noise)
```

**Attempt 7 did not worsen allocation churn.** The SepRun spill transient (4.3 MB per 100 KB scan on single-run shapes) is byte-identical to attempt 6; the new emission shapes add only the standard ~5 allocs/finding finding-pipeline cost.

## 5. F1.1 invariant (no Regex::new on scan paths) — PASS

- Static: `Regex::new` appears only in `CompiledEngine::compile` (engine.rs:199 — validation-only compile of the payment-card pattern; 210/213/220 — rule regexes) and `EntropyDetector::compile` (entropy.rs:85), plus the process-wide `OnceLock` `\w` probe initializer (engine.rs:565). None in `scan_inner`, `collect_rule_spans`, `make_finding`, `payment_card_candidate_ranges`, `partition_payment_card_run`, `push_payment_card_segment`, or `regex_word_char`'s steady-state path.
- Runtime: 200 serial scans of clean 100 KB **and** 200 of CJK-stress 100 KB each total **3 allocs/scan** — impossible if any regex (≈3,000+ allocs for `\w`, ≳30 for a rule pattern) were compiled per scan. The probe's one-time compile is visible exactly once (cold scan 3,107 allocs), never again.

## 6. New findings (none blocking)

1. **INFO — new thinnest non-emission margin: max-gap-density ambiguous run.** A 100 KB run of `"9999.9-"` repeated (separator every 5 bytes, kind change every gap, occasional both-sides-complete splits) measures **0.812 p50 / 0.881 p99** — inside the 1 ms/100 KB gate but with only ~13–19 % margin. This is the densest per-byte gap workload the predicate can see; F1.3 should re-measure this exact shape alongside attempt-6's `dsoup_dense_dot` (0.921 p99 here). Not a regression — a new documented corner of the input space.
2. **INFO / cross-post to correctness panel — ambiguous-run alignment sensitivity.** In a long multi-PAN run, a would-be split boundary whose separator KIND equals the previous gap's kind (e.g. Space→Space) does not split even when both sides are complete, shifting the relative digit counts so later boundaries never realign (measured: my first unit design `"4111 1111-1111.1111 4000.0566-5566 5556 "` emits **1 finding per 100 KB** instead of ~5,120; latency unaffected, 0.683 p50). Fail-closed and consistent with the blessed-regex oracle (which also finds 0 there), but precision semantics of dense multi-PAN runs depend on separator-kind sequencing — flagged for the correctness panel's span-semantics review (extends attempt-6 cross-post 5b).
3. **INFO — cold-start cost of the `\w` probe.** The first scan whose boundary check touches a non-ASCII char pays a one-time ~1.7 ms process-wide `Regex::new(r"\w")` (3,107 allocs). Irrelevant to steady-state latency and strictly better than a per-engine-build cost, but worth knowing for the first-request latency story.
4. **INFO — host-noise corroboration of the debug-guard change.** My first probe pass (under 40–48 % CPU contention from concurrent agent processes) showed p99-of-200 spikes 30–300× above p50 (e.g. multibyte max 312 ms vs 0.38 p50) while p50 stayed stable and matched the quiet re-run. This empirically confirms the builder's rationale for asserting p50 (not p99) in debug and for the 2× release CI tolerance; the strict release assertions (p50 < plan budget, p99 < 2×) were re-verified green in §2 with the noisy-host p99 still at 0.764–0.791 < 1.0.
5. **Guard honesty (documented, not load-bearing for this verdict):** every serial p50 and strict-p99 observed here sits under the plan budgets themselves (max non-emission p99 0.921 < 1.0; emission 3.06 < 8), so no CI tolerance softening affects the PASS.

## 7. Severity summary & disposition

| # | Finding | Severity | F1.2 blocker? |
|---|---|---|---|
| 1 | Attempt-6 wins preserved (mixed 0.592/0.642, NBSP 0.616/0.770, multibyte 0.380/0.434 — all ≤ attempt-6) | — | no |
| 2 | New worst cases in-budget: mixed-recovery emission 2.616 p99 @5,120–5,536 findings (8 ms class, 2.9× margin); near-miss 0.866 p99; CJK 0.754 p99 | — | no |
| 3 | Split predicate: O(1)/gap, no rescanning; max-split 0.298 p99, max-gap-density 0.881 p99 (19 % margin — watch in F1.3) | INFO | no |
| 4 | `\w` probe: process-once lazy init (~1.7 ms once, 3,107 allocs), zero per-scan cost (+0.33 ms/100 KB worst-case non-ASCII boundary delta) | — | no |
| 5 | Allocation churn identical to attempt 6 (spill 4.3 MB/100 KB on single-run shapes unchanged); finding pipeline ~5 allocs/finding | — | no |
| 6 | F1.1 holds statically (compile-only Regex::new) and at runtime (3 allocs/scan × 400 scans) | — | no |
| 7 | Debug p50-guard change cannot mask a real regression: medians move under algorithmic slowdown (ceiling trips 7–10×); release still enforces p50 < plan budget strictly + p99 < 2× + strict 5/15 ms p99 | INFO | no |
| 8 | Ambiguous-run separator-kind alignment sensitivity (1-finding collapse on Space→Space boundary) | cross-post | no |

**Verdict: PASS — F1.2 performance/ReDoS panel condition satisfied for attempt 7.** All §5 budgets hold with margin on strict statistics, no threshold was moved, scaling is linear on every class including the new worst cases, allocation behavior is unchanged from attempt 6, and the F1.1 invariant is intact. Repro: `cargo run --release` in `target/audit-probe7/` (raw output `probe7-results.txt`); suites in §2. No repo files edited; §8B loop not triggered by this panel.