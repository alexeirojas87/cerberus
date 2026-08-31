# Evidence Pack — F1.3 / R9 engine throughput

- Unit: F1.3 throughput del engine
- Attempt: 5 (FIX of attempt-4 FAIL)
- Builder status: **FIX executed — 5/5 stability series PASS; returns to VERIFY**
- Independent review: **PENDING** — the builder did not review its own work
- Unit final status: **OPEN — awaiting the independent correctness/security/performance panel**
- Base `HEAD`: `fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7`
- Branch: `docs/fix-install-commands` (dirty shared worktree; no commit, push, tag or release action)
- Date: 2026-08-31
- Host: macOS 26.5.1 (build 25F80), arm64, Apple M4 Pro, 12 logical CPUs, 24 GiB RAM
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, host `aarch64-apple-darwin`, LLVM 22.1.6; `cargo 1.97.1 (c980f4866 2026-06-30)`

This is builder evidence. Under §8B, F1.3 cannot be closed by this document alone: latency/detection-engine work requires a fresh correctness/security/performance panel and a majority PASS, followed by the F1 integration reviewer.

## What FIX attempt 5 changed

Two independent root causes from the attempt-4 failure analysis were repaired:

1. **Gate methodology (tests/load_test.rs).** The perf diagnosis showed the gate computed the p99 of 1,000 batch means (8 scans averaged per observation), not the p99 of the 8,000 individual scans the §5 "< 1 ms" budget speaks about. Batch averaging suppresses exactly the individual-scan tail the budget constrains, so intermittent contention failures could surface as borderline batch p99 while individual scans were slower. The gate now measures **8,000 individual scans per scenario** (`samples=8000`, `scans_per_sample=1`), one `Instant::now()` pair per scan, no trimming or retry. Warm-up (100 scans), workload, fingerprints and the strict `p99 < 1.0 ms` budget are unchanged.
2. **Engine redundant work (crates/cerberus-engine/src/engine.rs, entropy.rs).** A `sample(1)` profile of the gate showed three separate full-text Aho-Corasick passes per scan: the prefix presence automaton (`find_overlapping_iter`), the entropy keyword prefilter (`EntropyDetector::detect_near_keywords`) and the context-keyword prefilter (`context_keywords_may_match`); together roughly a quarter to a third of scan-path samples. The engine now builds **one case-insensitive presence automaton** over literal prefixes + entropy keywords + non-empty ASCII contextual keywords (bucketed by pattern id) and answers all presence questions in a single full-text pass. The entropy detector runs its keyword regex directly when the merged pass proved keyword presence and is skipped entirely on proven absence; on the `scan()` path (context == text buffer) the context-analyzer decision is answered from the same pass.

**Findings are provably unchanged.** Presence proofs are one-way — a miss proves absence, a hit may be a false positive that the per-pattern regex or analyzer later rejects. Case-insensitive matching only admits a superset of hits (a case-variant prefix marks presence, the case-sensitive regex then rejects it), so it can only skip less work, never add or drop findings. The context path preserves the non-ASCII conservative fallback exactly; the FIX itself was corrected once when the existing test `context_prefilter_unicode_fallback_preserves_casefold_and_boundaries` caught a dropped non-ASCII-context branch during development, and the full engine suite (232/232, including multiline state reuse and the 10,000 randomized payment-card oracle) plus the 659-test workspace matrix below pass on the frozen code. `scan_with_context` (separate context buffer) keeps its own prefilter scan over `context`; workload fingerprints are unchanged because rules and payload bytes are unchanged.

## Acceptance criteria

| Criterion | Command/evidence | Builder result |
|---|---|---:|
| Scan exactly 100 KiB | Gate asserts `payload.len() == 102400`; emitted `payload_bytes=102400` for both scenarios | PASS |
| Exact shipped default pack | `load_bench_rules()` parses `cerberus_packs::default_pack::DEFAULT_PACK_JSON`; product identity is `sha256:cc2999f03792194f9aea73763fd8b4831b48d5564400546ba90a465556411379`, 15 rules/15 patterns | PASS |
| Maximum supported MVP overlay with hundreds of patterns | Gate asserts 256 custom rules equals `detection_policy::MAX_CUSTOM_RULES`; effective policy is default + 256 non-colliding rules, two unique patterns each: 271 rules/527 patterns | PASS |
| Stable workload identity | Default fingerprint `sha256:b632f5a659f81185f92304beff08f8bb4c60c1e9f20fbfd1df0aa1d386f5220f`; maximum-policy fingerprint `sha256:40884edfb6bca9e2200e1975cbc4108cdae81d3a175304fb6d6c659bce7b5992`; both are asserted and unchanged by attempt 5 (no rule/payload byte moved) | PASS |
| Warm-up and at least 1,000 samples | 100 warm-up scans; **8,000 individual scan observations** per scenario | PASS |
| p50/p95/p99 reported | Release output emits all three percentiles over individual scans, workload cardinality, sample configuration, fingerprint and verdict | PASS |
| Closed gate `p99 < 1 ms` | Five consecutive post-FIX runs passed under individual-scan timing; worst observed p99 default **0.525125 ms**, maximum policy **0.464291 ms** | PASS (5/5, pending independent re-run) |
| No threshold movement | `F1_3_P99_BUDGET_MS = 1.0`; assertions use strict `<`; no tolerance/retry/skip path in release | PASS |
| Correctness and quality matrix | engine release 232/232; load suite release 13/13; workspace 659/659; fmt/clippy/diff checks clean | PASS |

## Benchmark design and workload honesty

The timed region contains only steady-state `CompiledEngine::scan`; policy parsing and engine compilation are deliberately outside it because §5 calls this an engine throughput micro-benchmark, not a policy-build benchmark. Every scan result is passed through `black_box`. A correctness scan before timing asserts the clean payload produces zero findings in each scenario.

Each percentile observation is one complete individual scan (8,000 observations per scenario). The earlier 8-scan batch-mean arithmetic was removed in attempt 5 after the perf diagnosis showed it hides the individual-scan tail the budget constrains. There is no sample deletion, outlier trimming, percentile substitution or automatic retry.

The maximum-policy workload is the largest MVP overlay by the closed rule-count limit: 256 custom rules, added without flag collisions to the exact 15-rule default pack. Each synthetic rule has two distinct literal-prefixed patterns, producing 527 total patterns. `DetectionPolicy` does not define a separate finite total-pattern cap, so this evidence does not claim that 527 is a mathematical maximum of arbitrary patterns per rule; it is the maximum supported rule combination with the required hundreds-of-patterns shape.

Runner control: release profile, one Rust test thread, one process, serialized in-process performance tests via `perf_lock`, fixed payload/rules/fingerprints, and warm-up before measurement. No CPU affinity or elevated priority was used; residual tail sensitivity is disclosed below.

## Latest release benchmark (PASS sample, not the unit verdict)

```console
$ rtk proxy cargo test --release --test load_test load_test_f1_3_engine_throughput_gate -- --nocapture --test-threads=1
running 1 test
f1_3_engine_throughput scenario=default profile=release payload_bytes=102400 rules=15 patterns=15 warmup_scans=100 samples=8000 scans_per_sample=1 measured_scans=8000 fingerprint=sha256:b632f5a659f81185f92304beff08f8bb4c60c1e9f20fbfd1df0aa1d386f5220f p50_ms=0.181125 p95_ms=0.232291 p99_ms=0.494833 strict_p99_budget_ms=1.0 result=PASS
f1_3_engine_throughput scenario=max_mvp_policy profile=release payload_bytes=102400 rules=271 patterns=527 warmup_scans=100 samples=8000 scans_per_sample=1 measured_scans=8000 fingerprint=sha256:40884edfb6bca9e2200e1975cbc4108cdae81d3a175304fb6d6c659bce7b5992 p50_ms=0.264500 p95_ms=0.278542 p99_ms=0.326166 strict_p99_budget_ms=1.0 result=PASS
test result: ok. 1 passed; 0 failed; 12 filtered out
```

### Five-run post-FIX stability series (frozen attempt-5 code)

All five serial invocations exited 0. Values are milliseconds per individual scan.

| Run | Default p50 | Default p95 | Default p99 | Maximum p50 | Maximum p95 | Maximum p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.177625 | 0.186666 | 0.202000 | 0.260916 | 0.272541 | 0.286667 |
| 2 | 0.177208 | 0.186167 | 0.204541 | 0.262417 | 0.277625 | 0.328709 |
| 3 | 0.177708 | 0.186292 | 0.216083 | 0.262792 | 0.272083 | 0.284042 |
| 4 | 0.179417 | 0.241458 | 0.525125 | 0.262917 | 0.288583 | 0.354750 |
| 5 | 0.177959 | 0.189250 | 0.202708 | 0.262500 | 0.288542 | 0.464291 |

Medians are stable to within ~2 µs across runs (0.177–0.179 default, 0.261–0.263 maximum). Runs 4 and 5 show residual environment tail (single-run p99 up to 0.525/0.464 ms) — the same contention signature that defeated attempts 1–4, now absorbed by ~2–2.9× lower per-scan medians instead of by batch averaging. The panel should re-verify on a quiet runner and under deliberately introduced contention.

## Failed attempts retained and repair

1. **Attempt 1 FAIL.** The pre-existing draft timed one scan per observation. Repeated serial runs exposed a maximum-policy `p99=1.038667 ms` failure even though p50 was 0.550125 ms. The first filtered invocation also exited 101; its detailed output was not available, so it is not promoted as quantified evidence.
2. **Attempt 2 FAIL.** Transparent 8-scan batches reduced normal timer noise but did not fix sustained contention: one of five runs reported default p50/p95/p99 0.521718/0.566843/0.593390 ms and maximum 0.549390/0.756250/**1.142078 ms**. No retry or threshold change was accepted as a fix.
3. **Attempt 3 FAIL after provisional PASS.** The engine now associates literal-prefixed multiline regexes with the already-built Aho-Corasick presence prefilter. A prefixed multiline regex is still compiled once with `(?m)` and retains the same finding path, but a clean payload lacking that prefix no longer incurs its full-text regex scan. Full engine tests, including multiline state reuse and 10,000 randomized payment-card oracle trials, passed. Median throughput improved from roughly 0.52/0.55 ms to 0.44/0.46 ms and 5/5 serial gate runs passed. A later final verification nevertheless failed: default p50/p95/p99 0.436583/0.467677/0.494510 ms; maximum 0.457385/0.559890/**1.075994 ms**. Exact reproduction is the focal release command above; it exited 101 at `tests/load_test.rs:715`.
4. **Attempt 4 FAIL.** The payment-card matcher gained a cheap no-digit fast exit so clean payloads do not execute its branch-heavy candidate loop. Engine release remained 232/232, Clippy/fmt/diff remained clean, and the next gate run passed at default 0.433187/0.451317/0.565448 ms and maximum 0.448776/0.461135/0.483968 ms. One PASS after a known intermittent failure is insufficient evidence of a stable strict-p99 gate. No further threshold, retry, outlier or workload manipulation was made.
5. **Attempt 5 FIX (this pack).** Root causes addressed per the attempt-4 failure analysis and the two diagnosis threads: (a) the gate now times 8,000 individual scans, removing the batch-mean tail-hiding the perf diagnosis identified; (b) the engine's three full-text presence passes (prefix AC, entropy keyword prefilter, context-keyword prefilter) were merged into one case-insensitive pass with per-bucket pattern ids, removing two redundant 100 KB byte scans per call on the `scan()` path. Findings provably unchanged (one-way presence proofs; regexes and analyzer unchanged); the development-time regression in the non-ASCII context branch was caught by `context_prefilter_unicode_fallback_preserves_casefold_and_boundaries` and repaired before freezing. Result: 5/5 stability series PASS with worst p99 0.525/0.464 ms under individual-scan timing.

## Verification matrix

```console
$ rtk cargo fmt --all -- --check
exit 0

$ rtk cargo clippy --workspace --all-targets -- -D warnings
cargo clippy: No issues found

$ rtk cargo test -p cerberus-engine --release
cargo test: 232 passed (4 suites, 0.03s)

$ rtk proxy cargo test --release --test load_test load_test_f1_3_engine_throughput_gate -- --nocapture --test-threads=1
5 consecutive runs: exit 0 (series table above)

$ rtk cargo test --release --test load_test -- --test-threads=1
cargo test: 13 passed (1 suite, 5.56s)

$ rtk cargo test --workspace
cargo test: 659 passed (34 suites, 54.17s)
```

Final diff hygiene is recorded after creating this Evidence Pack:

```console
$ rtk git diff --check
exit 0
```

## Frozen implementation hashes

```text
66679c8abbc3e2355a31161afa0fdba045acacb99f40c1f9903ee6b828fd5610  crates/cerberus-packs/src/default_pack.rs
cb13bf7ed280c4298657cd6db063d270801ed925eb5c5e3cf97bb3f91461db15  tests/load_test.rs
1862da84da1963e88c2d0111c5b171e420fbff0a459c650693e66e768dd9478d  crates/cerberus-engine/src/engine.rs
55a10e6227f5c18a860edc3bbff07582326d4d38539a2415eafe977467d97be1  crates/cerberus-engine/src/entropy.rs
2eca99c366fca939a774427229c487c429cf66bfb48006adb67104916457e9e2  Cargo.toml
9a25f03506aa20d92b52a9b1882a5055d1bfe9bd53ee95fc9c9d329188b99f17  Cargo.lock
```

The product report independently binds the exact embedded `DEFAULT_PACK_JSON` bytes as `sha256:cc2999f03792194f9aea73763fd8b4831b48d5564400546ba90a465556411379` (pack version 1.2.3, 15 rules).

## Builder verdict and independent-review focus

**Builder verdict: FIX executed — the unit returns to VERIFY.** Both attempt-4 root causes (batch-mean tail hiding; redundant full-text presence passes) are repaired with evidence, and the 5/5 stability series plus the full quality matrix pass on the frozen code. Under §8B the builder cannot close its own unit: the independent panel must re-run the gate and attempt to break the claims below before F1.3 can be marked PASS.

The independent panel should specifically try to break:

- the merged case-insensitive presence automaton: prove any workload where a finding appears, disappears, moves, or changes span versus the pre-FIX engine (prefix/entropy/context buckets, `scan`, `scan_with_context`, `scan_with_context_analyzer`, JSON leaf redaction);
- the claim that case-insensitive presence can only *weaken* proofs (mixed-case prefix/keyword payloads; Unicode case-folding edges such as U+0130);
- the same-buffer `scan()` decision (context == text) versus the separate-buffer `scan_with_context` path, including non-ASCII contexts;
- the workload fingerprints and exact `DEFAULT_PACK_JSON` identity (must be byte-identical to pre-FIX);
- individual-scan percentile arithmetic and the absence of hidden retries/outlier deletion;
- multiline correctness for prefixed and unprefixed multiline patterns after the prefilter reuse;
- stability on a fresh, quiet release runner and under deliberately introduced contention (the 5/5 series above was captured on the shared host without isolation).

F1.3 remains open until the panel verdict and the F1 integration reviewer sign-off.

