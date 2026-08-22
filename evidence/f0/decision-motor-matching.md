# Decision §9 #3 — Matching engine: Vectorscan vs regex/RE2

## Context

The §3 plan recommended Vectorscan (portable fork of Hyperscan) as the high-speed multi-regex
engine, with `regex` crate as plan B. The decision had to be closed in Phase 0 based on the
scan spike data.

## Evidence

### Vectorscan — does not compile on this machine

```
$ cargo build --features vectorscan
error: failed to run custom build command for `vectorscan v0.1.0`
Caused by:
  is 'cmake' not installed?
```

`evidence/f0/raw/scan-vectorscan-attempt.txt` — cmake is not available on the system. The build
script of `vectorscan-sys` requires cmake to compile the native Hyperscan C++ library.
Vectorscan remains a future optimization, activatable via `--features vectorscan`.

### Hybrid engine (Plan B) — meets the budget with margin

Benchmark: 300 patterns, 100 KB payload, 1000 iterations, release profile:

| Engine | scan_p50 | scan_p99 | Throughput | Matches |
|---|---|---|---|---|
| **Hybrid (AC + regex)** | **0.469 ms** | **0.623 ms** | **218.5 mbps** | 227 |
| Pure regex | 158.5 ms | 166.1 ms | 0.65 mbps | 236 |

- **Hybrid vs pure regex: ~335× faster in p50, ~254× in p99**
- **Hybrid p99 = 0.60–0.62 ms stable** (3 runs), well below the 1.0 ms threshold (§5)
- AC overhead with 0 prefixes: **0.088 ms p50** (sub-ms)
- Stability: p50 Δ 10.6%, p99 Δ 10.3% (< 20% / < 50%)
- No ReDoS: patterns without a prefix fall to `RegexSet` (DFA, linear time)

### Precision

Hybrid: 227 matches vs Pure regex: 236 matches (Δ~4%). The difference corresponds to patterns
without a viable literal prefix (e.g. `\d{5}`) that `extract_prefix` cannot extract and that the
AC prefilter does not cover. These patterns go directly to `RegexSet` (unprefixed) and are
scanned the same. There are no structural false negatives — verified in
`spike-escaneo-security-v2.md:73-87`.

## Decision

**Plan B = `regex` crate + Aho-Corasick prefilter** as the MVP matching engine.

| Option | Status | Reason |
|---|---|---|
| **Vectorscan** | ⏭️ Future optimization (NOT committed in MVP) | Does not compile without cmake; plan B meets the budget |
| **RE2** | ❌ Discarded | `regex` crate (native DFA) gives the same result without external dependency |
| **regex crate + AC** | ✅ **SELECTED** | Meets < 1 ms with ~40% margin; no C++ dependencies; guaranteed linear time |

## Decision propagation to future phases

> What "Vectorscan remains a future optimization" means: **the active engine of the MVP is Plan B
> (regex + AC)**. Vectorscan is NOT discarded nor committed in the MVP; it remains a
> **feature-gated optimization lever** (`--features vectorscan`), with a stub that compiles
> without the feature. It is activated ONLY if the conditions below trigger. It is not
> "second round" work.

| Item | What is propagated | Trigger (activation condition) | Phase destination |
|---|---|---|---|
| **Activate Vectorscan** | Replace/augment the AC+regex engine with Vectorscan for the hot path | The scan margin (~1.5× over the < 1 ms budget, §5) erodes: more patterns in rule packs, payloads > 100 KB, or CI/production evidence of p99 scan > threshold | **F1** (if the rule corpus grows when migrating `cerberus-detection-rules.json`) or **F7** (if a new rule pack requires it). Requirement: install `cmake` and verify latency vs budget with the F0 spike |
| **Bound post-AC window** | In `engine_hybrid.rs`, limit `shortest_match` to 128–1024 B after a prefix hit to avoid superlinear amplification O(N_hits × L_payload) | None — known 🟠 Medium security/CPU DoS risk | **F1** (mandatory, along with ReDoS fuzzing of prefixed patterns) |
| **Prefixed-route ReDoS fuzzing** | Fuzzing with patterns that DO have a literal prefix + non-matching payloads (not only the 3 unprefixed ReDoS patterns from F0) | None — §5 "No ReDoS" requirement | **F1** |
| **Monitor scan p99 in CI** | Hybrid bench 300 patterns / 99 KB in the CI pipeline, alert if p99 > 1 ms | None — the scan is the limiting constraint of the system | **F1** (from the first rule integration) |

Related risk: the ~1.5× scan margin is the **limiting constraint** (proxy has ≥ 18×).
See the full propagation table in `evidence/f0/budget-validation.md`.

## Key numbers

- **Hybrid scan p99:** 0.60–0.62 ms (§5 budget: < 1.0 ms)
- **Relative speed vs pure regex:** 335× (p50)
- **Throughput:** 212–218 mbps @ p50
- **Pattern compilation:** 10.3 ms (300 patterns, once at startup)
- **AC prefilter overhead (0 prefixes):** 0.088 ms

## References

- `evidence/f0/spike-escaneo-performance-v2.md` — performance review
- `evidence/f0/spike-escaneo-fix.md` — fixer implementation
- `evidence/f0/spike-escaneo-security-v2.md` — security verification (ReDoS, unsafe)
- `evidence/f0/raw/fix-bench-hybrid.json` — raw data hybrid
- `evidence/f0/raw/scan-vectorscan-attempt.txt` — failed attempt to compile Vectorscan
- `evidence/f0/raw/fix-bench-regex.json` — raw data pure regex
