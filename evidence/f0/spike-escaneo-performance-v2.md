# Evidence Pack — f0/spike-escaneo-performance-v2
- Attempt: 2    Reviewer: REVIEWER 2 (performance)    Verdict: PASS (with 1 observation)

## Configuration
- Machine: macOS (darwin), release profile
- Commits applied: attempt 2 of spike-escaneo (includes F2 fix: AC prefilter + p50 throughput)

## 1. Build
`cargo build --release --workspace 2>&1` → ✅ OK, 0 errors, `Finished release [optimized] in 5.42s`

## 2. Full bench (hybrid) — 300 patterns, 100 KB, 1000 iter
- 1st run (cold start): `scan_p50_ms=0.494`, `scan_p99_ms=1.838`, `throughput_mbps=207.4`, 227 matches
- 3 subsequent runs (stable):
  - run1: p50=0.484, p99=0.601, tp=211.8
  - run2: p50=0.483, p99=0.609, tp=211.9
  - run3: p50=0.483, p99=0.615, tp=212.0

**Stable p99 ≈ 0.60-0.62 ms < 1.0 ms ✅** (the p99=1.838 from the first run is a cold start outlier; 3 subsequent runs confirm sub-ms).

## 3. Comparative bench (pure regex) — 300 patterns, 100 KB, 200 iter
`--engine regex`: p50=158.281, p99=161.327, throughput=0.647 mbps, 236 matches
- Very slow as expected (~158-161 ms). **Hybrid vs pure regex difference ≈ 320× in p50.** ✅
- Note: matches diff (227 vs 236, Δ~4%) — the hybrid loses some recall due to patterns without a viable literal prefix; already documented in `spike-escaneo-fix.md`, not blocking for the performance budget.

## 4. Stability — hybrid, 50 patterns, 10 KB, 100 iter, 2 runs
| Metric | runA | runB | Variation |
|---|---|---|---|
| p50 | 0.052 ms | 0.047 ms | **10.6%** (< 20% ✅) |
| p99 | 0.064 ms | 0.058 ms | **10.3%** (< 50% ✅) |

## 5. Prefilter overhead — 0 patterns, 100 KB, 100 iter
`scan_p50_ms=0.088`, `scan_p99_ms=0.093`, `throughput_mbps=1161.4`
- **AC overhead with 0 prefixes ≈ 0.09 ms (sub-ms) ✅**. The residual cost is the empty RegexSet regex scan over 100 KB.

## 6. Context window (code review) — `engine_hybrid.rs`
- **There is no bounded window**: `shortest_match(&payload[m.start()..])` scans from the prefix hit **to the end of the payload** (engine_hybrid.rs:115-117).
- **Impact**: correct (never loses matches), and at 100 KB/300 patterns it remains sub-ms because `shortest_match` cuts as soon as there is a match. But at large payloads (>1 MB) the cost can grow superlinearly.
- **Observation (non-blocking for F0)**: bounding the window to 128-1024 bytes after the hit would avoid degradation on large payloads (relevant to §5 "≤ 50 KB" today is ok, but watch out in future phases).
- Precision note: `\bkey\b` extracts prefix "key" (extract_prefix preserves the `\b` boundaries) — the AC will match "key" as a substring, and the subsequent regex verifies the boundary. A small window would not affect this case because the AC hit is already in the correct position.

## 7. Throughput (code review) — `main.rs`
- `BenchResult::from_timings` uses `percentile(timings, 50.0)` for throughput (main.rs:210-214), **not mean** ✅ (F2 fix confirmed).
- p50 and p99 both derived from percentiles; `round_val` rounds to 3 decimals.

## Comparison against §5 budget
| §5 requirement | Threshold | Measured | Status |
|---|---|---|---|
| Scan ~100 KB + hundreds of patterns < 1 ms | scan_p99 < 1.0 ms | **p99 ≈ 0.60-0.62 ms** (cold: 1.84 outlier) | ✅ |
| Pure regex comparison | Must be VERY slow | p50 ≈ 158 ms | ✅ (320× worse) |
| Stability | p50 Δ<20%, p99 Δ<50% | p50 Δ10.6%, p99 Δ10.3% | ✅ |
| AC overhead without prefixes | sub-ms | 0.088 ms p50 | ✅ |
| Throughput with p50 | p50 (not mean) | 212 mbps @ p50 | ✅ |

## Verdict
**PASS** — the hybrid engine (AC prefilter + regex) meets the §5 budget with a ~40% margin over the 1 ms threshold. One observation for future phases: bound the regex context window after the AC hit in `engine_hybrid.rs` to protect against large payloads (>1 MB). Not blocking for F0.
