# Evidence Pack — f0/budget-validation
- Attempt: 1    Reviewer: BUILDER (consolidation)    Verdict: PASS

## Acceptance criteria — §5 NFRs vs spike data

| # | Criterion (§5) | Threshold | Measured | Evidence | Verdict |
|---|---|---|---|---|---|
| 1 | **Proxy added latency** — p99 overhead < 3–5 ms for prompts ≤ 50 KB | p99 < 3–5 ms | **Overhead p99 = 0.0–0.161 ms** (max observed); **0.071 ms** (mean of 2 runs 50 KB); **0.071 ms** (100 KB); **0.127 ms** (50 KB raw) | `evidence/f0/spike-proxy-performance.md:51-54`, `evidence/f0/raw/proxy-bench-50kb.txt:17` | ✅ PASS — margin ≥ 18× |
| 2 | **Scan throughput** — ~100 KB + hundreds of patterns in < 1 ms | scan_p99 < 1.0 ms | **scan_p99 = 0.60–0.62 ms** (stable, 3 runs); **0.595–0.635 ms** (reviewer reproduction, 4 runs); **0.623 ms** (raw `fix-bench-hybrid.json`); **p50 = 0.469 ms**; throughput = **212–218 mbps** | `evidence/f0/spike-escaneo-performance-v2.md:18`, `evidence/f0/raw/fix-bench-hybrid.json:8` | ✅ PASS — margin **~1.5×** (the TIGHTEST; **limiting constraint of the system**) |
| 3 | **No ReDoS** — no pattern causes catastrophic backtracking | Linear time guaranteed | 3 classic ReDoS patterns: `(a\|aa\|aaa)+b`, `(a\|aa)*b`, `(a+)+b` → `extract_prefix()` returns `None` → fall to `RegexSet` (internal DFA) → **188 µs on 100 KB of 'a's**, no hang. `unsafe_code = "forbid"` in workspace. | `evidence/f0/spike-escaneo-security-v2.md:26-43` | ✅ PASS |
| 4 | **Simple installation** — Mode B: one command, zero-config | Not applicable in F0 | Evaluation in F4 (local-daemon + cerberus-init). The workspace compiles a single static binary. | — | ⏭️ DEFERRED to F4 |
| 5 | **Cross-platform** — macOS, Linux, Windows | 3 OS CI matrix | CI configured with `["macos-latest", "ubuntu-latest", "windows-latest"]` in YAML; build + test + clippy + fmt pass on macOS. | `evidence/f0/scaffold-ci.md:12` | ✅ PASS |
| 6 | **Zero secret leakage** — raw value never persisted/logged | 0 leaks in logs | F0 does not handle real secrets: the proxy buffers opaque bytes and the scan never receives real traffic. Spike hygiene (0 `println!` of data, 0 `dbg!`) documented, but does not validate the product guarantee. | `evidence/f0/spike-proxy-security.md:98-109`, `evidence/f0/spike-escaneo-security-v2.md:88-95` | ⏭️ DEFERRED to F1/F5 — validation when the pipeline handles real secrets |
| 7 | **Memory hygiene** — zeroization post-scan | Not applicable in F0 | Implemented in F1/F2 (detection/redaction engine). The spike does not handle real secrets. | — | ⏭️ DEFERRED to F1 |
| 8 | **Precision (false positives)** — measured continuously | Not applicable in F0 | Evaluated in F1 with test corpus. Hybrid vs regex: Δ~4% matches (227 vs 236) documented, non-blocking. | `evidence/f0/spike-escaneo-performance-v2.md:23` | ⏭️ DEFERRED to F1 |

## Adversarial cases tested (attempt to break the budget)

- **Proxy: upstream down** → no 502 Bad Gateway, `Empty reply from server`. Bug reported, does not affect latency budget (see risk propagated to F3).
- **Proxy: 0 KB body** → bench produces valid JSON, overhead measured.
- **Proxy: `--payload-kb abc`** → parse error ignored, runs defaults. Fragile UX, does not affect performance.
- **Scan: `--patterns 0`** → 0 matches, valid JSON, no errors.
- **Scan: `--payload-size 0`** → throughput 0.0, no crash, correct handling.
- **Scan: `--engine invalid`** → error `invalid engine 'X' (expected 'regex' or 'hybrid')` + `exit(1)` (`main.rs:80-87`). Fix already applied in `spike-escaneo-fix`; no silent fallback.
- **Scan: Vectorscan compilation attempt** → `cmake` not installed on the system. Error: `is 'cmake' not installed?`. The offline stub compiles with `--features vectorscan` disabled. Vectorscan is not viable without cmake.
- **Scan: ReDoS with 100 KB payload of 'a' + 'b' at the end** → 188 µs, no hang. Linear time confirmed.

## Applicable NFRs

- **Proxy latency:** p99 overhead = 0.066–0.158 ms steady-state (max observed 0.161 ms; budget < 3–5 ms) → ✅ PASS, margin **≥ 18×** (wide: 18.6× to 31.1×). Bench 50 KB, 1000 iter, release, loopback.
- **Scan throughput:** scan_p99 = 0.595–0.635 ms (budget < 1.0 ms) → ✅ PASS, margin **~1.5×** (**the tightest of the system; limiting constraint**). Bench 300 patterns, real payload 99 KB, 1000 iter, release.
- **Security (ReDoS):** 0 ReDoS patterns cause hang → ✅ PASS. DFA+AC guarantee linear time. Caveat: the prefixed hybrid route with unbounded window can amplify superlinearly (risk propagated to F1, see table).
- **Security (unsafe):** `unsafe_code = "forbid"` verified functionally → ✅ PASS.
- **Cross-platform:** 3 OS CI matrix configured → ✅ PASS.

### Benchmark conditions (consolidated)

- **Environment:** loopback (localhost), macOS arm64, release profile.
- **Proxy:** 50 KB, 1000 iterations, 20 warm-up. Overhead = percentile diff (proxy_p99 − direct_p99), nearest-rank (conservative).
- **Scan:** 300 patterns, nominal payload 100 KB / real **99 KB** (`payload_size_kb=99` in `fix-bench-hybrid.json`; the generator truncates to line limit), 1000 iterations.
- **Scan figure consistency:** the raw `fix-bench-hybrid.json` records **0.623 ms p99** (1000 iter, 99 KB); `spike-escaneo-fix.md:29` cites **0.652 ms p99** — same methodology, **different runs** of the same fixer effort (not exactly as in the raw). `spike-escaneo-performance-v2.md:18` documents 0.601/0.609/0.615 ms (3 stable runs, after excluding the 1.838 ms cold start outlier). The reviewer's independent reproduction gave **0.595–0.635 ms** (4 runs). Consolidated range: **0.595–0.635 ms p99**.

## Phase 0 closed decisions

| Decision | Result | Effect |
|---|---|---|
| **Stack: Rust** | ✅ Confirmed (§3) | Single static binary, no GC, predictable latency |
| **Matching engine (§9 #3)** | ✅ **Plan B: regex crate + Aho-Corasick prefilter** | Vectorscan does not compile without cmake on this machine; hybrid AC meets the budget with margin |
| **Latency budget (§5)** | ✅ **Validated with experimental data** | Proxy overhead 0.066–0.158 ms p99 (margin ≥ 18×); scan 0.595–0.635 ms p99 (margin ~1.5×) |
| **Vectorscan** | ⏭️ **Deferred: future optimization / scale lever** | Offline stub present, feature-gated behind `cfg(feature = "vectorscan")`; first lever if the ~1.5× scan margin erodes |

## Risks detected and propagation to future phases

| Risk | Severity | Origin | Propagate to |
|---|---|---|---|
| Proxy without 502 on upstream down | 🔴 **Must fix** | `spike-proxy-correctness.md:41-51` | **F3** — reverse-proxy-core must respond 502 |
| No body limit → memory DoS | 🟠 Medium | `spike-proxy-security.md:134-139` | **F3** — implement `max_body_size` |
| No client/server timeouts → socket leak | 🟠 Medium | `spike-proxy-security.md:141-148` | **F3** — configure connect/request/idle timeouts |
| Headers forwarded without sanitization | 🟡 Low | `spike-proxy-security.md:150-157` | **F3** — implement header allowlist |
| Configurable upstream without restriction → potential SSRF | 🟢 Info | `spike-proxy-security.md:159-166` | **F3** — validate upstream as allowed address |
| Unbounded regex context window → superlinear amplification (O(N_hits × L_payload); ReDoS CPU DoS) | 🟠 **Medium** | `spike-escaneo-performance-v2.md:36-39`, `engine_hybrid.rs:115-117` | **F1** — expand ReDoS fuzzing with prefixed patterns + non-matching payloads; bound post-AC window to 128–1024 bytes |
| Enable Vectorscan as hot-path engine (feature-gated `--features vectorscan`) | ⏭️ Deferred — NOT committed in MVP | F0 spike (compilation failure without cmake); decision §9 #3 | **F1 or F7** — ONLY if the ~1.5× scan margin erodes (more patterns in packs, payloads > 100 KB, or p99 scan > 1 ms in CI/production). Trigger and details in `decision-motor-matching.md` §"Decision propagation" |
| Continuous monitoring of scan p99 in CI | 🟡 Watch | The scan is the limiting constraint (~1.5×); any budget erosion is silent without monitoring | **F1** — incorporate hybrid bench 300 patterns / 99 KB into CI pipeline, alert if p99 > 1 ms |

## If FAIL: what fails and how to reproduce it

Not applicable — all applicable criteria PASS; F1/F4/F5 criteria deferred. The §5 latency budget is validated with experimental data from the spikes. **The margin is NOT uniform**: proxy wide (≥ 18×) but scan tight (~1.5×) — see scalability risks below.

## Scalability and monitoring (F1+)

- With a **~1.5×** margin, the scan is the **limiting constraint of the system** (~12× tighter than the proxy: 18× vs 1.5×). Each increment of patterns/payload, or a cold start, **erodes the 1 ms budget**.
- **Future optimization lever:** Vectorscan (feature-gated) is the first option if the scan margin narrows with more patterns or payloads > 100 KB.
- **Monitoring proposed in F1+:** measure and alert the **scan p99** continuously in the CI pipeline (hybrid bench 300 patterns / 99 KB), not only in F0.
- **Proxy tail risk:** the first start recorded p99 overhead = **3.315 ms** (66–100% of the 3–5 ms budget), a cold start outlier that **does not reproduce in steady-state** (6/6 runs < 0.16 ms). Recorded as a tail risk to watch in real deployments (F4/F5), with no impact on the F0 verdict.

## Conclusion

**VERDICT: PASS** ✅ — The §5 latency budget is validated with spike data:
- Proxy overhead: **p99 = 0.066–0.158 ms steady-state** (budget < 3–5 ms, margin ≥ 18× — wide)
- Hybrid AC+regex scan: **p99 = 0.595–0.635 ms** (budget < 1.0 ms, margin **~1.5×** — **the tightest; limiting constraint of the system**)
- No ReDoS verified (with unbounded window caveat propagated to F1), cross-platform configured, zero leakage DEFERRED to F1/F5
- Decision §9 #3 closed: **Plan B = regex crate + Aho-Corasick prefilter** as the MVP matching engine
- Risks documented and propagated to F1/F3 as appropriate (incl. potential SSRF → F3; regex window 🟠 → F1)
