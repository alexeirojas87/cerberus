# Evidence Pack — f0/budget-validation (REVIEWER 1 · correctness · v2)
- Attempt: 2    Reviewer: REVIEWER 1 (correctness, independent)    Verdict: **PASS**
- Date: 2026-08-16    Worktree: `cerberus-wt-f0-budget-rv2-correctness`
- Subject: review of the corrected doc `evidence/f0/budget-validation.md` (commit `7c2e4e4`)

---

## Verdict

**PASS** ✅ — The fixer's corrections (7c2e4e4) close all findings from
the security rv1 review and the performance rv1 review. The cited numbers are
consistent with the raw data and with independent reproductions. No internal
contradictions. Decision §9 #3 remains well supported.

---

## 1. Numerical verification — cited numbers vs raw

### 1.1 Proxy p99 overhead (steady-state 0.066–0.158 ms)

| Cited figure (doc) | Raw value / source | Matches? |
|---|---|---|
| "0.066–0.158 ms steady-state" (L30,77) | Reviewer rv1 reproduction: 6 runs = 0.066, 0.072, 0.076, 0.076, 0.100, 0.158 ms | ✅ |
| "max observed 0.161 ms" (L30) | `spike-proxy-performance.md:41` — 0.161 ms from a previous run | ✅ |
| "0.127 ms (50 KB raw)" (L8) | `raw/proxy-bench-50kb.txt:16` — overhead p99 = 0.127667 | ✅ (value; cites line 17, off-by-one, see §4) |
| "0.071 ms (mean of 2 runs 50 KB)" (L8) | `spike-proxy-performance.md:40` — RUN1=0.000, RUN2=0.142 → mean 0.071 | ✅ |
| "0.071 ms (100 KB)" (L8) | `raw/proxy-bench-100kb.txt` — overhead p99 = 0.071459 | ✅ |
| "0.0–0.161 ms (max observed)" (L8) | Full range incl. run clipped to 0 (RUN1) and max 0.161 | ✅ |

### 1.2 Proxy margin ≥ 18×

- `3 ms / 0.161 = 18.6×`; `5 ms / 0.161 = 31.1×` → doc declares "18.6× to 31.1×" and "≥ 18×". ✅

### 1.3 Scan p99 (0.595–0.635 ms)

| Cited figure (doc) | Raw value / source | Matches? |
|---|---|---|
| "0.595–0.635 ms (reviewer reproduction, 4 runs)" (L9,41) | Reviewer rv1: 0.595, 0.610, 0.624, 0.635 ms | ✅ |
| "0.623 ms (raw fix-bench-hybrid.json)" (L9,41) | `raw/fix-bench-hybrid.json` — scan_p99_ms = 0.623 | ✅ (value; cites line 8, off-by-one, see §4) |
| "p50 = 0.469 ms" (L9) | `fix-bench-hybrid.json` — scan_p50_ms = 0.469 | ✅ |
| "throughput = 212–218 mbps" (L9) | raw hybrid = 218.548; reviewer rv1 scan = 211.5–213.1 | ✅ |
| "0.60–0.62 ms (stable, 3 runs)" (L9) | `spike-escaneo-performance-v2.md:14-16` — 0.601/0.609/0.615 | ✅ |
| "0.652 ms (spike-escaneo-fix.md:29)" (L41) | `spike-escaneo-fix.md:29` = 0.652; not exactly in raw — the doc explicitly declares it as "different runs" | ✅ (correct transparency) |

### 1.4 Scan margin ~1.5×

- `1.0 / 0.623 = 1.60×`; `1.0 / 0.652 = 1.53×` → "~1.5×" ✅ (L9,31,78)

### 1.5 Payload 99–100 KB

- `fix-bench-hybrid.json` records `payload_size_kb: 99` (nominal `--payload-size 100`, the generator truncates to the line limit). Doc L31,40 declares it as "real payload 99 KB / nominal 100 KB". ✅

### 1.6 Other figures

- Proxy cold outlier p99 = 3.315 ms (L72) — `budget-validation-review-performance.md:40` ✅
- ReDoS 188 µs on 100 KB of 'a's (L10) — `spike-escaneo-security-v2.md:39` ✅
- "6/6 runs < 0.16 ms" (L72) — reviewer rv1: runs B–G = 0.066–0.158, all < 0.16 ✅
- "~12× tighter" (L69): 18.6/1.6 ≈ 11.6 ≈ 12 ✅

---

## 2. Verification of the fixer's corrections

| Required correction | Status in doc v2 | Applied? |
|---|---|---|
| "Zero leakage" PASS → DEFER | L13: `⏭️ DEFERRED to F1/F5` + justification (F0 does not handle real secrets) | ✅ |
| SSRF in risks table → F3 | L60: row "Configurable upstream without restriction → potential SSRF \| 🟢 Info \| ...spike-proxy-security.md:159-166 \| **F3**" | ✅ |
| `--engine invalid` stale removed/updated | L24 adversarial case updated to "error `invalid engine 'X'` + `exit(1)` (main.rs:80-87)"; row removed from risks table | ✅ — verified against code: `main.rs:80-87` does `eprintln!` + `std::process::exit(1)` (commit 7f5cfb6) |
| Regex window severity 🟠 Medium | L61: `🟠 **Medium**` with explicit risk (O(N_hits × L_payload), ReDoS CPU DoS) + expanded F1 action (fuzzing with prefixed patterns + bound window 128–1024 B) | ✅ |
| Scan margin as limiting constraint | L9, L31, L69, L78: "the TIGHTEST / limiting constraint of the system", "~12× tighter than the proxy" | ✅ |
| Bench conditions (loopback, macOS arm64) | L38: "loopback (localhost), macOS arm64, release profile"; L39-40 proxy/scan detail | ✅ |
| Scalability/monitoring section | L67-72: Vectorscan lever, scan p99 monitoring in CI F1+, 3.315 ms tail risk | ✅ |

---

## 3. Internal consistency and dates/SHAs

- **Criterion 1 (L8)** and **NFR latency (L30)**: use "0.0–0.161 max" and "0.066–0.158 steady-state" respectively — both backed by the same sources (the 0.0 is the clipped run of the spike, the steady-state range excludes the 3.315 cold start). They do not contradict. ✅
- **L41** reconciles 0.623 (raw) vs 0.652 (fixer doc) as different runs — eliminates the discrepancy flagged in rv1. ✅
- **Dates/SHAs**: the doc does not cite SHAs, only indirectly referenced commits. Commit `7c2e4e4` ("fix(f0): budget-validation rigor scan margin + security risks") exists in git log and its diff matches 1:1 the verified corrections. `8db7d31` (spike-proxy) and `7f5cfb6` (--engine fix) also exist. ✅
- Cross-references (`spike-escaneo-performance-v2.md:18`, `spike-proxy-performance.md:51-54`, `spike-escaneo-security-v2.md:26-43,88-95`, `spike-proxy-security.md:98-109,134-166`, `scaffold-ci.md:12`) point to correct lines. ✅

---

## 4. Decision §9 #3 — is it still well supported?

**Yes.** ✅ The "Plan B = regex crate + Aho-Corasick prefilter" decision remains supported:

- **Vectorscan not viable here**: `raw/scan-vectorscan-attempt.txt` shows the error `is 'cmake' not installed?` (the `vectorscan-sys` build script requires cmake). ✅
- **Hybrid meets budget**: scan_p99 = 0.595–0.635 ms < 1.0 ms, independently reproduced (4 reviewer rv1 runs). ✅
- **Margin** ~1.5× documented as the limiting constraint with Vectorscan as the first lever (L70). ✅
- **No structural ReDoS**: prefixed → linear AC; unprefixed → RegexSet DFA; unbounded window caveat propagated to F1 as 🟠 Medium. ✅
- `decision-motor-matching.md` is consistent with the doc (same numbers: 0.623/0.469/218.5 mbps/227 matches). ✅

---

## 5. Findings (non-blocking)

1. **Minor off-by-one in two raw citations** (correct value, line ±1): `proxy-bench-50kb.txt:17` — the p99 overhead is on line 16; `fix-bench-hybrid.json:8` — the `scan_p99_ms` is on line 7 (line 8 is throughput). Does not affect the truthfulness of the figures.
2. **Traceability of the reviewer reproduction**: the 0.595–0.635 and 0.066–0.158 ranges come from the rv1 review artifact (`budget-validation-review-performance.md`), not from a raw committed in this worktree. It is documented as "reviewer reproduction" in the doc; acceptable, but a reader without access to the rv1 worktree could not reproduce it from `evidence/f0/raw/`. Recommendation (non-blocking): commit the reproduction JSONs in F1+.
3. **Inherited methodological observation** (already accepted in rv1, not fixable without re-bench): the proxy bench uses non-interleaved percentile diff; at the measured levels (<0.2 ms) it is noise floor. Documented in `spike-proxy-performance.md:70`.

---

## 6. Conclusion

The corrected document is **internally consistent**, all cited numbers
match the raw data and independent reproductions, and each finding from
the rv1 review (security + performance) was correctly applied: zero-leakage DEFERRED,
SSRF → F3, `--engine invalid` updated/removed, regex window 🟠 Medium, scan
margin ~1.5× as the limiting constraint, bench conditions present, and a
scalability/monitoring section added. Decision §9 #3 (regex + AC) remains valid.

**VERDICT: PASS** ✅
