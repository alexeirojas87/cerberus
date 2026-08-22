# Evidence Pack — f0/budget-validation-review-security-v2
- Role: **REVIEWER 3 (Security)**
- Unit: **latency-budget** (second attempt)
- Audited documents: `evidence/f0/budget-validation.md`, `evidence/f0/decision-motor-matching.md`
- Verified code: `crates/spike-scan/src/main.rs:80-87`
- Verdict: **PASS** ✅

## Summary

The 5 requested security corrections + 2 additional criteria are verified.
All mandatory corrections are present and correct. 1 non-blocking observation
on the quantitative documentation of superlinear amplification.

---

## 1. Verified security corrections

### 1.1 "Zero leakage" → `⏭️ DEFERRED to F1/F5`

| Status | Detail |
|--------|---------|
| **Criterion** | The §5 #6 row must not be PASS, it must defer |
| **Doc** | `budget-validation.md:13` → `⏭️ DEFERRED to F1/F5 — validation when the pipeline handles real secrets` |
| **Code** | `spike-proxy-security.md:98-109` confirms 0 data `println!`, 0 `dbg!` |
| **Verdict** | ✅ **CORRECT** |

### 1.2 SSRF in risks table → F3

| Status | Detail |
|--------|---------|
| **Criterion** | The SSRF finding from `spike-proxy-security.md:159-166` must be in the propagation table |
| **Doc** | `budget-validation.md:60` → `Configurable upstream without restriction → potential SSRF \| 🟢 Info \| spike-proxy-security.md:159-166 \| F3` |
| **Verdict** | ✅ **CORRECT** — propagated to F3 with severity 🟢 Info and origin |

### 1.3 `--engine invalid` stale removed/updated

| Status | Detail |
|--------|---------|
| **Criterion** | The `--engine invalid` with silent fallback to Hybrid must be corrected or updated |
| **Doc** | `budget-validation.md:24` → `error 'invalid engine 'X' (expected 'regex' or 'hybrid')' + exit(1) (main.rs:80-87). Fix already applied in spike-escaneo-fix; no silent fallback.` |
| **Code** | `main.rs:80-87` → `eprintln!("invalid engine '{other}' (expected 'regex' or 'hybrid')"); std::process::exit(1);` — no catch-all, no silent fallback |
| **Verdict** | ✅ **CORRECT** — the stale is removed; the code confirms the fix |

### 1.4 Unbounded regex window → 🟠 Medium, F1 action

| Status | Detail |
|--------|---------|
| **Criterion** | Severity 🟠 Medium, F1 action: prefixed fuzzing + bounded window 128-1024 B |
| **Doc** | `budget-validation.md:61` → `🟠 Medium \| spike-escaneo-performance-v2.md:36-39, engine_hybrid.rs:115-117 \| F1 — expand ReDoS fuzzing with prefixed patterns + non-matching payloads; bound post-AC window to 128–1024 bytes` |
| **Verdict** | ✅ **CORRECT** — severity, origin, action, and destination correct |

---

## 2. No ReDoS criterion — honesty of the record

| Subcriterion | Doc | Verdict |
|---|---|---|
| Acknowledges that F0 did not cover the prefixed hybrid route | `budget-validation.md:32` → `Caveat: the prefixed hybrid route with unbounded window can amplify superlinearly (risk propagated to F1, see table)`. The spike (`spike-escaneo-security-v2.md:36`) confirms: the 3 ReDoS patterns tested have `extract_prefix() = None` → they only cover the unprefixed route. | ✅ **YES** — explicit caveat, with reference to the propagation table |
| Superlinear amplification as 🟠 Medium to expand in F1 | `budget-validation.md:61` → risk with `O(N_hits × L_payload)`, 🟠 Medium, F1 with prefixed fuzzing + bounded window | ✅ **YES** — qualitatively correct |
| Specific numbers (3.3 ms @100KB, 337 ms @1MB) | **Do not appear** in `budget-validation.md` nor in `spike-escaneo-performance-v2.md` nor in any file in the worktree. | ⚠️ **NO** — the numbers are not recorded |

**Observation**: The risk record is honest regarding existence, severity,
mechanism (`O(N_hits × L_payload)`), and propagation, but omits the quantitative
evidence of the amplification. The numbers 3.3 ms @100KB and 337 ms @1MB do not
appear in any document in the worktree. This does not invalidate the verdict, but
quantitative traceability would be strengthened if they were included.

---

## 3. Engine decision — no new risk

| Aspect | Detail | Verdict |
|---------|---------|-----------|
| Selected engine | `regex` crate + Aho-Corasick prefilter (Plan B) | — |
| New risk introduced | None. The unbounded window risk in the prefixed hybrid route is already documented in `budget-validation.md:61` and propagated to F1 | ✅ **NO NEW RISK** |
| Vectorscan | Discarded due to lack of cmake, remains a future optimization | — |
| Clear decision | `decision-motor-matching.md:48-54` → table with statuses and reasons | ✅ **YES** |

---

## 4. Risk propagation — complete table

| Origin finding | Risk | Severity | Propagate | In doc | Verdict |
|---|---|---|---|---|---|
| `spike-proxy-correctness.md:41-51` | Proxy without 502 on upstream down | 🔴 Must fix | F3 | `budget-validation.md:56` | ✅ |
| `spike-proxy-security.md:134-139` | No body limit → memory DoS | 🟠 Medium | F3 | `budget-validation.md:57` | ✅ |
| `spike-proxy-security.md:141-148` | No timeouts → socket leak | 🟠 Medium | F3 | `budget-validation.md:58` | ✅ |
| `spike-proxy-security.md:150-157` | Headers forwarded without sanitization | 🟡 Low | F3 | `budget-validation.md:59` | ✅ |
| `spike-proxy-security.md:159-166` | Upstream without restriction → SSRF | 🟢 Info | F3 | `budget-validation.md:60` | ✅ |
| `spike-escaneo-performance-v2.md:36-39` | Unbounded regex window → superlinear amplification | 🟠 Medium | F1 | `budget-validation.md:61` | ✅ |

**All findings from spike-proxy (5) and spike-escaneo (1) are propagated.** ✅

---

## 5. Additional findings

| # | Finding | Severity | File |
|---|---|---|---|
| 1 | Superlinear amplification numbers (3.3 ms @100KB, 337 ms @1MB) not recorded in any doc in the worktree — the quantitative evidence of the 🟠 Medium risk remains incomplete | 🟢 Info (observation) | `budget-validation.md:61` |
| 2 | `budget-validation.md` says "Attempt: 1" but the task indicates it is the second attempt — cosmetic inconsistency in the header | 🟢 Info | `budget-validation.md:2` |

---

## Final verdict

**PASS** ✅ — The 5 required security corrections are present and correct:

| Criterion | Result |
|---|---|
| 1. Zero leakage → DEFERRED to F1/F5 | ✅ |
| 2. SSRF in risks table → F3 | ✅ |
| 3. `--engine invalid` stale removed/updated | ✅ (code confirms fix) |
| 4. Unbounded regex window 🟠 Medium, F1 action (prefixed fuzzing + window 128-1024 B) | ✅ |
| 5. No ReDoS — honest record of the caveat (prefixed route not covered by F0 fuzzing) | ✅ (with observation: 3.3/337 ms numbers missing) |
| 6. Engine decision with no new risk | ✅ |
| 7. Complete risk propagation (6 findings, 6 rows) | ✅ |

**Closure**: The documents `budget-validation.md` and `decision-motor-matching.md` meet
the Gauntlet's security criteria. The risk of superlinear amplification due to
an unbounded window is correctly identified, classified as 🟠 Medium, and propagated
to F1 with a concrete action. The omission of the quantitative numbers (3.3/337 ms) is a
non-blocking observation that does not affect the validity of the verdict.
