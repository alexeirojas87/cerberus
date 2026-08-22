# Evidence Pack — f0/integration-gate
- Attempt: 1    Reviewer: revisor-integracion (independent)    Verdict: PASS
- Date: 2026-08-16    Worktree: cerberus-wt-f0-integration-gate (detached HEAD @ 22ced1f)

## Phase acceptance criteria (§8 F0)

> "spikes demonstrate scan < target and proxy overhead < target; matching engine decided
> and latency budget validated in writing."

| Criterion | Command executed | Output (quoted) | Result |
|----------|-------------------|-----------------|-----------|
| Integrated build (dev) | `cargo build --workspace` | `Finished dev profile in 9.01s`, 0 errors | ✅ |
| Integrated build (release) | `cargo build --release --workspace` | `Finished release profile in 14.02s`, 0 errors | ✅ |
| Integrated tests | `cargo test --workspace` | **40 passed; 0 failed** (see breakdown below) | ✅ |
| Integrated lint | `cargo clippy --workspace --all-targets -- -D warnings` | `Finished dev profile`, 0 errors | ✅ |
| Integrated format | `cargo fmt --check` | `FMT_EXIT=0`, 0 diffs | ✅ |
| Integrated scan < 1 ms | `cargo run --release --bin spike-scan -- --patterns 300 --payload-size 100 --iterations 500` | `scan_p99_ms: 0.625` (p50 0.486), 227 matches, 210.6 mbps | ✅ |
| Integrated proxy < 3–5 ms | `cargo run --release --bin spike-proxy -- --bench --payload-kb 50 --iterations 500` | `overhead p99: 0.061 ms` (run1), `0.072 ms` (run2) | ✅ |
| Scan reproducibility (p50 Δ < 20%) | scan bench ×2 | p50 0.486 → 0.481 ms (**Δ 1.0%**) | ✅ |
| Phase decisions | `evidence/f0/decision-motor-matching.md` exists | Decision §9 #3 written: **regex crate + Aho-Corasick** | ✅ |
| Budget validated in writing | `evidence/f0/budget-validation.md` exists | PASS with numbers (proxy 0.066–0.158 ms; scan 0.595–0.635 ms) | ✅ |
| Evidence packs of the 4 units | `evidence/f0/` listing | 13 packs + raw (see §6 table) | ✅ |

## Integrated test breakdown (40 total, 0 failed)

| Crate | Suite | Passed |
|---|---|---|
| benchkit | lib unit | 6 |
| cerberus-core | lib unit | 1 |
| spike-proxy | lib unit | 3 |
| spike-proxy | integration (real HTTP e2e) | 4 |
| spike-scan | lib unit | 7 |
| spike-scan | main unit | 11 |
| spike-scan | integration (binary/edge/schema) | 8 |
| **Total** | | **40 passed; 0 failed; 0 ignored** |

Doc-tests: 0 in the 4 crates (0 failed). No orphan crate: all 4 are members of `crates/*` and
all build + test + clippy + fmt.

## Reproduced latency numbers (integration reviewer verification)

- **Scan (hybrid AC+regex, 300 patterns, 99 KB, 500 iter, release):**
  run1: p50 = **0.486 ms**, p99 = **0.625 ms**, 210.6 mbps → §5 target < 1 ms ✅ (margin ~1.6×)
  run2: p50 = **0.481 ms**, p99 = 0.656 ms → Δp50 = **1.0%** (< 20% required)
- **Proxy (50 KB, 500 iter, release, loopback):**
  run1: overhead p99 = **0.061 ms**; run2: overhead p99 = **0.072 ms** → §5 target < 3–5 ms ✅
  (margin ~50–80×). Consistent with the 0.066–0.158 ms from the evidence pack.
- The integrated numbers reproduce the consolidated range of `budget-validation.md`
  (scan 0.595–0.635 ms; proxy 0.066–0.158 ms). No cold start outliers in the reviewer's own runs.

## Integration adversarial cases tested

- **Race/cleanup:** after each proxy bench run, `pgrep -fl spike-proxy` = empty (exit 1)
  and `lsof -iTCP -sTCP:LISTEN` with no proxy sockets → **0 residual processes/sockets** ✅
- **Version consistency:** `Cargo.lock` committed (git ls-files OK); the 4 crates declare
  `version = "0.1.0"` consistent across manifests and lock; no duplicated versions of own crates ✅
- **Reproducibility:** scan bench ×2 → Δp50 1.0%, Δp99 5.0% (0.625→0.656), both < 20% ✅
- **Full workspace:** `cargo test --workspace` covers the 4 crates; `crates/*` glob in
  `Cargo.toml:3` with no orphan members; CI (`ci.yml`) reflects exactly the same commands
  (fmt, clippy -D warnings, test, build release) with 3 OS matrix ✅
- **`--engine invalid` fix present:** confirmed in `main.rs:80-87` (`eprintln!` + `exit(1)`),
  per verification by `budget-validation-review-correctness-v2.md:68` (commit 7f5cfb6) ✅

## Status of unit evidence packs (existence + PASS)

| Unit (§8B.6) | Pack | Declared verdict |
|---|---|---|
| scaffold+CI | `evidence/f0/scaffold-ci.md` | ✅ PASS (Attempt 1) |
| spike-escaneo (correctness) | `spike-escaneo-correctness-v2.md` | ❌ FAIL pre-fix → **fixed** (see finding 1) |
| spike-escaneo (fixer) | `spike-escaneo-fix.md` | ✅ PASS (Attempt 2) |
| spike-escaneo (performance) | `spike-escaneo-performance-v2.md` | ✅ PASS (Attempt 2, 1 non-blocking observation) |
| spike-escaneo (security) | `spike-escaneo-security-v2.md` | ✅ PASS (Attempt 2) |
| spike-proxy (correctness) | `spike-proxy-correctness.md` | ✅ PASS (1 bug reported → F3) |
| spike-proxy (performance) | `spike-proxy-performance.md` | ✅ PASS |
| spike-proxy (security) | `spike-proxy-security.md` | ✅ PASS |
| latency-budget (correctness) | `budget-validation-review-correctness-v2.md` | ✅ PASS (Attempt 2) |
| latency-budget (performance) | `budget-validation-review-performance-v2.md` | ✅ PASS (Attempt 2) |
| latency-budget (security) | `budget-validation-review-security-v2.md` | ✅ PASS |
| latency-budget (consolidation) | `budget-validation.md` | ✅ PASS |
| decision §9 #3 | `decision-motor-matching.md` | ✅ Decision written (regex crate + AC) |

The **spike-escaneo** unit panel (high risk → majority): correctness FAIL→fix→re-verified in
budget-correctness, performance PASS, security PASS → majority reached.

## Integration findings

1. **Incomplete spike-escaneo correctness trail (observation, non-blocking):**
   `spike-escaneo-correctness-v2.md` remained documented as **FAIL** (real gauntlet failure due to
   `--engine invalid`, `main.rs:80-83` pre-fix) and the closing commit is called "panel PASS v2 + v3"
   but there is no `correctness-v3` pack with its own re-verification. The fix re-verification
   was absorbed by `spike-escaneo-fix.md` (PASS) and `budget-validation-review-correctness-v2.md`
   (§2 verifies the fix against code, commit 7f5cfb6). The phase verdict is solid: the fix is
   in the code (verified by this reviewer in `main.rs:80-87`) and the latency figures
   reproduce. Recommended for future phases: always close each FAIL with an explicit re-verification
   pack from the same panelist.
2. **Tight scan margin (~1.5×)** reproduced (0.625 ms vs 1.0 ms budget) — it is the
   limiting constraint of the system, already documented and propagated to F1/F3 in `budget-validation.md`.
3. **Proxy without 502 on upstream down** (spike-proxy bug, `spike-proxy-correctness.md:41-51`)
   propagated to F3; does not affect F0 latency criteria.

## Applicable NFRs

- Proxy latency: overhead p99 = 0.061–0.072 ms (reproduced; budget < 3–5 ms) → ✅ PASS
- Scan throughput: scan_p99 = 0.625–0.656 ms (budget < 1.0 ms) → ✅ PASS
- Security: `unsafe_code = "forbid"` in workspace (`Cargo.toml:8`) → ✅ PASS
- Reproducibility: Δp50 1.0% (required < 20%) → ✅ PASS

## If FAIL: what fails and how to reproduce it

Not applicable — all §8 F0 phase acceptance criteria are met in integrated state and the
latency numbers reproduce independently.

## Conclusion

**PHASE 0 VERDICT: PASS** ✅ — The integrated workspace (4 crates) builds dev+release without errors,
passes 40/40 tests, clean clippy -D warnings and fmt; the hybrid AC+regex scan runs at p99 = 0.625 ms
(< 1 ms) and proxy overhead at p99 = 0.061–0.072 ms (< 3–5 ms) with reproducibility < 20%; the
matching engine is decided in writing (regex crate + Aho-Corasick) and the latency budget
validated in writing with numbers. The 13 evidence packs of the 4 units exist and declare PASS
(except the pre-fix correctness FAIL that was fixed and re-verified). Phase 0 ready to
approve the §8B.7 gate and open F1.
