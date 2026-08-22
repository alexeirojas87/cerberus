# Fase 9 — Adversarial Findings & Final Verdict (Reviewer: opencode, fresh context)
- Commit under review: HEAD of `main` = **`c327527`** (`git log --oneline -3` confirms — see §0).
- Prior P1 (codex review): `load_test_decode_and_scan` / `load_test_scan_and_redact` flaked under parallel debug CPU contention (p99 51–65 ms > 50 ms debug budget).
- Builder's claimed fix: debug path enforces ONLY a 30× "pathology ceiling" (150 ms); release still enforces strict 5 ms.
- Mission: BREAK F9, don't confirm it. Findings below survived independent re-execution.

---

## §0 — CRITICAL: the "fix on top of c327527" does NOT exist as a commit

`git log --oneline -3`:
```
c327527 feat(F9): hardening + GA — redos-fuzz/load-test sobre pack real, failsafe proxy-level, docs F4/F8
857cdd1 test(gauntlet): evidence sim 29/29 para el cierre F4/F8
b27e1bf fix(F4 forward): backlog explícito + test_state cfg(test) + Notify solo en tests
```
**HEAD IS `c327527` itself.** There is no fix commit on top of it. The fix exists ONLY as
**uncommitted working-tree modifications** to `tests/load_test.rs`:

```
$ git diff -- tests/load_test.rs   # unstaged
- const fn budget_for(...)  ← REMOVED
- assert_p99_budget: debug branch now uses release_budget * 30.0 (150 ms) ceiling, no strict budget
- load_test_empty_engine: same release=5.0 / debug=5.0*30.0 split
```

`git diff c327527..HEAD -- tests/load_test.rs` → **empty** (nothing committed on top).

**Consequence:** at the reviewed commit (`c327527` clean checkout), the debug workspace gate is
STILL flaky (codex verified 2/3 fail; the working-tree patch is what makes it green). The fix
code is sound (verified below) but it has not landed in git. For GA the fix must be committed.

---

## §1 — Gate re-run (all commands executed raw, no rtk filtering, this machine)

### Lint / format
| Cmd | Exit | Result |
|-----|------|--------|
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 | No issues found |

### Debug workspace — 3× raw (the flake reproducibility test)
| Run | Exit | Total | load_test | integration |
|-----|------|-------|-----------|-------------|
| 1 | 0 | **596 passed; 0 failed** | 8/0 (1.05s) | 8/0 (30.22s) |
| 2 | 0 | **596 passed; 0 failed** | 8/0 (1.03s) | 8/0 (30.54s) |
| 3 | 0 | **596 passed; 0 failed** | 8/0 | 8/0 |

**3/3 debug workspace runs GREEN with the working-tree fix applied.** The codex P1 flake
(2/3 fail at clean c327527) is reproducibly resolved BY THE PATCH. (At clean HEAD without the
patch, per codex, it is still 2/3 fail — see §0.)

### Release workspace — 2×
| Run | Exit | Total |
|-----|------|-------|
| 1 | 0 | **596 passed; 0 failed** |
| 2 | 0 | **596 passed; 0 failed** |

Release gate stable. The §5 p99 < 3–5 ms budget is a release criterion and is enforced here.

### Individual binaries
| Cmd | Exit | Result |
|-----|------|--------|
| `cargo test --test redos_fuzz` | 0 | 8 passed; 0 failed (0.12s) |
| `cargo test --test load_test` | 0 | 8 passed; 0 failed |
| `cargo test --test failsafe` | 0 | 10 passed; 0 failed (0.01s) |
| `python3 tools/simulate.py` | 0 | **29 PASS / 0 FAIL** |

### No-leak / MITM commands cited by security-review (re-run, exact counts)
| Cmd | Exit | Result | Matches evidence pack? |
|-----|------|--------|--------------------------|
| `cargo test -p cerberus-packs --lib telemetry` | 0 | **12 passed** | ✅ (claims 12) |
| `cargo test -p cerberus --bin cerberus feedback` | 0 | **13 passed** | ✅ (claims 13) |
| `cargo test -p cerberus-store --lib` | 0 | **22 passed** | ✅ (claims 22) |
| `cargo test -p cerberus-proxy --lib -- forward::` | 0 | **20 passed** | ✅ (claims 20) |

---

## §2 — Is the load_test fix SOUND? (adversarial analysis)

### 2a. Code path correctness (`tests/load_test.rs`)
- `assert_p99_budget` (L28–48): `is_release = !cfg!(debug_assertions)`.
  - **Release branch:** `budget = release_budget` (5.0); hard `assert!(p99_ms < budget)`. ✅ strict 5 ms.
  - **Debug branch:** `debug_ceiling = release_budget * 30.0` (150 ms); asserts only `p99_ms < 150`. ✅ ONLY a pathology ceiling, no strict 5 ms in debug.
- `load_test_empty_engine` (L167–186): `ceiling = if is_release { 5.0 } else { 5.0 * 30.0 }`. Same split. ✅
- `budget_for` const fn: **fully removed**, `grep -rn "budget_for" --include="*.rs"` → 0 matches. No dead code. ✅

### 2b. Could the fix mask a REAL regression?
Observed p99 (standalone, `--nocapture`):

| test | debug p99 | debug ceiling (150) | release p99 | release budget (5) | release margin |
|------|-----------|----------------------|-------------|---------------------|----------------|
| 1kb_clean | 5.820 ms | ✓ | 0.917 ms | 5 | 5.4× |
| 10kb_clean | 8.273 ms | ✓ | 1.178 ms | 5 | 4.2× |
| 50kb_secrets | 15.579 ms | ✓ | 1.240 ms | 5 | 4.0× |
| 100kb_clean | 14.773 ms | ✓ | 1.394 ms | 5 | 3.6× |
| decode_and_scan | 25.638 ms | ✓ | 2.081 ms | 5 | 2.4× |
| scan_and_redact | 27.834 ms | ✓ | **2.598 ms** | 5 | **1.9×** |
| empty_engine (avg) | 2.212 ms | ✓ | 0.454 ms | 5 | 11× |

Under parallel contention codex saw debug decode_and_scan ~51–54 ms, scan_and_redact ~55–65 ms.
The 150 ms ceiling sits ~2.3× above that worst case.

- **Quadratic / catastrophic regression** on 10–100 KB payloads → hundreds of ms to seconds →
  caught by the 150 ms debug ceiling (and also by release 5 ms). ✅
- **Mild linear regression (2×) under debug contention** (~130 ms) could slip past the 150 ms
  debug ceiling — BUT release is strict at 5 ms and scan_and_redact sits at 2.6 ms (1.9× margin),
  so a 2× regression → 5.2 ms → **FAIL release**. The release gate is the real §5 gate and is
  meaningful (not razor-thin, not loose). ✅
- `redos_fuzz` adds a 3rd layer: 100 ms ceiling on adversarial backtracking inputs.

**Verdict on fix soundness: SOUND.** Debug ceiling = pathology guard; release = real §5 budget
with ~2× margin on the heaviest test. A regression big enough to matter in production is caught
by release; a catastrophic one is caught by both. The 30× multiplier is defensible (the codex
reviewer's own recommended option was "perf belongs in release").

### 2c. P1 flake reproducibility — CONFIRMED FIXED (with the patch)
3/3 raw debug workspace runs green (596/0 each). The `load_test_decode_and_scan` /
`load_test_scan_and_redact` failures codex saw (51–65 ms) do not recur; worst standalone debug
p99 is 27.8 ms, well under 150 ms.

---

## §3 — Spec compliance of F9 units (§8B.6: security-review, redos-fuzz, load-test, failsafe, docs)

### redos-fuzz — "redos-fuzz(todos los packs)"
- `tests/redos_fuzz.rs` `use cerberus_packs::default_pack::DEFAULT_PACK_JSON` (L19). ✅ real pack.
- `redos_fuzz_each_pattern` (L61–80) iterates `for rule in &rules { for pattern in &rule.patterns }`
  → compiles + times **every pattern of every rule**. The default pack
  (`crates/cerberus-packs/src/default_pack.rs`) has exactly **13 rules, 1 pattern each** =
  13 patterns fuzzed individually, **incl. multiline PEM (L136), id_rsa OPENSSH (L145), .env (L154)**. ✅
- Dedicated adversarial multiline tests: `redos_fuzz_malformed_pem_multiline` (truncated PEM +
  100× nested BEGIN), `redos_fuzz_env_block_large` (5000 lines), `redos_fuzz_long_suffix_after_prefix`
  (sk- + 100k). ✅
- Drift guard: `redos_fuzz_load_all_rules_returns_default_pack` asserts `rules.len() >= 13`
  (L228–232) — **weaker than load_test's `== 13`** (see P2-4). Floor only.

### load-test
- `tests/load_test.rs` loads `DEFAULT_PACK_JSON` (L15, L52). ✅ real 13-rule pack.
- Drift guard `load_test_default_pack_rule_count` asserts `rules.len() == 13` (L235–240). ✅ strict.
- Benchmarks 1/10/50/100 KB clean + secrets + decode+scan + scan+redact + empty engine. ✅
- Release p99 all < 5 ms (§2b table). ✅

### failsafe — secure-by-default + proxy-level coverage
- `fail_policy_default_is_closed_secure`: `FailPolicy::default() == Closed` AND
  `ProxyConfig::default().fail_policy == Closed`. ✅ secure-by-default.
- 5 heterogeneous error classes (engine/decode/redact/upstream/timeout) → all Reject under Closed,
  all Allow under Open. ✅
- Invalid-span redaction → Err, no panic. ✅
- **Proxy-level fail-closed:** the REAL proxy pipeline is covered in
  `crates/cerberus-proxy/src/forward.rs` (20 tests). Adversarially verified the cited tests are
  genuine proxy-level, NOT mere `evaluate()` calls:
  - `mismatched_ca_pair_fails_closed_before_listener_bind` (L1015) calls `spawn_forward_proxy(cfg, ctx).await`
    and asserts `Err` before bind, error contains "does not match". ✅ real.
  - `connect_tls_invalid_json_obeys_closed_and_open_fail_policy_without_audit_leak` (L1364),
    `connect_tls_redaction_failure_obeys_closed_and_open_fail_policy_without_leak` (L1421),
    `missing_ca_prevents_listener_from_binding` (L1731) — all bind real `TcpListener` upstreams. ✅
  - **P2-3:** `tests/failsafe.rs::proxy_pipeline_fail_closed_rejects_on_simulated_engine_error` (L127)
    is misnamed — it calls `evaluate(FailPolicy::Closed, "engine: regex compile timeout after 2s")`
    directly with a hardcoded string, NOT the real pipeline. Coverage is rescued by forward.rs, but
    the failsafe.rs test name overstates what it tests. (Same as codex P2-3.)

### docs — F4/F8 spot-check (grep counts, all ≥1)
| Claim | File | Hits |
|-------|------|------|
| Windows winget | user-guide.md | 2 ✅ |
| MITM opt-in | user-guide.md | 3 ✅ |
| MITM | operator-guide.md | (operator) ✅ |
| Dev Feedback | user-guide.md | 1 ✅ |
| Telemetry opt-in | user-guide.md | 3 ✅ |
| Helm | operator-guide.md | 3 ✅ |
| Windows platform | operator-guide.md | 3 ✅ |
| Rule pack Ed25519 | security-guide.md | 1 ✅ |
| Zero Leak | security-guide.md | 1 ✅ |
| Threat Model | security-guide.md | 1 ✅ |
| Telemetry Privacy | security-guide.md | 1 ✅ |

All 3 guides exist and are substantive; F4/F8 features documented. ✅

### Dependency hygiene (default_pack move)
`crates/cerberus-packs/Cargo.toml`: deps = `cerberus-engine` (path) + serde/ed25519-dalek/sha2/reqwest/uuid.
**No dependency on `cerberus` (the bin crate) → no cycle.** Direction: `cerberus` → `cerberus-packs` →
`cerberus-engine`. `default_pack.rs` is a `const &str`, no new deps. ✅

---

## §4 — Findings (P0 / P1 / P2)

### P0 — (none)
No security codepath untested. No production pack drift (single source `DEFAULT_PACK_JSON`).
Release gate green + stable ×2. No-leak/MITM tests exist and pass with exact cited counts.

### P1-1 — The fix is NOT committed; HEAD (`c327527`) is still flaky
- The task expected "a fix on top of c327527". **No such commit exists** — HEAD IS c327527.
- The fix lives only as uncommitted working-tree changes to `tests/load_test.rs`.
- At clean `c327527` (per codex, verified) the debug workspace gate fails 2/3 (decode_and_scan
  51–54 ms, scan_and_redact 55–65 ms > 50 ms). The patch resolves it (3/3 green here), but the
  reviewed commit itself does not pass reliably.
- AGENTS.md: "Si no se pudo ejecutar, es FAIL." At the commit under review, it cannot be executed
  reliably green.
- **Fix:** commit the `load_test.rs` patch as a real commit on top of c327527.

### P1-2 — Evidence pack `evidence/f9/load-test.md` is STALE (numbers don't match code)
- L9: cites "p99 < 5ms (release) / **< 50ms (debug 10x)**" — but the patch changed debug to a
  **30× ceiling (150 ms)** with **no strict debug budget**.
- L31: "En debug, budget **10x** relajado (CPU compartida)." — code now uses 30× pathology ceiling,
  not a 10× budget.
- The evidence pack does not describe the actual debug behavior of the code it documents.
- Also `evidence/f9/security-review.md` (L7) and `evidence/f9/integration-gate.md` (L20) cite
  "596/0 debug" as a flat fact without noting the debug-budget patch that makes it reproducible
  (nor the ×3 reproducibility run).
- Contract: "Prohibido 'lo veo bien'." Evidence must match reality.
- **Fix:** refresh load-test.md (30×/150 ms ceiling, no strict debug budget, 596/0 debug ×3);
  note the debug fix in security-review.md + integration-gate.md.

### P2-1 — redos_fuzz budget (100 ms) is 20× the 3–5 ms target
- `MAX_SCAN_TIME_MS = 100` (`tests/redos_fuzz.rs:22`). Defense-in-depth only (RE2-like engine makes
  ReDoS impossible by construction); the real latency gate is load_test release (5 ms). A
  pattern-specific pathological input not in load_test's 6 payloads could slip both — but engine
  guarantees linear time. Acceptable. (Same as codex P2-1.)

### P2-2 — `redos_fuzz_each_pattern` uses a single non-targeted input per pattern
- L67: every pattern fuzzed against exactly one input `"a"×5000 + "!"`. Does not craft inputs
  targeting each pattern's specific quantifiers/anchors. Multiline patterns get dedicated
  adversarial engine tests (`malformed_pem_multiline`, `env_block_large`). Net: criterion met in
  spirit; weakness is input diversity. (Same as codex P2-2.)

### P2-3 — `failsafe::proxy_pipeline_*` test is misnamed (doesn't run the proxy)
- `tests/failsafe.rs:127` calls `evaluate()` directly with a hardcoded string. Real proxy-level
  fail-closed is covered in forward.rs (20 tests, verified genuine). Name overstates. (Same as codex.)

### P2-4 — redos_fuzz drift guard is weaker than load_test's
- `redos_fuzz.rs:228` asserts `rules.len() >= 13` (would not catch 13→14 growth). `load_test.rs:237`
  asserts `== 13` (strict). load_test rescues it, but the two guards are inconsistent. Minor.

### P2-5 — debug 150 ms ceiling ~2.3× above worst observed under contention
- Under contention codex saw ~65 ms; ceiling 150 ms. A 2× linear regression under debug contention
  (~130 ms) could slip past debug. Mitigated by release 5 ms strict (scan_and_redact 2.6 ms, 1.9×
  margin → 2× regression fails release). Acceptable since release is the real §5 gate. Not a blocker.

---

## §5 — Per-unit verdict (§8B.6)

| Unit | Verdict | Exact evidence |
|------|---------|-----------------|
| **security-review** | **PASS** | fmt 0 / clippy 0; release 596/0 ×2; no-leak telemetry 12/0, feedback 13/0, store 22/0, MITM forward 20/0 (all reproduce exact cited counts); simulate 29/0; MITM fail-closed tests are REAL proxy-level (`spawn_forward_proxy`/`connect_tls` w/ real `TcpListener`, not `evaluate()`). No F4/F8 codepath untested. |
| **redos-fuzz** | **PASS** | `cargo test --test redos_fuzz` → 8/0. Loads real `DEFAULT_PACK_JSON` (13 rules incl. multiline PEM/id_rsa/.env); `redos_fuzz_each_pattern` iterates every pattern; dedicated multiline adversarial tests. P2-1/P2-2 weaknesses noted, not blocking. |
| **load-test** | **PASS (behavior)** / **FAIL (commit+evidence)** | With the working-tree patch: 3/3 debug workspace 596/0, 2/2 release 596/0, standalone 8/0; release p99 all <5 ms (heaviest scan_and_redact 2.598 ms, 1.9× margin); drift guard `==13`. BUT the patch is uncommitted (P1-1) and `evidence/f9/load-test.md` cites stale "debug 10x/50ms" (P1-2). |
| **failsafe** | **PASS** | `cargo test --test failsafe` → 10/0. Secure-by-default (`FailPolicy::default()==Closed`, `ProxyConfig::default().fail_policy==Closed`), 5 heterogeneous error classes, invalid-span no-panic. P2-3 misnomer; real proxy-level covered in forward.rs. |
| **docs** | **PASS** | All 3 guides exist + substantive; 11 F4/F8 claims spot-checked by grep, all ≥1 hit (winget/MITM/feedback/telemetry/Helm/Windows/Ed25519/Zero-Leak/Threat-Model). |

---

## §6 — Overall verdict for Fase 9: **FAIL (P1 blocking)**

### Rationale
On substance the work is real and the fix is sound: with the working-tree patch the debug flake
is reproducibly gone (3/3 debug workspace 596/0), release is green + stable (2/2 × 596/0), the
§5 p99 < 3–5 ms release budget is enforced with a meaningful ~2× margin on the heaviest test,
`budget_for` is cleanly removed, no-leak/MITM tests reproduce exact cited counts, redos-fuzz covers
all 13 patterns incl. multiline, failsafe is secure-by-default, docs cover F4/F8, no dependency
cycle, no production pack drift.

**However** two P1s block GA sign-off:

1. **The fix is not committed.** HEAD is `c327527`; the task expected "a fix on top of c327527"
   and no such commit exists — the patch is uncommitted working-tree changes. At the reviewed
   commit the debug gate is still flaky (codex: 2/3 fail). AGENTS.md: "Si no se pudo ejecutar, es FAIL."

2. **`evidence/f9/load-test.md` is stale.** It cites "debug 10x / 50ms" while the code enforces a
   30× (150 ms) pathology ceiling with no strict debug budget. Evidence does not match reality
   ("Prohibido 'lo veo bien'"). security-review.md / integration-gate.md also cite 596/0 debug
   without noting the fix or the ×3 reproducibility run.

Both are small, localized fixes away from PASS:
- (a) commit the `load_test.rs` patch as a real commit on top of c327527;
- (b) refresh `evidence/f9/load-test.md` (30×/150 ms ceiling, no strict debug budget, 596/0 debug ×3)
  and note the debug fix in security-review.md / integration-gate.md.

### Explicit confirmation re: the P1 flake fix
- **Sound:** YES. Debug enforces ONLY a 30× (150 ms) pathology ceiling (no strict 5 ms); release
  still enforces strict 5 ms with ~2× margin on the heaviest test. `budget_for` fully removed, no
  dead code. A real regression is caught by release (5 ms) or by the debug ceiling (quadratic →
  hundreds of ms). The 30× multiplier is defensible (matches codex's own "perf belongs in release").
- **Reproducible:** YES (with the patch). 3/3 raw debug workspace runs green (596/0 each), no
  `load_test_decode_and_scan` / `load_test_scan_and_redact` failure. Without the patch (clean
  c327527) codex established 2/3 fail — so reproducibility is contingent on committing the patch.

### What is NOT broken (fix is small)
No P0. No security codepath untested. No production pack drift. No dependency cycle. Release gate
stable. No-leak/MITM counts reproduce exactly. Docs accurate. redos-fuzz/load-test/failsafe pass on
their own evidence commands. The fix code itself is correct.

## Files
- This file: `evidence/review8/opencode-f9-findings.md`
- Raw gate logs: `/tmp/{debug_run1,debug_run2,debug_run3,release_run1,release_run2,redos,failsafe,
  loadtest_nocapture,loadtest_release,simulate,tel,fb,store,fwd,clippy}.log`
