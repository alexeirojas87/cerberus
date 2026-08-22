# Fase 9 — Adversarial Findings & Final Verdict (Reviewer: Codex, fresh context)
- Commit: c327527
- Gate re-run evidence: `evidence/review8/codex-f9-gate.md`
- Mission: BREAK F9, don't confirm it. Findings below are what survived verification.

## Findings (P0 / P1 / P2)

### P0 — (none)
No hard blocker. Release gate is green + stable; no-leak / fail-closed / MITM-fail-closed codepaths exist with passing tests; no inline-drift at the production level; simulate 29/0; clippy/fmt clean.

### P1-1 — DEBUG workspace gate is FLAKY; builder's "596/0 debug" evidence is not reproducible
- **What broke:** `cargo test --workspace --all-targets` (debug) failed **2 of 3** runs on this machine. Identical failure both times: `load_test_decode_and_scan` (p99 51.6ms / 54.2ms) and `load_test_scan_and_redact` (p99 65.4ms / 55.8ms) exceed the 50ms debug budget.
- **Root cause:** the two HEAVY perf tests (decode+scan, scan+redact) exceed the 10×-relaxed debug budget (50ms, `budget_for(false, 5.0)`) **only under parallel workspace CPU contention**. Standalone `cargo test --test load_test` passes 8/0 in 1.04s; release passes 8/0 in 0.74s. So the test is correct, the **debug budget under parallel load is too tight**.
- **Why it matters:** the gauntlet (§8B.1 rule 3) and AGENTS.md make determinism first-class ("Si no se pudo ejecutar, es FAIL"). The builder fixed one flake (daemon env-race, `pid_path_is_in_config_dir` / `config_dir_is_dot_cerberus` now take `ENV_LOCK` — **verified green across 2 release runs**) but the load_test debug-budget flake remains. The evidence pack states `596 passed; 0 failed` (debug) as a verified fact — that is **not** reproducible.
- **Reproduce:** `cargo test --workspace --all-targets` (debug), run 3×. ~67% failure rate on an 8-core macOS host. Failures are in `tests/load_test.rs::load_test_decode_and_scan` / `::load_test_scan_and_redact`.
- **Fix (reviewer suggestion, not applied):** either (a) raise the debug budget for the two heavy tests specifically (e.g. `budget_for(false, 5.0)` → `* 15.0` for decode/redact), (b) mark the perf tests `#[ignore]` in debug and gate them behind `--release` only (the §5 budget is a release criterion anyway), or (c) run `load_test` serially via a `harness = false` + dedicated test binary. Smallest correct fix is (b) — perf belongs in release.

### P2-1 — redos_fuzz budget (100ms) is 20× the real 3–5ms target
- `MAX_SCAN_TIME_MS = 100` (`tests/redos_fuzz.rs:22`). This is a catastrophic-backtracking safety net, NOT the latency budget (load_test enforces 5ms release). But 100ms would NOT catch a 50ms pathological scan that isn't in load_test's corpus. Acceptable as defense-in-depth (the Rust `regex` crate is RE2-like → ReDoS impossible by construction), but the reviewer prompt's concern is valid: a pattern-specific pathological input not covered by load_test's 6 payloads could slip past both gates.
- **Severity P2** because engine guarantees linear time; this is belt-and-suspenders, not the primary gate.

### P2-2 — `redos_fuzz_each_pattern` uses a single non-targeted input per pattern
- `tests/redos_fuzz.rs:67`: every pattern is fuzzed against exactly one input, `"a"×5000 + "!"`. This does not craft inputs targeting each pattern's specific quantifiers/anchors (e.g. the `{20,}` quantifier in the openai pattern, the `(?:.*\n)*?` in the PEM pattern). The genuinely adversarial multiline cases live in separate engine-level tests (`redos_fuzz_malformed_pem_multiline`, `redos_fuzz_env_block_large`) which DO target the multiline patterns at the scan level.
- Net: "redos-fuzz(todos los packs)" criterion is met in spirit (every pattern compiles + runs; multiline patterns get dedicated adversarial engine tests). Weakness is input diversity per pattern.

### P2-3 — failsafe `proxy_pipeline_*` test is misnamed (doesn't run the proxy)
- `tests/failsafe.rs::proxy_pipeline_fail_closed_rejects_on_simulated_engine_error` does NOT exercise the real proxy pipeline. It calls `evaluate(FailPolicy::Closed, "engine: regex compile timeout after 2s")` directly with a hardcoded string. There is no decode→scan→policy end-to-end run with a failing engine.
- Mitigation: real proxy-level fail-closed IS covered in `crates/cerberus-proxy/src/forward.rs` (`connect_tls_invalid_json_obeys_closed_and_open_fail_policy_without_audit_leak`, `connect_tls_redaction_failure_obeys_closed_and_open_fail_policy_without_leak`) — so net coverage is fine, but the failsafe.rs test name overstates what it tests.

### P2-4 — precision/recall corpus uses a divergent flag name
- `crates/cerberus-engine/tests/precision_recall_test.rs:159-162` uses flag `internal.private_key_pem`, while the shipped pack (`default_pack.rs:131`) uses `secret.pem_private_key`. This is a separate test corpus (not claiming to be the production pack), but if anyone reads F1 precision/recall evidence as reflecting production detection, the flag naming diverges. Minor / documentation-level.

### INFO — inline pattern copies exist, but NOT a competing production pack (drift eliminated at production level)
- The builder's SPECIFIC F9 claim ("redos-fuzz/load-test now use the REAL default pack instead of inline copies") is **VERIFIED TRUE**: `tests/redos_fuzz.rs` and `tests/load_test.rs` both `use cerberus_packs::default_pack::DEFAULT_PACK_JSON`; grep for `"flag"` in `tests/` returns nothing (no inline rule JSON).
- Production path is consolidated: `crates/cerberus/src/packs.rs::default_rules_json()` delegates to `cerberus_packs::default_pack::DEFAULT_PACK_JSON`; `daemon.rs` + `init.rs` consume that delegate. `DetectionPolicy::seeded()` production default has empty categories/rule_actions/custom_rules/allowlist (asserted in `detection_policy.rs::default_openai_rule_keeps_its_declared_block_action`).
- Inline copies of `sk-[A-Za-z0-9]{20,}` / `-----BEGIN ... PRIVATE KEY-----` exist in: `cerberus-engine` unit tests (`engine.rs`, `constraints.rs`, `multiline.rs`, `rule.rs`), `crates/spike-scan` (F0 throwaway), `cerberus-proxy/tests/smoke_harness.rs` (5×), `cerberus-proxy/src/detection_policy.rs:426/442`. **All are inside `#[cfg(test)]` modules or the F0 spike crate** — test fixtures testing engine mechanics, NOT a second production pack. No production drift.

## Final verdict per F9 unit (§8B.6)

| Unit | Verdict | Justification (exact evidence) |
|------|---------|--------------------------------|
| **security-review** | **PASS** | clippy 0 / fmt 0; release 596/0 ×2 with env-race tests green; no-leak tests exist (`payload_has_no_secrets_fields`, `dev_feedback_line_has_flag_and_hash_never_raw`, store 22/0) and pass; MITM fail-closed tests exist (`mismatched_ca_pair_fails_closed_before_listener_bind`, `strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime`) and pass; simulate 29/0. The P1 debug flake is a load-test budget issue, not a security codepath defect. |
| **redos-fuzz** | **PASS** | `cargo test --test redos_fuzz` → 8/0 (0.10s). Loads real `DEFAULT_PACK_JSON` (13 rules incl. multiline PEM/id_rsa/.env); `redos_fuzz_each_pattern` iterates every pattern of every rule; dedicated adversarial multiline tests (`malformed_pem_multiline`, `env_block_large`, `long_suffix_after_prefix`). P2 budget/input-diversity weaknesses noted; "no ReDoS" met by RE2-like engine + defense-in-depth fuzz. |
| **load-test** | **PASS (unit)** / **FAIL (workspace gate)** | Standalone `--test load_test` 8/0 (debug 1.04s, release 0.74s); drift guard asserts `rules.len()==13`; p99<5ms release met. BUT under parallel `--workspace --all-targets` (debug) the two heavy tests flake (P1-1: 2/3 runs FAIL). The unit's own evidence commands reproduce green; the workspace gate does not. |
| **failsafe** | **PASS** | `cargo test --test failsafe` → 10/0. Covers secure-by-default (`FailPolicy::default()==Closed`, `ProxyConfig::default().fail_policy==Closed`), 5 heterogeneous error classes (closed→Reject, open→Allow), invalid-span redaction (no panic). P2-3: `proxy_pipeline_*` name overstates (calls `evaluate` directly), but real proxy-level fail-closed is covered in forward.rs. |
| **docs** | **PASS** | All 3 guides exist and are substantive (spot-checked content, not just keyword counts). security-guide: Threat Model + Zero Leak (never persisted/hashed/not in telemetry/not in feedback) + No ReDoS (13 rules, redos_fuzz.rs) + Fail-Closed default + MITM opt-in/scoped + Telemetry Privacy (exact collected/never-collected lists) + Rule Pack Ed25519. user-guide: brew/curl/winget/Docker, MITM opt-in, commands table (mitm/pack/license), Dev Feedback, Telemetry opt-in, License Tiers. operator-guide: MITM/telemetry/feedback architecture, Docker/Helm, Windows platform notes. |

## Overall verdict for Fase 9: **FAIL (P1 blocking)**

### Rationale
The release gate (the authoritative §5 budget + GA bar) is **green and stable** — `cargo test --release --workspace --all-targets` → 596/0 on **both** runs, env-race fix verified, no-leak/fail-closed/MITM codepaths covered with passing tests, simulate 29/0, clippy/fmt clean, redos-fuzz/load-test/failsafe standalone pass, docs complete. On the substance of the 5 F9 units, the work is real and the builder's structural claims (real-pack fuzz/bench, single-source pack, failsafe extension, env-race fix, F4/F8 docs) all check out.

**However**, the gate as specified in §8B and re-run here includes `cargo test --workspace --all-targets` (debug). That gate is **flaky — 2 of 3 runs FAILED** with `load_test_decode_and_scan` / `load_test_scan_and_redact` exceeding the 50ms debug budget under parallel CPU contention. The builder's evidence pack asserts `596 passed; 0 failed` for debug as a verified fact; that number is **not reproducible**. The gauntlet's determinism principle (§8B.1 rule 3 + the env-race narrative) makes a 67%-failure gate a blocking FAIL, not a "pass on the run that counted."

This is a **small, localized fix away from PASS** (raise the debug budget for the two heavy tests, or gate perf behind `--release` only — which is where the §5 budget is validated anyway). It is **not** a correctness or security regression: the release numbers are clean and stable. But GA sign-off requires the gate to pass reliably, and it does not.

### Required fix before GA sign-off
- Make `cargo test --workspace --all-targets` (debug) reliably green. Recommended: mark the perf assertions in `load_test.rs` as release-only (the §5 p99<3–5ms budget is a release criterion) OR raise the debug budget for `decode_and_scan`/`scan_and_redact` to a margin that survives parallel workspace contention on CI.
- Refresh the F9 evidence packs with the reproducible numbers (release 596/0 ×2, and either debug-stable or debug-perf-gated-behind-release) instead of the non-reproducible "596/0 debug" claim.

### What is NOT broken (so the fix is small)
- No P0. No security codepath untested. No production pack drift. Env-race fix works. Release gate stable. Docs accurate. redos-fuzz/load-test/failsafe units pass on their own evidence commands.

## Files
- `evidence/review8/codex-f9-gate.md` — full gate re-run, all commands + exact output
- `evidence/review8/codex-f9-findings.md` — this file
