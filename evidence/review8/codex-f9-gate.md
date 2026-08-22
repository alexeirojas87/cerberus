# Fase 9 — Adversarial Gate Re-run (Reviewer: Codex, fresh context)
- Commit reviewed: c327527 (HEAD of main)
- Worktree: clean (`git diff HEAD --stat` empty for tracked files)
- Date: 2026-08-22
- Protocol: §8B (Gauntlet). Rule 3 ("Si no se pudo ejecutar, es FAIL") applied — I EXECUTED every command and report what I observed, not what the builder claimed.

> RTK filter caveat: `rtk cargo test` is a "failures-only" filter that drops passing-binary summaries. For evidence I re-ran each gate command **raw (no rtk)** and captured full output to `/tmp/cerberus_*.log`. Numbers below come from raw logs.

## 1. `cargo fmt --all -- --check`
- Command: `cargo fmt --all -- --check`
- Exit: 0
- Output: (empty — 0 diffs)
- **Result: PASS**

## 2. `cargo clippy --workspace --all-targets -- -D warnings`
- Command: `cargo clippy --workspace --all-targets -- -D warnings`
- Output: `No issues found` (rtk wrap; exit 0)
- **Result: PASS**

## 3. `cargo test --workspace --all-targets` (DEBUG) — run 3× to characterize flakes
> Builder claims `596 passed; 0 failed`. I got a **flaky gate: 2 of 3 runs FAILED.**

| Run | Result | Detail |
|-----|--------|--------|
| 1 | **FAIL** | `load_test`: 6 passed; **2 failed**. `load_test_decode_and_scan` p99=**51.648ms** > 50ms debug budget; `load_test_scan_and_redact` p99=**65.366ms** > 50ms. |
| 2 | PASS | 596 passed; 0 failed (raw, unfiltered). load_test 8/0 in 1.09s. |
| 3 | **FAIL** | `load_test`: 6 passed; **2 failed**. `load_test_decode_and_scan` p99=**54.155ms**; `load_test_scan_and_redact` p99=**55.825ms**. |

- Failure mode (identical both times): the two HEAVY perf tests in `load_test.rs` (`decode_and_scan`, `scan_and_redact`) exceed the 10×-relaxed debug budget (50ms) **only when the whole workspace runs in parallel**. Standalone `cargo test --test load_test` (no parallel contention) passes 8/0 (see §6 below).
- Reproduce: `cargo test --workspace --all-targets` in debug, run 3×. ~67% failure rate on this 8-core macOS machine.
- **Result: FAIL (flaky)** — the builder's "596/0 debug" evidence is NOT reproducible. Determinism violation per §8B.1 rule 3 and the env-race narrative.

## 4. `cargo test --release --workspace --all-targets` — run TWICE (env-race flake check)
> Builder claims `596 passed; 0 failed` and an env-race fix. Verified.

| Run | Result | Detail |
|-----|--------|--------|
| 1 | **PASS** | 596 passed; 0 failed. load_test 8/0 in 0.74s. |
| 2 | **PASS** | 596 passed; 0 failed. load_test 8/0 in 0.70s. |

- Env-race tests (the builder's fix target) both green on both runs:
  - `daemon::tests::pid_path_is_in_config_dir ... ok`
  - `daemon::tests::config_dir_is_dot_cerberus ... ok`
  - `mitm::tests::strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime ... ok`
- **Result: PASS** — env-race fix VERIFIED across 2 consecutive release runs.

## 5. `python3 tools/simulate.py`
- Command: `python3 tools/simulate.py`
- Output: `RESULTADO: 29 PASS / 0 FAIL`
- Transcript: `evidence/sim/sim-run-20260821-235854.log`
- **Result: PASS** (matches builder claim exactly)

## 6. F9 unit standalone tests (debug, as evidence packs cite them)
| Command | Result | Time |
|---------|--------|------|
| `cargo test --test redos_fuzz` | 8 passed; 0 failed | 0.10s |
| `cargo test --test load_test` | 8 passed; 0 failed | 1.04s |
| `cargo test --test failsafe` | 10 passed; 0 failed | 0.00s |

- **Result: PASS** for all three standalone. (Note: `load_test` passes standalone but flakes under parallel workspace load — see §3.)

## 7. Component evidence the builder cites (verified to exist + pass in workspace run)
| Claim | Verified |
|-------|----------|
| `cerberus-packs` telemetry no-leak: `payload_has_no_secrets_fields` (telemetry.rs:495) | ✅ exists, test fn present |
| `cerberus` feedback no-raw: `dev_feedback_line_has_flag_and_hash_never_raw` (feedback_ux.rs:380) | ✅ exists |
| `cerberus-store` no-leak (22 tests) | ✅ 22/0 in release |
| MITM fail-closed before bind: `mismatched_ca_pair_fails_closed_before_listener_bind` (forward.rs:1015) | ✅ exists |
| MITM tampered CA rejected: `strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime` (mitm.rs:399) | ✅ exists |
| forward.rs no-leak: `connect_tls_redacts_before_forwarding_and_audit_has_no_raw_secret`, `..._without_audit_leak`, `..._without_leak` | ✅ exist (20 forward tests total) |

## Criterion summary (§8B.6 F9 units)
| Criterion | Command | Observed | Result |
|-----------|---------|----------|--------|
| fmt | `cargo fmt --all -- --check` | 0 diffs, exit 0 | ✅ |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | No issues, exit 0 | ✅ |
| debug workspace | `cargo test --workspace --all-targets` | **2/3 FAIL** (load_test flake) | ❌ |
| release workspace (×2) | `cargo test --release --workspace --all-targets` | 596/0 ×2, env-race fixed | ✅ |
| simulate | `python3 tools/simulate.py` | 29/0 | ✅ |
| redos-fuzz | `cargo test --test redos_fuzz` | 8/0 | ✅ |
| load-test | `cargo test --test load_test` (debug) / `--release` | 8/0 standalone; 8/0 release | ✅ (unit) |
| failsafe | `cargo test --test failsafe` | 10/0 | ✅ |

**Gate verdict: FAIL on the debug-workspace criterion (flaky 2/3). All other criteria PASS.**
