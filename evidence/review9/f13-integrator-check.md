# Evidence — F1 integration review (F1.3 attempt-6 candidate)

- **Candidate:** `fdebc39dbf974892337ee5f20162e0480708249f` @ `origin/r9-remediation` (https://github.com/alexeirojas87/cerberus.git, branch `r9-remediation`)
- **Clone path:** `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f1-integrator-clone`
- **Date:** 2026-08-31 (verification window ~20:30–20:55 UTC)
- **Host:** Alexei-MacBook-Pro.local — Darwin 25.5.0, arm64 (Apple Silicon T6041), 12 cores, 24 GB RAM. Load averages at start: 7.41 / 7.02 / 7.17 (host was NOT quiet; no build was launched by the reviewer during the run).
- **Toolchain:** rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1 (c980f4866 2026-06-30)
- **Method:** clean `git clone --branch r9-remediation` from origin; `git rev-parse HEAD` == `fdebc39dbf974892337ee5f20162e0480708249f` (exact match, verified before any step). Zero code or test edits were made anywhere. All commands recorded verbatim with exit codes.

## Remote state

`git log --oneline -6` (exit 0):

```
fdebc39 fix(f1): F1.3 attempt 6 — conservative non-ASCII entropy fallback restores Unicode-folded keyword detection (P1)
3e20fd6 fix(f1): F1.1 evidence pack - precompiled multiline/entropy regexes (unit CLOSED)
4683dd4 fix(f1): engine precompiled regex reuse + single-pass presence automaton + individual-scan throughput gate (F1.3 attempt 5)
786c576 fix(f1): shipped-pack PII repair + production precision/recall gate (R9-9)
7320f85 fix(g0): inert release/notify-tap workflows + Review 9 findings, fix plan, containment evidence
fccd9e4 fix(ci): use $HOME directly in config_dir instead of dirs::home_dir
```

`git status` (exit 0): `On branch r9-remediation` / `Your branch is up to date with 'origin/r9-remediation'.` / `nothing to commit, working tree clean` — **CLEAN**.

Containment (G0 freeze) — both workflows inert, quoted decisive lines:

- `.github/workflows/release.yml`:
  - L14: `"on": []` (inert for every ref)
  - L16–17: `permissions:` / `contents: read`
  - L20–22: `jobs:` / `review9_release_freeze:` / `if: ${{ false }}`
  - L27–28: single step `run: |` / `exit 1` (unreachable fail-closed guard)
- `.github/workflows/notify-tap.yml`:
  - L7: `"on": []`
  - L9–10: `permissions:` / `contents: read`
  - L13–15: `review9_tap_freeze:` / `if: ${{ false }}`
  - L20–21: `run: |` / `exit 1` (unreachable fail-closed guard)

**Containment verified.** No triggers, no write permissions, no bypass, no release-producing job.

## Frozen-hash verification

`shasum -a 256` over the clone vs. hashes frozen in the evidence packs (F1.3 attempt-6 block: `evidence/f1/r9-engine-throughput.md` L226–233; F1.2 pack: `evidence/f1/r9-pii-regression-repair.md` L105–113).

| File | Pack | Expected (frozen) | Observed | Match |
|---|---|---|---|---|
| `crates/cerberus-engine/src/engine.rs` | F1.3 attempt-6 | `87bacec2dae044e119582353f68c4051b95bb0cb26ed4157599b2c718ded36e8` | `87bacec2dae044e119582353f68c4051b95bb0cb26ed4157599b2c718ded36e8` | ✅ |
| `crates/cerberus-engine/src/entropy.rs` | F1.3 attempt-6 | `36e956db39d89e76becda3f71898d14bc24d3109a6641ecb7878734e93cdb285` | `36e956db39d89e76becda3f71898d14bc24d3109a6641ecb7878734e93cdb285` | ✅ |
| `crates/cerberus-engine/Cargo.toml` | F1.3 attempt-6 | `58a05566fe10114dcb1b81c80ef649f2d9a536530adfe84c15cc78ec5833bb57` | `58a05566fe10114dcb1b81c80ef649f2d9a536530adfe84c15cc78ec5833bb57` | ✅ |
| `Cargo.lock` | F1.3 attempt-6 | `583ec84cd5d462c6d2347fdce3828549ba0ff058f6b2c435004b6a94bdfa03c9` | `583ec84cd5d462c6d2347fdce3828549ba0ff058f6b2c435004b6a94bdfa03c9` | ✅ |
| `crates/cerberus-engine/src/constraints.rs` | F1.2 | `595ff762949c8c504383aed504c608d1293854ff85cb9c3e44bd427ca9142765` | `595ff762949c8c504383aed504c608d1293854ff85cb9c3e44bd427ca9142765` | ✅ |
| `crates/cerberus-engine/src/validator.rs` | F1.2 | `714ab59a8fe56c87e0b3cdcb6a66a1f5b9d224b2eaa50c6ea20f41f570a80ad6` | `714ab59a8fe56c87e0b3cdcb6a66a1f5b9d224b2eaa50c6ea20f41f570a80ad6` | ✅ |
| `crates/cerberus-packs/src/default_pack.rs` | F1.2 | `66679c8abbc3e2355a31161afa0fdba045acacb99f40c1f9903ee6b828fd5610` | `66679c8abbc3e2355a31161afa0fdba045acacb99f40c1f9903ee6b828fd5610` | ✅ |
| `crates/cerberus-proxy/src/json_redact.rs` | F1.2 | `49fe71a58c00fcfb5787a39ce5dc65ab62f63e2581340308ce5ad0bc0230a192` | `49fe71a58c00fcfb5787a39ce5dc65ab62f63e2581340308ce5ad0bc0230a192` | ✅ |
| `crates/cerberus-packs/tests/production_pack_pr.rs` | F1.2 | `33bf4c7a12133dc946ac6b03d896748266e255e128ae1b4dbcd4167fb6da9e21` | `33bf4c7a12133dc946ac6b03d896748266e255e128ae1b4dbcd4167fb6da9e21` | ✅ |
| `evidence/f1/raw/production_pack_pr.json` | F1.2 | `e13bd318c3680fb67e9eaa0b10bd07b832de1246f78a5c44b8c9355542ba9f35` | `e13bd318c3680fb67e9eaa0b10bd07b832de1246f78a5c44b8c9355542ba9f35` | ✅ |

**Result: 10/10 exact match — zero exceptions.** F1.2-era files are byte-identical to their closure state; the F1.3 attempt-6 freeze is exactly what was pushed.

Note (expected, not a failure): F1.1's frozen `engine.rs`/`entropy.rs` hashes (`d8d19bc1fb9514d4aa649fdaa4b477e9cc995c8f4a68a68acbe53d9c30d3d78c` / `5e19e2ed2c17ee0568098e8ad29f4ef55c21d205dd69b044997c39bd1be3d5c6`, recorded in `evidence/f1/r9-regex-compiler.md`) are **historical** and were superseded/re-frozen by F1.3's attempt-6 block — the current files match the F1.3 freeze above, as intended by the fix lineage (`fdebc39` → attempt 6 replaced attempt 5's freeze `1862da84…`/`55a10e62…`).

## Full battery

All runs sequential on this clone; cold builds; no concurrent builds launched by the reviewer (host load ~7 was pre-existing ambient load from other processes, not from this verification).

| # | Command (verbatim) | Exit | Result |
|---|---|---|---|
| 1 | `rtk cargo fmt --all -- --check` | 0 | clean |
| 2 | `rtk cargo clippy --workspace --all-targets -- -D warnings` | 0 | 0 issues |
| 3 | `rtk cargo test --workspace --all-targets` | 0 | **664 passed / 0 failed** (25 suites, 48.95 s, debug) |
| 4 | `rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1 --nocapture` | 0 | **19 passed / 0 failed** (1.63 s) |
| 5 | `rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture` | 0 | **11 passed / 0 failed** (0.05 s) |
| 6 | `rtk cargo test --release --test load_test -- --test-threads=1 --nocapture` | 0 | **13 passed / 0 failed** (5.66 s) |
| 7 | `rtk proxy cargo test --release --test load_test load_test_f1_3_engine_throughput_gate -- --nocapture --test-threads=1` (×3 consecutive serial runs) | 0/0/0 | **3/3 PASS** — see table below |
| 8 | `rtk cargo test --release --workspace --all-targets` | 0 | **664 passed / 0 failed** (25 suites, 11.46 s, release) |
| 9 | `git diff --check` | 0 | clean (no output) |

Post-battery `git status --short`: empty — `Cargo.lock` was **not** modified by any build (no dependency drift; lockfile is exactly the frozen `583ec84c…` state).

## F1.3 gate reproduction (3-run table)

`load_test_f1_3_engine_throughput_gate`, serial, `--test-threads=1`, release profile, payload 102400 B, 100 warmup + 8000 measured scans per sample; strict p99 budget 1.0 ms. Workload fingerprints match the frozen pack exactly: default `sha256:b632f5a659f81185f92304beff08f8bb4c60c1e9f20fbfd1df0aa1d386f5220f`, max_mvp_policy `sha256:40884edfb6bca9e2200e1975cbc4108cdae81d3a175304fb6d6c659bce7b5992`.

| Run | Scenario | p50 (ms) | p95 (ms) | p99 (ms) | Budget | Result |
|---|---|---:|---:|---:|---:|---|
| 1 | default | 0.179916 | 0.185709 | 0.198625 | < 1.0 strict | PASS |
| 1 | max_mvp_policy | 0.265417 | 0.276750 | 0.298041 | < 1.0 strict | PASS |
| 2 | default | 0.180542 | 0.187125 | 0.204000 | < 1.0 strict | PASS |
| 2 | max_mvp_policy | 0.265458 | 0.276167 | 0.294709 | < 1.0 strict | PASS |
| 3 | default | 0.180417 | 0.188584 | 0.226209 | < 1.0 strict | PASS |
| 3 | max_mvp_policy | 0.265750 | 0.278583 | 0.305875 | < 1.0 strict | PASS |

Worst observed p99 across all 6 scenario-runs: **0.305875 ms** (max_mvp_policy, run 3) — 3.3× headroom under the 1.0 ms strict budget. Every run also reproduced the exact same workload fingerprints as the builder's frozen series, so the gate decision is bound to identical inputs.

## Verdict: PASS

Independent reproduction from a clean clone of `fdebc39` @ `origin/r9-remediation` confirms the full F1 battery: 10/10 frozen-hash matches (F1.3 attempt-6 freeze byte-identical on the pushed remote; F1.2-closure files untouched), G0 containment intact (both workflows inert with `"on": []`, `contents: read`, `if: ${{ false }}` + `exit 1` guards), fmt/clippy clean, 664/0 test passes in both debug and release, 19/19 production-pack precision/recall, 11/11 ReDoS fuzz, 13/13 load suite, and 3/3 consecutive strict F1.3 gate reproductions (worst p99 0.305875 ms vs 1.0 ms budget) on a host carrying ambient load ~7. The F1.3 attempt-6 candidate's fresh-panel claims (2/2 PASS correctness+security) and the builder's frozen 5/5 performance series are independently corroborated end-to-end from the pushed remote state, with zero local-history contamination and zero dependency drift (Cargo.lock unmodified by builds). The F1 phase gate stands on a PASS.

## Notes

- **Host contention:** load averages were 7.41/7.02/7.17 at battery start (ambient load from other host processes, machine up 9 days). Despite this, all 6 gate scenario-runs stayed ≤ 0.31 ms p99 — comfortably strict-PASS. This is *harder* conditions than a quiet runner; it strengthens, not weakens, the verdict. The builder's frozen series itself disclosed 4 non-passing runs under load-average 6–10 with stable p50s — consistent with the behavior observed here.
- **Performance carry-over justification:** the only code delta in `fdebc39` vs the attempt-5 frozen series is the entropy-fallback repair (engine.rs/entropy.rs); the builder's 5/5 frozen-code performance series (F6–F10 qualifying runs, worst p99 0.459958 ms maximum / 0.411750 ms default, pack lines 210–224) carries over because attempt-6 froze those exact hashes, and my independent reproduction re-measured the gate directly on attempt-6 code anyway (3/3, above) — so the F1.3 performance claim does not lean on carry-over alone; it is re-measured.
- **Dependency drift check:** builds were cold; `git status --short` empty afterwards confirms `Cargo.lock` byte-stability through fmt/clippy/debug/release builds.
- **No edits:** no code, test, or workflow file was modified anywhere. Clone left in place at the temp path for the orchestrator to clean up. Gate run logs are at `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f1-gate-run{1,2,3}.log`.
- **Battery counts cross-check:** debug 664 (25 suites) == release 664 (25 suites); load_test 13 (12 filtered out in the single-gate run, consistent with 13-test suite); production_pack_pr 19; redos_fuzz 11 — all match the F1.3/F1.2 pack expectations exactly.
