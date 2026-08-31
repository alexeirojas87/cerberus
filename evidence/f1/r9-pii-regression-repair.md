# Evidence Pack — F1/R9 PII regression repair

- Attempt: 8 (four reported regressions plus adversarial FIX loops)
- Date: 2026-08-31 (America/New_York)
- Independent panel: `final_correctness_gate`, `final_security_gate`, `final_performance_gate`
- Verdict: **PASS (3/3 panel)**
- Human sign-off: **APPROVED — 2026-08-31**
- Unit status: **CLOSED**
- Scope: F1.2 shipped-pack PII detection and its structured JSON context path

## Acceptance criteria

| Criterion | Command / evidence | Output | Result |
|---|---|---|---|
| Adjacent PANs with the same separator remain distinct | engine focal tests plus independent CLI reproduction | exact spans `(0,19)` and `(20,39)` | PASS |
| Valid PANs survive a complete invalid block; fragments never form a FrankenPAN | `kind_change_splits_only_between_complete_pans` | valid-invalid-valid returns `(0,19)` and `(40,59)`; both FrankenPAN regressors return none | PASS |
| PAN issuer handling covers MIR/Maestro without rejecting valid non-`+` ISO/Luhn PANs | validator tests plus independent CLI reproduction | MIR 2200/2204 and Maestro 6759 pass; unknown issuer passes without `+`; anti-phone behavior preserved | PASS |
| Unicode context matching is case-insensitive with stable offsets and Unicode-safe boundaries | constraints focal tests | uppercase/accented keywords pass; `İ` expansion stays on the correct line; combining marks and ZWJ do not create boundaries | PASS |
| Canonical compact E.164 is detected without context | production pack focal test | `+14155552671` is `pii.phone_number`; 6/16-digit out-of-range controls are none | PASS |
| Exact shipped pack identity and measured precision/recall remain valid | release product gate | 19/19; 58 TP, 0 FP, 0 FN; every evaluable category/flag 100% precision and recall | PASS |
| JSON leaf scans reuse one normalized context and scale with leaf count | release many-leaf gate + independent performance review | 50 KB/64 leaves p99 0.359 ms; 50 KB/512 leaves p99 0.515 ms | PASS |
| Workspace hygiene, build and tests | commands below | all exit 0 | PASS |

## Final Gauntlet commands

```text
rtk cargo fmt --all -- --check
rtk git diff --check
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo build --workspace --all-targets
rtk cargo test --workspace --all-targets
rtk cargo test --release -p cerberus-packs --test production_pack_pr -- --test-threads=1 --nocapture
rtk cargo test --release --test redos_fuzz -- --test-threads=1 --nocapture
rtk cargo test --release --test load_test -- --test-threads=1 --nocapture
rtk cargo test --release --workspace --all-targets
```

```text
fmt: PASS
diff-check: PASS
clippy: PASS, no issues
build: PASS
workspace debug: 654 passed, 25 suites
product pack release: 19 passed
ReDoS release: 11 passed
load release serial: 12 passed
workspace release: 654 passed, 25 suites
```

The plan-budget load gate uses 500 samples in release (200 in debug) without
changing its thresholds. Three consecutive final serial runs passed. Observed
ranges included PAN-dense 100 KB p50 0.778–0.786 / p99 0.888–0.928 ms,
NBSP-only 100 KB p50 0.832–0.861 / p99 0.980–1.070 ms, and mixed-PAN
recovery with 5,536 findings p50 2.828–2.846 / p99 3.135–4.451 ms. The
documented release guards remain p50 `<1 ms` and p99 `<2 ms` for the 100 KB
scan shapes, and p50/p99 `<8 ms` for the emission-dominated recovery shape.

The permanent JSON proxy-path guard fixes the body near 50 KB and checks both
64 and 512 string leaves. The final independent run measured 64 leaves at
p50 0.268 / p99 0.359 ms and 512 leaves at p50 0.413 / p99 0.515 ms. An 8x
leaf increase therefore remained well below the official `<5 ms` p99 budget.

## Adversarial cases and FIX history

- The first adjacent-PAN repair failed two pack tests: it required a maximal
  separator run to be fully valid and chose accidental Luhn cuts. The final DP
  selects bounded 13–19 digit chains, preserves valid segments around a
  complete invalid block, rejects short tails, and allows only a compact fresh
  suffix after an invalid prefix.
- Independent review found two fragment combinations that formed synthetic
  FrankenPANs. Both are permanent negative regressions:
  `1111111111111 4444 9000000000007` and
  `1111111111111 4444 900000000007`.
- Unicode review found lowercase expansion offset drift plus combining-mark and
  ZWJ boundary errors. Original/lower line maps are separate and boundaries now
  follow regex `\w`, while underscore deliberately remains a keyword separator
  for identifiers such as `OPENAI_API_KEY`.
- Performance review first measured PAN 100 KB p50 about 1.26 ms and debug NBSP
  p50 103 ms. Unreachable fresh DP states were removed; the final scan remains
  linear with a bounded 19-digit look-back.
- Performance review then reproduced JSON `O(leaves × body)` behavior (64-leaf
  p99 30.113 ms). `redact_json` now creates one `ContextAnalyzer` per body and
  `keyword_anywhere` caches each keyword-set result. The permanent 64/512-leaf
  gate proves the repaired scaling.
- One final NBSP p99 run hit 2.267 ms under OS contention. The threshold was not
  relaxed; release sampling increased from 200 to 500. Three subsequent full
  serial batteries passed with NBSP p99 0.980–1.070 ms.

## Independent panel

- **Correctness PASS:** engine 228, proxy JSON 5 and product pack 19 passed;
  exact adjacent/gapped PAN spans, issuer cases, Unicode offsets/boundaries,
  compact E.164, JSON cross-field context and both FrankenPAN controls were
  independently reproduced.
- **Security PASS:** release ReDoS 11/11; PAN/phone downgrade, Unicode `\w`
  parity, two FrankenPANs, valid-invalid-valid recovery and multibyte paths all
  passed. No raw PII appeared in findings/log checks for this unit.
- **Performance PASS:** release load 12/12; PAN paths are linear and the shared
  JSON analyzer/cache removes the body-per-leaf rescan. The reviewer repeated
  both 64- and 512-leaf gates below 1 ms p99.

## Frozen final hashes

```text
2eca99c366fca939a774427229c487c429cf66bfb48006adb67104916457e9e2  Cargo.toml
ff9b17880524f292eea6569e368369b8d22c81457b1ec32c4898f6ca7813e922  crates/cerberus-engine/src/engine.rs
595ff762949c8c504383aed504c608d1293854ff85cb9c3e44bd427ca9142765  crates/cerberus-engine/src/constraints.rs
714ab59a8fe56c87e0b3cdcb6a66a1f5b9d224b2eaa50c6ea20f41f570a80ad6  crates/cerberus-engine/src/validator.rs
66679c8abbc3e2355a31161afa0fdba045acacb99f40c1f9903ee6b828fd5610  crates/cerberus-packs/src/default_pack.rs
49fe71a58c00fcfb5787a39ce5dc65ab62f63e2581340308ce5ad0bc0230a192  crates/cerberus-proxy/src/json_redact.rs
33bf4c7a12133dc946ac6b03d896748266e255e128ae1b4dbcd4167fb6da9e21  crates/cerberus-packs/tests/production_pack_pr.rs
f9265040f9cb0e18770ca1dfb8a63dc9bab805ad33bbcfd29d7e0dcb33bd77e5  tests/load_test.rs
e13bd318c3680fb67e9eaa0b10bd07b832de1246f78a5c44b8c9355542ba9f35  evidence/f1/raw/production_pack_pr.json
```

Toolchain: `rustc 1.97.1`, `cargo 1.97.1`; host: Darwin 25.5.0 arm64.

## Limits and phase gate

- The shipped PAN grammar remains deliberately bounded to 1–3 ASCII
  space/NBSP characters or one `.`, `/`, `-`; other Unicode whitespace is a
  documented residual risk, not part of these four reported regressions.
- The existing contract uses Unicode `to_lowercase`, not locale/full Unicode
  case-fold equivalences such as `ß → ss`.
- Human sign-off closes this F1.2 repair unit only. It does not clear the
  Review 9 containment register, prove memory zeroization, or authorize a
  release. The repository remains stopped at the phase gate pending closure
  and integration review of the other invalidated units.
