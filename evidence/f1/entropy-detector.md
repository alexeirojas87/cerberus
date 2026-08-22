# Evidence Pack — F1/entropy-detector
- Attempt: 1    Reviewer: BUILDER (self-verify)    Verdict: PASS

## Acceptance criteria

| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| Compiles | `cargo build -p cerberus-engine` | `Finished dev profile` | ✅ |
| Tests pass | `cargo test -p cerberus-engine` | `53 passed; 11 passed; 0 failed` | ✅ |
| Clippy | `cargo clippy -p cerberus-engine --all-targets` | `Finished, no warnings` | ✅ |
| Format | `cargo fmt -p cerberus-engine --check` | `FMT OK` | ✅ |
| Shannon entropy `("aaaa") ≈ 0.0` | `entropy::tests::entropy_repeated_char` | PASS | ✅ |
| Shannon entropy `("sk-abc...") > 4.0` | `entropy::tests::entropy_high_random_token` | PASS | ✅ |
| `password=abc123` → not detected | `entropy::tests::detect_low_entropy_near_keyword_no_finding` | PASS | ✅ |
| `password=J8sK2m9x...` → detected | `entropy::tests::detect_high_entropy_near_keyword` | PASS | ✅ |
| No keywords → not detected | `entropy::tests::detect_no_keywords_no_findings` | PASS | ✅ |
| Engine integration: findings are added | `engine::tests::scan_detects_secret` (2 findings: regex + entropy) | PASS | ✅ |
| Short value (< 8 chars) not detected | `entropy::tests::detect_short_value_no_finding` | PASS | ✅ |
| Case-insensitive keywords | `entropy::tests::detect_case_insensitive_keyword` | PASS | ✅ |
| JSON-style `{"password": "..."}` | `entropy::tests::detect_json_style` | PASS | ✅ |
| Hash ≠ raw value | `entropy::tests::detect_hashed_value_not_raw` | PASS | ✅ |
| Multiple keywords, only high entropy | `entropy::tests::detect_within_window_multiple_keywords` | PASS | ✅ |

## Adversarial cases tested

- **Empty string**: `shannon_entropy("")` = 0.0 ✅
- **Repetitive**: `shannon_entropy("aaaa")` ≈ 0.0 ✅
- **Low entropy**: `shannon_entropy("abc123")` < 3.0 ✅
- **High entropy**: `shannon_entropy("J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE")` > 4.0 ✅
- **Hashed secret**: Finding.hashed_value never contains the raw value ✅
- **Text without keywords**: 0 findings ✅
- **Keyword with short value**: not detected (min 8 chars) ✅
- **Integration with existing engine**: entropy findings are added to the regex scan findings ✅
- **Normal operation unchanged**: pre-existing tests still pass (scan_no_secrets, action_per_rule_honoured, etc.) ✅

## Applicable NFRs
- No new dependencies (only the existing `regex` + std math)
- No secret leakage: findings use `hash_value` (SHA-256), never the raw value
- Latency: O(n) in bytes for entropy, O(k * w) for detection (k = keywords, w = 200-char window)

## Modified files

| File | SHA-256 | Change |
|---------|---------|--------|
| `crates/cerberus-engine/src/entropy.rs` | `f839b0bdbbd29cc909602633126d750f1df62507ecbbbefea01ba004de9c9be5` | New: Shannon entropy + generic detector |
| `crates/cerberus-engine/src/engine.rs` | `1d31a3d3cf899e47f0da2d3570d89af5efd15d615ea95f9037231a6c4f1b069c` | Modified: entropy integration in scan + builder |
| `crates/cerberus-engine/src/lib.rs` | `6ba810ba3ce30359d56b52d1127f39ff05464911986c2213768c0f9ec1fa8fba` | Modified: `pub mod entropy;` |

## Deviations
- None. Implementation follows the build plan spec §4.3 and §8 F1.
- Default threshold 4.0 configurable via `EngineBuilder::with_entropy_threshold()`.
- Flag: `entropy.high_entropy_secret`, category: `Secrets`, severity: `Medium`, action: `Warn`.
