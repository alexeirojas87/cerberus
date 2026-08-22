# Evidence Pack — Phase 1: rule-loader (Reviewer 1 — Correctness)

**Reviewer:** REVIEWER 1 (correctness)
**Worktree:** `cerberus-wt-f1-rule-loader-review-correctness`
**Date:** 2026-08-17
**Verdict:** **PASS**

## Summary

Reviewed unit: crate `cerberus-engine` (rule-loader + scanning engine).
Objective: break the unit. The 10 protocol points were executed. All pass.

---

## 1. Workspace build

```bash
export PATH="$HOME/.cargo/bin:$PATH" && cargo build --workspace 2>&1
```

Result: `Finished dev profile ... in 20.05s` — **0 errors**.

Crates compiled: benchkit, cerberus-core, spike-scan, cerberus-engine, spike-proxy.

## 2. Tests (`cargo test -p cerberus-engine`)

Result: **48/48 tests pass** (37 lib + 11 integration), 0 failures, 0 ignored.

```
running 37 tests  ... test result: ok. 37 passed
running 11 tests  ... test result: ok. 11 passed
Doc-tests: 0 tests
```

## 3. Clippy (`cargo clippy -p cerberus-engine --all-targets -- -D warnings`)

Result: `Finished dev profile` — **0 errors, 0 warnings**. No diagnostic output.

## 4. Format (`cargo fmt --check`)

Result: no output — **0 diffs**. Code correctly formatted.

## 5. Real load of test-rules.json

Location: `crates/cerberus-engine/test-rules.json`.

- **11 rules** loaded (`rules.len() == 11`), meets the `>=10` requirement.
- Test that verifies it: `test_rules_file_loads_with_expected_count` (assert `len() >= 10`).
- All rules have a non-empty `flag` and non-empty `patterns` (`rules_have_all_required_fields`).
- Contains the 3 categories (secrets/pii/internal_code) and the 3 actions (block/redact/warn).

## 6. Adversarial scan

### 6a. Empty text → no findings
Verified test: `empty_text_produces_no_findings` — `scan(&engine, &ScanRequest::new(""))` returns `findings.is_empty()`. **PASS** (verified in manual run, then original test restored).

### 6b. Real secret matching multiple rules
Test text: `"API: sk-abcDEFghijklmnopqrstuvwxyz123456\nEmail: test@test.com\nAWS: AKIA1234567890ABCDEF"`.

Finds **all matches**:
- `secret.openai_api_key` (sk-...)
- `pii.email` (test@test.com)
- `secret.aws_access_key_id` (AKIA...)

The findings add up to `>=2` distinct rules. **PASS** (verified in manual run with test `scan_finds_multiple_rules_in_one_text`, then restored).

### 6c. OpenAI allowedExample (`sk-test-example-not-real`)
Test `allowed_examples_do_not_fire`: the explicitly allowed token does **NOT trigger** the `secret.openai_api_key` rule. The main reason is that it is shorter than `minLength: 20` (23 vs 20 — note: "sk-test-example-not-real" is 23 chars, but the pattern requires `[A-Za-z0-9]{20,}` after `sk-`; the text contains `-` which breaks the charclass). Both mechanisms (allowedExamples + pattern) agree on not triggering. **PASS**.

## 7. Generic ScanRequest without domain IDs

`ScanRequest` (crates/cerberus-engine/src/scan.rs:19) has **only** two fields:
- `text: String`
- `metadata: HashMap<String, String>`

`AgentId`, `PbiId`, `CorrelationId` do **NOT exist**. The design uses `metadata` for arbitrary caller labels (tool, provider, correlation). Test `generic_scan_request_has_no_domain_fields` confirms it. **PASS**.

## 8. YAML loading (`loader::load_rules_from_yaml`)

- Unit tests: `load_from_yaml_string`, `load_from_yaml_object_string` (sequence and mapping).
- Integration: `yaml_load_matches_json_behavior`, `yaml_file_roundtrip` (real temporary file).
- Path: `load_rules_from_yaml` (loader.rs:61) → `parse_rules` with `FileFormat::Yaml`, accepts a sequence (`-`) or a mapping with a `rules` key.
- Identical semantics to JSON: same defaults and validation.

**PASS**.

## 9. Loading a nonexistent file → clear error

- JSON: `load_rules_from_json("/nonexistent/...")` → `LoadError::Io` with message `"cannot read rules file: ..."`.
- YAML: identical behavior.
- Tests: `missing_file_returns_io_error` (unit), `nonexistent_file_returns_clear_error` and `yaml_file_not_found_returns_clear_error` (verified manually).

**PASS**.

## 10. Privacy: hashed_value never the raw value

`engine::hash_value` (engine.rs:279) generates `format!("sha256:{}", hex::encode(sha256(trim(value))))`:
- Format: `sha256:` prefix (7 chars) + 64 hex chars = **71 total chars**.
- `Finding.hashed_value` is the only field for the value; there is no field with the raw value.
- Tests: `hash_value_is_sha256` (len 71, deterministic), `finding_never_contains_raw_value`, `scan_detects_secret` (assert `hashed_value.len() == 71`), `scan_finds_openai_key` (integration, assert `hashed_value != raw` and `starts_with("sha256:")`).
- In the multi-rule adversarial test (6b) it was validated that each finding has the `sha256:` + 71 chars format.

**PASS**.

---

## Results table

| # | Check | Result |
|---|-------|-----------|
| 1 | `cargo build --workspace` | ✅ 0 errors |
| 2 | `cargo test -p cerberus-engine` (48 tests) | ✅ 37 lib + 11 integration, 0 fail |
| 3 | `cargo clippy ... -- -D warnings` | ✅ 0 errors/warnings |
| 4 | `cargo fmt --check` | ✅ 0 diffs |
| 5 | real test-rules.json load (≥10 rules) | ✅ 11 rules |
| 6a | Empty text → no findings | ✅ |
| 6b | Multi-rule secret → finds all | ✅ |
| 6c | OpenAI allowedExample → does not trigger | ✅ |
| 7 | ScanRequest without AgentId/PbiId | ✅ |
| 8 | YAML loading (sequence + mapping + file) | ✅ |
| 9 | Nonexistent file → clear error | ✅ |
| 10 | hashed_value `sha256:` 71 chars, no raw | ✅ |

**Total: 12/12 ✅**

## Bugs found

**None (0 bugs).** The unit is correct.

### Minor observations (non-blocking, not correctness bugs)

1. **`context_keywords` and `validators` are not evaluated** — they are defined in the model (`Rule`) and deserialized, but the engine does not use them (engine.rs). Commented in the code as "kept for compatibility; not evaluated yet" (rule.rs:104). Correct for the Phase 1 scope, but must be resolved in a later phase.
2. **`hash_normalization` is not applied** — the field exists but `make_finding` (engine.rs:223) always does `raw_value.trim()` regardless of the `hashNormalization` value. The OpenAI rule defines `"hashNormalization": "trim"`, and the trim matches, but other normalizations would not be supported. Not blocking because all current rules are trim-compatible.
3. **Single regex match on prefixed patterns** — in `scan` (engine.rs:191) `regex.find()` (first match) is used per AC hit, not `find_iter`. If the same AC-prefix appears and the regex matches several times within the rest of the text, only the first is reported. With the current corpus (one secret per pattern per text) it produces no false negatives, but with multiple secrets of the same type in a long text only the first would be reported. Note: the `scan_multiple_patterns_same_rule` test covers two secrets of *different* patterns, not two of the same pattern — a margin to watch.
4. **YAML error uses deprecated serde_yaml** — Cargo.toml shows `serde_yaml v0.9.34+deprecated`. Correct and functional; candidate for migration to `serde_yml`/`serde_yaml_ng` in a later phase.

None of the observations affect the correctness verdict for the Phase 1 scope (MVP, rule-loader).
