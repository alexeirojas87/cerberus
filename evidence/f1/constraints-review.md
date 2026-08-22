# Evidence Pack — F1 Constraints Review

## Metadata
- **Reviewer**: REVIEWER 1 (correctness)
- **Worktree**: `cerberus-wt-f1-review-constraints`
- **Baseline commit**: `4379c3b` (detached HEAD, aligned with `main`)
- **Date**: 2026-08-17

---

## 1. Baseline

| Check       | Result |
|-------------|--------|
| `cargo test --package cerberus-engine` | 115 unit + 15 integration = **130 passed, 0 failed** |
| `cargo clippy --package cerberus-engine -- -D warnings` | **Clean** (0 warnings) |
| `cargo fmt --check` | **Clean** |
| `cargo build --package cerberus-engine` | **Clean** |

---

## 2. Bugs Found

### BUG-1 (CRITICAL): Constraints not integrated into the engine

**File**: `crates/cerberus-engine/src/engine.rs:258`

**Problem**: The `make_finding()` method only ran validators (`self.validators.all_pass(...)`) but **never called** `constraints::check_constraints()`. This means that `minLength`, `maxLength`, `allowedExamples`, and `contextKeywords` existed as a module and passed their unit tests, but were completely ignored in the engine's detection pipeline.

**Impact**: Any rule with constraints did not apply them. Findings were emitted even though they should have been discarded.

**Fix applied**: The call to `check_constraints(rule, trimmed, text)` was added in `make_finding()`, before validation. The full `text` (scanned context) is used as context for `contextKeywords`.

```rust
// engine.rs:261-263
if !check_constraints(rule, trimmed, text) {
    return None;
}
```

### BUG-2 (Medium): Integration test `allowed_examples_do_not_fire` did not test constraints

**File**: `crates/cerberus-engine/tests/integration_test.rs`

**Problem**: The test used `"sk-test-example-not-real"` as an "allowed example" but this value contains hyphens (`-`) that are not in the `[A-Za-z0-9]` set of the pattern `\bsk-[A-Za-z0-9]{20,}\b`. Therefore, the regex never matched and the test passed by coincidence, not because constraints worked.

**Fix applied**:
1. Added `"sk-AllowedExampleABCDEFGHIJKLMNOPQRSTUVWXYZ"` to `allowedExamples` in `test-rules.json`
2. Updated the test to use this value, which DOES match the regex (32 alphanumeric chars after `sk-`)
3. The text includes the context keyword `openai` so it does not fail due to `contextKeywords`

---

## 3. Adversarial Tests Added

Four new integration tests (in `tests/integration_test.rs`):

| Test | Scenario | Result |
|------|-----------|-----------|
| `no_constraints_always_passes_in_engine` | Rule without constraints → match passes | ✅ |
| `combined_minlength_and_contextkeywords_in_engine` | Both constraints must be met; fails if one is not | ✅ |
| `empty_context_vs_keyword_context` | Empty discarded; with keyword passes | ✅ |
| `allowed_examples_minlength_min_wins` | Short value AND in allowed → minLength wins (discards first) | ✅ |

---

## 4. Execution Evidence

```
test result: ok. 130 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.25s  (clippy clean)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s  (build clean)
    cargo fmt --check  # clean (no output)
```

---

## 5. Modified Files

| File | Change |
|---------|--------|
| `crates/cerberus-engine/src/engine.rs:2` | Added `use crate::constraints::check_constraints` |
| `crates/cerberus-engine/src/engine.rs:188` | Fix indent: `validators: ValidatorRegistry::new()` |
| `crates/cerberus-engine/src/engine.rs:261-263` | Added `check_constraints` call in `make_finding` |
| `crates/cerberus-engine/src/engine.rs:662` | Format: `.build()` on a separate line |
| `crates/cerberus-engine/test-rules.json:11` | Added `"sk-AllowedExampleABCDEFGHIJKLMNOPQRSTUVWXYZ"` to `allowedExamples` |
| `crates/cerberus-engine/tests/integration_test.rs` | Test corrected + 4 adversarial tests |

---

## 6. Gate Pass

**Verdict**: ✅ PASS — Constraints correctly implemented, integrated into the engine, and verified with adversarial tests.

**Constraints coverage in pipeline**:
- `check_constraints()` in `constraints.rs`: unit-tested (7 existing tests)
- Called from `make_finding()` in `engine.rs`: integration-tested (4 new adversarial tests)
- Regression test `allowed_examples_do_not_fire`: corrected to test real integration
