# Evidence Pack: Redaction Review (F2 — Correctness)

## 1. Build & CI Pipeline

| Step | Result |
|------|--------|
| `cargo build --workspace` | ✅ PASS (14.24s, zero warnings) |
| `cargo test -p cerberus-engine` (146 tests) | ✅ PASS (130 unit + 11 integration + 5 precision-recall) |
| `cargo clippy -p cerberus-engine --all-targets -- -D warnings` | ✅ PASS (clean) |
| `cargo fmt --check` | ✅ PASS (no changes) |

## 2. Functional Requirements Verification

File: `crates/cerberus-engine/src/redact.rs` (343 lines)

| # | Requirement | Test / Evidence | Status |
|---|-------------|-----------------|--------|
| 1 | Redact replaces span with token | `redact_replaces_span` L176 — `"sk-abc123def456"` → `"[REDACTED:test.key]"` | ✅ |
| 2 | Block returns error | `block_returns_error` L184 — `matches!(err, RedactError::Blocked { .. })` | ✅ |
| 3 | Warn passthrough | `warn_passes_through` L192 — output == input | ✅ |
| 4 | Allow passthrough | `allow_passes_through` L200 — output == input | ✅ |
| 5 | Overlapping spans → most severe action | `overlapping_spans_most_severe_wins` L226 — Redact(10..16) > Warn(8..14) | ✅ |
| 6 | Custom token template | `custom_token_template` L240 + `custom_token_template_simple` L252 | ✅ |
| 7 | preserve_length (token < span) | `preserve_length_shorter` L264 — filler `*` appended | ✅ |
| 8 | preserve_length (token > span) | `preserve_length_longer_truncates` L277 — truncated to span length | ✅ |
| 9 | JSON valid post-redact | `json_structure_preserved` L290 — `serde_json::from_str` succeeds | ✅ |
| 10 | Block > Redact (coexistence) | `block_takes_precedence_over_redact` L303 — Block wins despite Redact present | ✅ |
| 11 | Findings out-of-order are sorted | `findings_out_of_order_sorted` L320 — correct positions after sort | ✅ |

## 3. Adversarial / Edge Cases

| # | Scenario | Test / Evidence | Status |
|---|----------|-----------------|--------|
| 1 | Empty findings | `no_findings_returns_original` L219 — returns `Ok(text)` | ✅ |
| 2 | Empty text | `empty_text_returns_empty` L314 — `apply_redaction("", &[], ...)` → `""` | ✅ |
| 3 | **end < start (inverted span)** | ❌ **NO TEST EXISTS. No guard in production code.** `f.end - f.start` on L117 underflows (panic in debug, wrap in release). `replace_range(start..end)` panics. | ❌ **BUG** |
| 4 | Block + Redact combined | `block_takes_precedence_over_redact` L303 — block wins | ✅ |

## 4. Bug Report: Inverted span (end < start) not validated

**File:** `crates/cerberus-engine/src/redact.rs:117`

**Problem:** The `apply_redaction` function does not validate that `f.end >= f.start`. If a finding has `end < start`:

1. L117: `f.end - f.start` → **usize underflow** (panic in debug, `usize::MAX` in release)
2. L118: `result.replace_range(f.start..f.end)` → **panic** due to `start > end` (even if the underflow does not crash)

**Root cause:** `Finding` (engine.rs:293-308) has `start: usize` and `end: usize` with no documented invariant or verified at construction.

**Suggested fix:** Add a guard at the start of `apply_redaction`:
```rust
for f in findings {
    if f.end < f.start {
        return Err(RedactError::Blocked {
            flag: format!("{}:invalid_span(end<start)", f.flag),
        });
    }
}
```

## 5. Summary

- **10/11 functional requirements:** ✅ PASS
- **3/4 adversarial:** ✅ PASS
- **1 critical bug:** ❌ inverted span (end < start) causes panic
- **CI pipeline:** ✅ PASS (build, 146 tests, clippy, fmt)
