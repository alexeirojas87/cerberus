# Evidence Pack — Phase 2 / feedback-hook
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors | ✅ |
| `cargo test -p cerberus-engine` | `cargo test -p cerberus-engine` | 180 passed; 0 failed | ✅ |
| `cargo clippy --all-targets -- -D warnings` | `cargo clippy --all-targets -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| No findings: total=0, no intervention | `test::feedback_no_findings` | Pass | ✅ |
| Count per flag correct | `test::feedback_counts_by_flag` | Pass | ✅ |
| Count per action correct | `test::feedback_counts_by_action` | Pass | ✅ |
| Max severity detected | `test::feedback_max_severity` | Pass | ✅ |
| Block message generated | `test::feedback_block_message` | Pass | ✅ |
| Redact message generated | `test::feedback_redact_message` | Pass | ✅ |
| Warn message generated | `test::feedback_warn_message` | Pass | ✅ |
| Allow generates no message | `test::feedback_allow_no_message` | Pass | ✅ |
| Summary line without findings | `test::feedback_summary_line_clean` | Pass | ✅ |
| Summary line with findings | `test::feedback_summary_line_with_findings` | Pass | ✅ |
| Count per category | `test::feedback_by_category` | Pass | ✅ |
| FeedbackOptions default | `test::feedback_default_options` | Pass | ✅ |

## Adversarial cases tested
- Findings of different flags → correct count per flag
- Findings of different actions → count per action
- Findings of different categories → count per category
- Mixed severity → max_severity is the highest
- No findings → summary_line reports "no sensitive data"
- With block+redact findings → summary_line includes both counts
- FeedbackOptions disableable

## Applicable NFRs
- N/A (no latency/security applies to this unit)

## Files
- `crates/cerberus-engine/src/feedback.rs` (new)
- `crates/cerberus-engine/src/lib.rs` (modified: +pub mod feedback)

## SHAs
```
TODO: sha256sum of new files
```

## Deviations from plan
None. It implements feedback-hook: a structured signal with by_flag, by_action, by_category, max_severity, total, and human-readable messages.
