# Evidence Pack — Phase 2 / action-precedence
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors | ✅ |
| `cargo test -p cerberus-engine` | `cargo test -p cerberus-engine` | 180 passed; 0 failed | ✅ |
| `cargo clippy --all-targets -- -D warnings` | `cargo clippy --all-targets -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Block > Redact > Warn > Allow on overlapping spans | `test::full_precedence_chain_block_over_redact_over_warn_over_allow` | Pass | ✅ |
| Redact wins over Warn+Allow on overlap | `test::redact_wins_over_warn_and_allow_span_overlap` | Pass | ✅ |
| resolve_spans sorts by precedence | `test::resolve_spans_ordered_by_precedence` | Pass | ✅ |
| Non-overlapping spans all kept | `test::resolve_non_overlapping_spans_all_kept` | Pass | ✅ |
| resolve_spans is public and documented | `pub fn resolve_spans` with `#[must_use]` | Pass | ✅ |

## Adversarial cases tested
- 4 overlapping actions (Block > Redact > Warn > Allow) → Block wins
- Redact + Warn + Allow overlapping → Redact wins (most severe without Block)
- Two overlapping Allow → first is kept (same action)
- Disjoint spans → both kept
- Global Block always applied before resolving spans (apply_redaction check)

## Applicable NFRs
- N/A (no latency/security applies to this unit)

## Modified files
- `crates/cerberus-engine/src/redact.rs` (resolve_spans/y action_severity public + tests)
- No new dependencies added

## SHAs
```
TODO: sha256sum of modified files
```

## Deviations from plan
None. The precedence follows the design exactly: Block > Redact > Warn > Allow, with resolve_spans as the public API for other modules to use.
