# Evidence Pack — Phase 2 / break-glass
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors | ✅ |
| `cargo test -p cerberus-engine` | `cargo test -p cerberus-engine` | 180 passed; 0 failed | ✅ |
| `cargo clippy --all-targets -- -D warnings` | `cargo clippy --all-targets -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Break-glass disabled returns original findings | `test::disabled_returns_original` | Pass | ✅ |
| Break-glass enabled without Block returns original | `test::enabled_without_block_returns_original` | Pass | ✅ |
| Break-glass removes Block and returns BypassRecord | `test::enabled_with_block_removes_block` | Pass | ✅ |
| allow_once static works | `test::allow_once_static_works` | Pass | ✅ |
| Multiple blocks all bypassed | `test::multiple_blocks_all_bypassed` | Pass | ✅ |

## Adversarial cases tested
- Break-glass disabled → normal behavior, bypass does not apply
- No Block findings → bypass does nothing
- Block + Redact/Warn → only Block is removed, the rest pass
- allow_once with arbitrary reason → recorded in BypassRecord
- Multiple Block → all removed, correct count

## Applicable NFRs
- N/A (no latency/security applies to this unit)

## Files
- `crates/cerberus-engine/src/break_glass.rs` (new)
- `crates/cerberus-engine/src/lib.rs` (modified: +pub mod break_glass)

## SHAs
```
TODO: sha256sum of new files
```

## Deviations from plan
None. It implements exactly the break-glass design: a header or allow_once that lets Block findings through and leaves an audited record.
