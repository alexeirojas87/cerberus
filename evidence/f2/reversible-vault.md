# Evidence Pack — Phase 2 / reversible-vault
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors | ✅ |
| `cargo test -p cerberus-engine` | `cargo test -p cerberus-engine` | 180 passed; 0 failed | ✅ |
| `cargo clippy --all-targets -- -D warnings` | `cargo clippy --all-targets -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| store/resolve round-trip works | `test::store_and_resolve` | Pass | ✅ |
| resolve_str with wrapper [VAULT:...] works | `test::resolve_str_with_wrapper` | Pass | ✅ |
| resolve_str with direct id works | `test::resolve_str_direct_id` | Pass | ✅ |
| Nonexistent token returns None | `test::resolve_nonexistent_token` | Pass | ✅ |
| Empty vault at start | `test::vault_is_empty_initially` | Pass | ✅ |
| len() increments with stores | `test::vault_len_increases` | Pass | ✅ |
| clear() removes everything | `test::clear_removes_all` | Pass | ✅ |
| Monotonic tokens (v1, v2, ...) | `test::tokens_are_monotonic` | Pass | ✅ |
| ReversibleOptions default disabled | `test::reversible_options_default_disabled` | Pass | ✅ |
| ReversibleOptions.enabled() works | `test::reversible_options_enabled` | Pass | ✅ |

## Adversarial cases tested
- Token with [VAULT:...] format extracted correctly
- Token without wrapper (direct id) also works
- Nonexistent token → None (no panic)
- Thread-safe via Mutex (concurrent access)
- Monotonic counter: sequential IDs
- clear() after store → empty vault

## Applicable NFRs
- N/A (no latency/security applies to this unit)

## Files
- `crates/cerberus-engine/src/vault.rs` (new)
- `crates/cerberus-engine/src/lib.rs` (modified: +pub mod vault)

## SHAs
```
TODO: sha256sum of new files
```

## Deviations from plan
None. It implements reversible-vault: a thread-safe local vault with [VAULT:vN] tokens and a ReversibleOptions flag to enable it.
