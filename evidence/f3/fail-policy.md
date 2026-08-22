# Evidence Pack — Phase 3 / fail-policy
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| FailClosed → Reject | `test::fail_closed_rejects` | Pass | ✅ |
| FailOpen → Allow | `test::fail_open_allows` | Pass | ✅ |
| Any error in fail_closed → Reject | `test::fail_closed_rejects_any_error` | Pass | ✅ |
| Any error in fail_open → Allow | `test::fail_open_passes_any_error` | Pass | ✅ |

## Adversarial cases tested
- Arbitrary error strings → policy applied equally
- Config and deserialize via serde (YAML/JSON)

## Applicable NFRs
- N/A

## Files
- `crates/cerberus-proxy/src/policy.rs`
- `crates/cerberus-proxy/src/config.rs` (FailPolicy enum)

## Deviations from plan
None. Configurable fail-open/closed policy via config file.
