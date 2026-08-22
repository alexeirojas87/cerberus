# Evidence Pack — Phase 3 / integration-gate
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Integration verification: all F3 units

| Unit | Status |
|--------|--------|
| reverse-proxy-core | ✅ PASS |
| agnostic-decoder | ✅ PASS |
| schema-adapters | ✅ PASS |
| shadow-enforce | ✅ PASS |
| fail-policy | ✅ PASS |
| healthcheck-logs | ✅ PASS |

## Full suite
| Command | Output | Result |
|---------|--------|-----------|
| `cargo build --workspace` | 0 errors (4 crates) | ✅ |
| `cargo test --workspace` | 266 passed; 0 failed (18 suites) | ✅ |
| `cargo clippy --all-targets --workspace -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | No diffs | ✅ |

## Summary
Phase 3 complete with 6 PASS units. New crate `cerberus-proxy` with integration to the
`cerberus-engine` engine. Provider-agnostic proxy with decode, scan, redact, shadow/enforce,
fail-policy, healthcheck, and logging without secrets.

## Pending for Phase 4
- Proxy main binary (CLI): currently only a lib, missing a binary with CLI args
- E2E tests with a real upstream
- Latency benchmarks
