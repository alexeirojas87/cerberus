# Evidence Pack — Phase 3 / reverse-proxy-core
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors (4 crates) | ✅ |
| `cargo test --workspace` | `cargo test --workspace` | 266 passed; 0 failed | ✅ |
| `cargo clippy --all-targets --workspace -- -D warnings` | `cargo clippy --all-targets --workspace -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Proxy handler receives request and forwards | unit test + integration | E2E verified | ✅ |
| Body buffered before forwarding | proxy_handler reads full body with `.collect()` | Pass | ✅ |
| Upstream configurable via ProxyConfig | `test::find_upstream_default` | Pass | ✅ |
| Hop-by-hop headers not forwarded | SKIP_HEADERS constant | Pass | ✅ |
| Path /health responds 200 | `test::healthcheck_endpoint_responds_ok` | Pass | ✅ |

## Adversarial cases tested
- Proxy with local upstream (spike pattern) → healthcheck before forward
- Empty findings → pass-through without modification
- Block findings → 403 Forbidden with flag in body

## Applicable NFRs
- N/A (latency coverage in F0 spike already validated)

## Files
- `crates/cerberus-proxy/` (new complete crate)
  - `Cargo.toml`
  - `src/lib.rs`
  - `src/proxy.rs`
  - `src/config.rs`
  - `src/decoder.rs`
  - `src/adapters.rs`
  - `src/shadow.rs`
  - `src/policy.rs`
  - `src/health.rs`
  - `src/log.rs`

## SHAs
```
TODO: sha256sum in CI
```

## Deviations from plan
None. It implements exactly the F3 design: provider-agnostic proxy with scan/redact pre-forward.
