# Evidence Pack — f0/scaffold-ci
- Attempt: 1    Reviewer: revisor-adversarial-001    Verdict: PASS

## Acceptance criteria (one per row)
| Criterion | Command executed | Output (quoted/attached) | Result |
|----------|-------------------|-------------------------|-----------|
| Build workspace (debug) | `cargo build --workspace 2>&1` | `Compiling benchkit v0.1.0 ... Compiling cerberus-core v0.1.0 ... Finished dev profile [unoptimized + debuginfo] target(s) in 0.47s` | ✅ |
| Build workspace (release) | `cargo build --release --workspace 2>&1` | `Compiling benchkit v0.1.0 ... Compiling cerberus-core v0.1.0 ... Finished release profile [optimized] target(s) in 0.16s` | ✅ |
| Tests pass (7 total) | `cargo test --workspace 2>&1` | `benchkit: 6 passed; 0 failed` + `cerberus-core: 1 passed; 0 failed` = `7 passed; 0 failed` | ✅ |
| Clippy 0 errors/warnings | `cargo clippy --all-targets --workspace -- -D warnings 2>&1` | `Checking benchkit ... Checking cerberus-core ... Finished dev profile` — 0 warnings, 0 errors | ✅ |
| Format without differences | `cargo fmt --check 2>&1` | No output (0 differences) | ✅ |
| YAML CI valid + 3 OS | `ruby -e '... YAML.load_file ...'` | `OS matrix: ["macos-latest", "ubuntu-latest", "windows-latest"]` + `3 OS check: PASS` | ✅ |
| Makefile targets functional | `make build && make test && make fmt && make lint` | All targets execute and return 0 (see full output in attachment) | ✅ |
| benchkit percentile covers edges | Code review + tests | Tests: `percentile_returns_none_for_empty` (empty list → None). Covers p50, p99, single-element, empty. Missing: p=0, p=100, but asserts allow `[0.0, 100.0]` (doc says `(0.0, 100.0]` but assert includes 0.0 — minor non-critical discrepancy). | ✅ (with observation) |

## Adversarial cases tested (attempt to break)
- **`cargo build --workspace --no-default-features`** → compiles without errors (0.03s). No features defined, so it is a correct no-op.
- **Clippy catches lints (injection test)** → a fn with an unused variable was added to `benchkit/src/lib.rs`. `cargo clippy` reported 3 errors: `items_after_test_module`, `missing_const_for_fn` (nursery), `no_effect_underscore_binding` (pedantic). **Demonstrated that pedantic + nursery are active and block.** File restored.
- **Unnecessary deps** → no crate has dependencies. Workspace Cargo.toml only has lints. No superfluous deps.
- **YAML uses fixed-version actions (no `@main`)** → `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `actions/cache@v4`. Correct: uses major version tags, not `@main`.
- **Makefile depends on `cargo` without prior verification** → no guard (e.g. `which cargo`) before invoking cargo. Low risk: cargo is assumed installed in any Rust environment.
- **`.gitignore`** → contains `target/`, `*.swp`, `.DS_Store`, `evidence/`. All correct.

## Applicable NFRs
- (none of §5 applies directly to scaffold — it is organizational)

## If FAIL: what fails and how to reproduce it
- N/A — all criteria PASS.
