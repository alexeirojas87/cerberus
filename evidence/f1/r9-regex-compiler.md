# Evidence Pack — F1.1 / R9 regex compiler

- Unit: F1.1 precompilation of multiline and entropy regexes
- Builder status: **PASS** (attempt 2; attempt 1 failed Clippy and was repaired)
- Independent review: **PASS**
- Unit final status: **PASS**
- Base HEAD: `fccd9e4823e17f3598b0aa27a7ae6bd632dfeec7`
- Builder worktree: `/private/tmp/cerberus-f1-1-builder-fccd9e4`
- Baseline worktree: `/private/tmp/cerberus-f1-1-baseline-fccd9e4`
- OS/architecture: `Darwin 25.5.0 arm64`
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, host `aarch64-apple-darwin`, LLVM `22.1.6`

This pack initially records builder evidence. F1.1 remains open until a different reviewer reproduces it and the integrator records a PASS below.

## Acceptance result

| Criterion | Builder result | Evidence |
|---|---:|---|
| Multiline regexes compile during `EngineBuilder::build()` | PASS | `CompiledEngine.multiline_entries`; focused test asserts exactly two compiled entries |
| Entropy keyword regex compiles at engine build | PASS | `CompiledEngine.entropy_detector`; focused test asserts one compiled expression |
| `scan` and `scan_with_context` contain no `Regex::new` | PASS | structural source check exits 0 |
| Repeated scans preserve findings/action/hash | PASS | 32 `scan` + 32 `scan_with_context` equality checks |
| Public entropy API preserved | PASS | existing entropy suite and unchanged public signature |
| Engine tests | PASS | 198 passed |
| Engine integration | PASS | 15 passed |
| ReDoS regression suite | PASS | 8 passed |
| JSON redaction downstream tests | PASS | 5 passed |
| Format/diff hygiene | PASS | fmt and `git diff --check` exit 0 |
| Clippy affected crate | PASS on attempt 2 | no issues with `-D warnings` |

## Implementation evidence

`CompiledEngine` owns one `(Regex, PatternEntry)` for every multiline pattern, compiled with `(?m)` during `compile`, and an `EntropyDetector` whose keyword regex is also compiled during `compile`. Neither scan method contains lazy or per-call compilation.

The compatibility function `entropy::detect_near_keywords(text, threshold, secret)` keeps its public signature. It uses a `OnceLock<EntropyDetector>` and fails visibly if its static regex ever becomes invalid, avoiding both per-call compilation and a permanently cached fail-open detector.

Structural check:

```console
rtk proxy awk '/pub fn scan_with_context/{in_scan=1} /fn make_finding/{in_scan=0} in_scan && /Regex::new/{found=1} END{if(found) exit 1; print "PASS: scan and scan_with_context contain no Regex::new"}' crates/cerberus-engine/src/engine.rs
```

```text
PASS: scan and scan_with_context contain no Regex::new
```

All remaining `Regex::new` occurrences in the changed files are construction-time: three in `CompiledEngine::compile` and one in `EntropyDetector::compile`.

## Builder verification

```console
rtk cargo test -p cerberus-engine
rtk cargo test -p cerberus-engine --test integration_test
rtk cargo test --test redos_fuzz
rtk cargo test -p cerberus-proxy json_redact
```

```text
engine: 198 passed
integration: 15 passed
ReDoS: 8 passed
JSON redaction: 5 passed, 170 filtered out
```

```console
rtk cargo clippy -p cerberus-engine --all-targets -- -D warnings
rtk cargo fmt --all -- --check
rtk git diff --check
```

```text
cargo clippy: No issues found
fmt: exit 0
git diff --check: exit 0
```

Builder attempt 1 failed `clippy::unused-self` in the test-only compiled-state accessor. The accessor was repaired to inspect the owned regex and attempt 2 passed.

Independent review then found that the initial `OnceLock<Option<EntropyDetector>>` compatibility path cached compile failure and silently returned no findings. The integrator repaired it to `OnceLock<EntropyDetector>` with an explicit invariant failure; the post-repair matrix and reviewer rerun are recorded below.

## Informational release micro-measurement

This is the existing in-process `tests/load_test.rs`, not the F3 HTTP/JSON gate. Same-host release runs before and after the change reported:

| Scenario | Before p99 | After p99 |
|---|---:|---:|
| 1 KB clean | 0.558 ms | 0.004 ms |
| 10 KB clean | 0.791 ms | 0.117 ms |
| 50 KB with secrets | 0.724 ms | 0.221 ms |
| 100 KB clean | 1.305 ms | 0.411 ms |
| decode + scan | 0.938 ms | 0.380 ms |
| scan + redact | 0.900 ms | 0.347 ms |
| empty engine average | 0.299 ms | 0.014 ms |

Both runs passed 8 tests. These samples and the stale 15 ms harness threshold do not establish the closed `<5 ms` HTTP acceptance criterion.

## Modified files and integrity

```text
d8d19bc1fb9514d4aa649fdaa4b477e9cc995c8f4a68a68acbe53d9c30d3d78c  crates/cerberus-engine/src/engine.rs
5e19e2ed2c17ee0568098e8ad29f4ef55c21d205dd69b044997c39bd1be3d5c6  crates/cerberus-engine/src/entropy.rs
```

Builder patch SHA-256 before adding evidence: `9a552b17d3f25b4e9e3f51f919185b6fddce7765563e5461bb91c3e8c54d8b94`.

## Known limits and reviewer focus

- `multiline::detect_multiline` remains a standalone compatibility API that compiles a caller-supplied pattern per direct invocation. The engine hot path no longer calls it.
- The stale load harness is outside F1.1 and remains untouched.
- Reviewer must reproduce the structural check, focused tests, full engine suite, ReDoS suite, downstream JSON redaction tests, and inspect exact finding order/action/hash equality.

## Independent review

**PASS** — fresh adversarial reviewer, post-repair state, 2026-08-26.

No critical, high, medium or low findings remain open. The reviewer independently confirmed:

- all modified `Regex::new` calls are construction-time and neither scan method compiles regex;
- multiline ordering, deduplication, action selection, finding fields and hashes are preserved;
- 32 repeated `scan` and 32 repeated `scan_with_context` calls compare the complete `ScanOutput`;
- the public entropy signature is unchanged and the extracted detection loop is semantically identical;
- engine construction propagates regex failures as `Result`, while the public compatibility helper now makes an invalid static-regex invariant visible rather than caching a fail-open state;
- the standalone `multiline::detect_multiline` compatibility API has no productive hot-path consumer.

Independent commands, all exit 0:

```console
rtk cargo fmt --all -- --check
rtk cargo clippy -p cerberus-engine --all-targets -- -D warnings
rtk cargo test -p cerberus-engine
rtk cargo test -p cerberus-engine --test integration_test
rtk cargo test --test redos_fuzz
rtk cargo test -p cerberus-proxy json_redact
rtk git diff --check
```

```text
clippy: no issues
engine: 198 passed
integration: 15 passed
ReDoS: 8 passed
JSON redaction: 5 passed, 170 filtered
focused reuse, repeated entropy and invalid-regex tests: 1 passed each
structural scan-path check: PASS
```

Frozen reviewer hashes:

```text
d8d19bc1fb9514d4aa649fdaa4b477e9cc995c8f4a68a68acbe53d9c30d3d78c  crates/cerberus-engine/src/engine.rs
5e19e2ed2c17ee0568098e8ad29f4ef55c21d205dd69b044997c39bd1be3d5c6  crates/cerberus-engine/src/entropy.rs
```

## Integrator verification

**PASS (pending independent-review result)** — 2026-08-26, primary checkout.

The engine file remains byte-identical to the isolated builder output. The entropy file carries the independent-review repair described above; these are the frozen post-repair hashes:

```text
d8d19bc1fb9514d4aa649fdaa4b477e9cc995c8f4a68a68acbe53d9c30d3d78c  crates/cerberus-engine/src/engine.rs
5e19e2ed2c17ee0568098e8ad29f4ef55c21d205dd69b044997c39bd1be3d5c6  crates/cerberus-engine/src/entropy.rs
diff builder/engine.rs vs integrated/engine.rs: exit 0, no output
entropy.rs differs only by the reviewed fail-open repair in the public compatibility helper
```

Commands:

```console
rtk cargo fmt --all -- --check
rtk cargo clippy -p cerberus-engine --all-targets -- -D warnings
rtk cargo test -p cerberus-engine
rtk cargo test -p cerberus-engine --test integration_test
rtk cargo test --test redos_fuzz
rtk cargo test -p cerberus-proxy json_redact
rtk proxy awk '/pub fn scan_with_context/{in_scan=1} /fn make_finding/{in_scan=0} in_scan && /Regex::new/{found=1} END{if(found) exit 1; print "PASS: scan and scan_with_context contain no Regex::new"}' crates/cerberus-engine/src/engine.rs
rtk git diff --check
```

Output / combined exit 0:

```text
cargo clippy: No issues found
cargo test: 198 passed (4 suites, 0.06s)
cargo test: 15 passed (1 suite, 0.01s)
cargo test: 8 passed (1 suite, 0.11s)
cargo test: 5 passed, 170 filtered out (2 suites, 0.01s)
PASS: scan and scan_with_context contain no Regex::new
fmt: exit 0
git diff --check: exit 0
```

This full matrix was rerun after the fail-open repair; combined exit 0 in 16.9 seconds.
