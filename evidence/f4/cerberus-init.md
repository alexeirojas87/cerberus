# Evidence Pack — Phase 4 / cerberus-init
- Attempt: 1    Reviewer: Builder    Verdict: PASS

## Acceptance criteria
| Criterion | Command executed | Output | Result |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 285 passed; 0 failed | ✅ |
| Detects known agents | `test::detect_agents_returns_vec` | len >= 4 | ✅ |
| scan_text without secrets → clean | `test::scan_empty_text_returns_clean` | "None detected" | ✅ |
| scan_text with API key → findings | `test::scan_with_skey_detects` | "Findings" | ✅ |
| scan_file nonexistent → error | `test::scan_nonexistent_file_returns_error` | is_err | ✅ |
| `cerberus init` creates config dir + yaml | `run_init("/tmp/cerberus-test")` | Report + files | ✅ |
| `cerberus test <text>` scans inline | `scan_text()` | Findings or clean | ✅ |
| `cerberus scan <file>` scans file | `scan_file()` | Findings or error | ✅ |

## Adversarial cases tested
- init without installed agents → reports with manual config tips
- configured agents → detects and marks as ready
- nonexistent file → clear error
- text without secrets → clean message (no findings)

## Files
- `crates/cerberus/src/init.rs` (new)

## Deviations from plan
None. Autodetection of Claude Code, Codex, opencode, pi, Continue/Cursor.
