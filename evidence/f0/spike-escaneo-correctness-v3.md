# Evidence Pack — Phase 0: spike-escaneo · Correctness v3

## Context
- **Objective**: verify that the criterion that failed in attempt 2 (handling of `--engine invalid`) NOW passes, and that nothing broke.
- **Worktree**: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/cerberus-wt-f0-scan-rv3-verify`
- **Role**: quick verification reviewer.
- **Date**: 2026-08-16

## Verdict: **PASS**

The key criterion (`--engine bogus` → exit=1 + clear error on stderr) was corrected and the rest of the battery remains green. No regression detected.

## Results per command

### 1. Build workspace
`cargo build --workspace 2>&1`
```
Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.09s
```
**PASS** — compiles without errors (crates: benchkit, cerberus-core, spike-scan).

### 2. Format
`cargo fmt --check 2>&1`
```
(exit 0, no output)
```
**PASS** — no differences.

### 3. Clippy
`cargo clippy -p spike-scan --all-targets -- -D warnings 2>&1`
```
Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.74s
```
**PASS** — 0 errors / 0 warnings.

### 4. Tests
`cargo test -p spike-scan 2>&1`
```
Unittests src/lib.rs      : 7 passed; 0 failed
Unittests src/main.rs     : 11 passed; 0 failed
tests/integration.rs      : 8 passed; 0 failed
--------------------------------------------------
Total: 26 passed; 0 failed (3 suites)
```
**PASS** — 26/26 (7 lib + 11 unit + 8 integration).

### 5. Key criterion
a) Invalid engine — `cargo run --bin spike-scan -- --engine bogus --patterns 5 --payload-size 1 --iterations 1`:
- stdout (with `2>/dev/null`): empty
- stderr: `invalid engine 'bogus' (expected 'regex' or 'hybrid')`
- `exit=1`
**PASS** — clear error on stderr and exit code 1 (the attempt 2 failure).

b) `--engine regex` (with `2>/dev/null`):
```
{
  "engine": "regex",
  "iterations": 3,
  "patterns": 3,
  "payload_size_kb": 1,
  "regex": { "compile_ms": ..., "matches_found": 3, "scan_p50_ms": 0.003, "scan_p99_ms": 0.004, "throughput_mbps": ... },
  "vectorscan": null
}
```
Validated with `python3 -c 'import json,sys; json.load(sys.stdin)'` → **valid JSON**.

c) `--engine hybrid` (with `2>/dev/null`):
```
{
  "engine": "hybrid",
  "hybrid": { "compile_ms": ..., "matches_found": 3, "scan_p50_ms": 0.033, "scan_p99_ms": 0.036, "throughput_mbps": ... },
  "iterations": 3,
  "patterns": 3,
  "payload_size_kb": 1,
  "vectorscan": null
}
```
Validated with the same parser → **valid JSON**.

## Conclusion
- Trigger fix confirmed: `--engine invalid` returns `exit=1` with message `invalid engine 'bogus' (expected 'regex' or 'hybrid')` exclusively on stderr, with no leakage to stdout.
- No regression: build, fmt, clippy (-D warnings) and 26/26 tests green; correct JSON output for regex and hybrid.
- **Verdict: PASS** — correctness gate authorized.
