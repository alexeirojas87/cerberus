# Evidence Pack: spike-escaneo correctness v2

**Reviewer:** REVIEWER 1 (correctness)
**Attempt:** 2 (post-fixer)
**Worktree:** cerberus-wt-f0-scan-rv2-correctness
**Date:** 2026-08-16

---

## Verdict: FAIL

## Criteria

### 1. `cargo build --workspace` → 0 errors
✅ **PASS** — Compiles without errors or warnings in 4.88s (dev profile).

### 2. `cargo test -p spike-scan` → all pass
✅ **PASS** — 26 tests pass:
- 7 lib unit tests (patterns, payload)
- 11 main unit tests (engine_hybrid)
- 8 integration tests (binary, schemas, edge cases)

### 3. `cargo clippy -p spike-scan --all-targets -- -D warnings` → 0 errors
✅ **PASS** — Clippy 0 errors, 0 warnings.

### 4. `cargo fmt --check` → no differences
✅ **PASS** — No differences.

### 5. Quick bench: valid JSON with required fields
✅ **PASS** — `--patterns 50 --payload-size 10 --iterations 50` produces valid JSON with default engine (hybrid) and fields `compile_ms, scan_p50_ms, scan_p99_ms, throughput_mbps, matches_found`.

### 6. Hybrid engine produces correct JSON
✅ **PASS** — `--engine hybrid --patterns 300 --payload-size 100 --iterations 100` produces JSON with `engine: "hybrid"` and sub-object `hybrid` with fields: `compile_ms, matches_found, scan_p50_ms, scan_p99_ms, throughput_mbps`.

### 7. Adversarial tests: --patterns 0, --payload-size 0, --engine invalid
❌ **FAIL** — `--engine invalid` does not produce an error. Silently runs with default engine (hybrid). Bug in `crates/spike-scan/src/main.rs:80-83`:

```rust
"--engine" => {
    i += 1;
    args.engine = match raw[i].as_str() {
        "regex" => EngineKind::Regex,
        _ => EngineKind::Hybrid,  // BUG: catch-all silences errors
    };
}
```

`--patterns 0` and `--payload-size 0` pass without error ✅ (valid edge cases that produce coherent JSON). `--engine invalid` must fail with a decent error, not run with default.

### 8. Review of `engine_hybrid.rs`
✅ **PASS** — Code analysis:

| Aspect | Status | Detail |
|---------|--------|---------|
| `extract_prefix` handles escapes | ✅ | `\b`, `\B` zero-width → skip; `\d`, `\w`, `\p`, etc. → break |
| `extract_prefix` handles regex meta | ✅ | `(`, `)`, `[`, `]`, `.`, `?`, `*`, `+`, `|`, `^`, `$`, `{`, `}` → break |
| `extract_prefix` returns `None` without literal prefix | ✅ | `MIN_PREFIX_LEN = 2` → `\d{5}` → `None`, `[a-f]{32}` → `None` |
| `extract_prefix` captures `\bkey\b` → `"key"` | ✅ | Test verifies it |
| Aho-Corasick prefilter correct window | ✅ | `shortest_match(&payload[m.start()..])` verifies regex from prefix position |
| Patterns without prefix → RegexSet fallback | ✅ | `unprefixed_set` + `unprefixed_indices` handle correctly |
| Empty patterns → 0 matches | ✅ | Test verifies it |
| Empty payload → 0 matches | ✅ | Test verifies it |
| No false positives | ✅ | Test verifies it |

## Bug found

**`main.rs:80-83`** — `--engine invalid` is silently accepted as `EngineKind::Hybrid`. It should print an error and exit with code != 0, or parse only "regex"/"hybrid" and reject other values.

## Conclusion

It does not pass the **§8B Gauntlet**: criterion 7 fails. The fixer must correct the `--engine` validation in `parse_args()` before this unit is considered complete.
