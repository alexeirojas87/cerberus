# Evidence Pack — REVISOR 2 (performance/correctness): multiline-blocks

**Revisor:** REVISOR 2
**Fase:** F1 — Review multiline-blocks
**Worktree:** `cerberus-wt-f1-review-multiline`
**Fecha:** 2026-08-17

---

## 1. Baseline

| Check | Result |
|-------|--------|
| `cargo build` | ✅ 125 crates, 0 errors |
| `cargo clippy --all-targets` | ✅ 0 issues |
| `cargo fmt --check` | ✅ (2 issues fixed — see §6) |
| `cargo test` | ✅ 166 passed (15 suites, 30s) |

---

## 2. Code Review — `crates/cerberus-engine/src/multiline.rs`

### Structure
- **`is_multiline_pattern()`** — heuristics: `-----BEGIN`, `\n`, `\n\n` in the pattern string. Correct: PEM patterns contain `-----BEGIN`, .env patterns contain `\n`.
- **`detect_multiline()`** — compiles patterns with `(?m)` flag, runs `regex::Regex::find()`, returns `Option<Finding>` with `start`/`end` byte offsets covering the full match.
- **Hash** — uses `sha256:` prefix before SHA-256 hex digest (same scheme as engine).

### Detection correctness
| Pattern | Detectable? | Mechanism |
|---------|------------|-----------|
| `-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----` | ✅ `(?m)` + `(?:.*\n)*?` captures body lines |
| `-----BEGIN EC PRIVATE KEY-----` | ✅ Same pattern structure |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | ✅ Same pattern structure |
| `-----BEGIN DSA PRIVATE KEY-----` | ✅ Same pattern structure |
| `.env` (`DB_PASSWORD=...\nDB_HOST=...`) | ✅ `(?:^|\n)(?:DB_PASSWORD\|...)=.*\n?` with `(?m)` |
| Single-line patterns (e.g. `sk-...`) | ✅ Filtered out by `is_multiline_pattern()` |

### Edge case: `.env at start of string`
The pattern `(?:^|\n)(?:DB_PASSWORD|...)=.*\n?` with `(?m)` correctly matches `^` at the absolute start of text. Verified working in adversarial testing.

### Issues found
1. ✅ **Minor**: `is_multiline_pattern` also checks `\\n\\n` — this is redundant but harmless. No real patterns trigger it.
2. ✅ **Finding span**: `pem_block_captures_full_range` test verifies start..end covers BEGIN→END inclusive with all body lines.

---

## 3. Adversarial Tests (manual verification)

### 3.1 PEM RSA key
```
Input: "prefix\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----\nsuffix"
Result: ✅ DETECTED — captures 3-line block, start..end covers BEGIN→END
Span: correct (starts at BEGIN, ends after END)
```

### 3.2 .env file
```
Input: "DB_PASSWORD=secret123\nDB_HOST=localhost"
Result: ✅ DETECTED — captures "DB_PASSWORD=secret123\n"
Span: correct
```

### 3.3 SSH OPENSSH key
```
Input: "some text\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...\n-----END OPENSSH PRIVATE KEY-----\nmore text"
Result: ✅ DETECTED — captures full block
Span: correct (BEGIN→END inclusive)
```

### 3.4 Normal text (false positive check)
```
Input: "This is just normal text with no secrets or keys whatsoever"
Result: ✅ NO FALSE POSITIVE — correctly returns None
```

---

## 4. Finding Span Coverage

Test `pem_block_captures_full_range` verifies:
- `captured.starts_with("-----BEGIN RSA PRIVATE KEY-----")` ✅
- `captured.ends_with("-----END RSA PRIVATE KEY-----")` ✅
- `captured.contains("\nline1\n")` ✅
- `captured.contains("\nline2\n")` ✅

Test `pem_block_multi_line_body` verifies headers (Proc-Type, DEK-Info) are captured ✅

**Veredicto**: Findings cubren el bloque completo sin truncamiento.

---

## 5. Integration in `engine.rs`

Call site at `engine.rs:239-244`:
```rust
// Multiline block detection (PEM keys, .env, SSH keys)
// Runs after normal regex matching for patterns that span multiple lines.
for rule in &self.rules {
    if let Some(finding) = detect_multiline(text, rule) {
        findings.push(finding);
    }
}
```

**Correct position**: After prefixed regex (AC+regex) at lines 202-222, after unprefixed regex at lines 224-236, and **before** entropy detection at line 246. This is the correct order per the build plan §4.4.

---

## 6. Formatting Fixes Applied

Two `cargo fmt` violations were fixed:
1. `engine.rs:188` — `validators:` field had 0 indentation (needed 12 spaces to match sibling fields)
2. `engine.rs:662` — `.build()` had 0 indentation (needed 12 spaces to match method chain)

Both fixed. `cargo fmt --check` now passes cleanly.

---

## 7. Summary

| Criterio | Veredicto |
|----------|-----------|
| Build | ✅ PASS |
| Tests (multiline) | ✅ 11/11 pass |
| Tests (all) | ✅ 166/166 pass |
| Clippy | ✅ Clean |
| Format | ✅ Clean (2 fixes applied) |
| PEM key detection | ✅ Full block, correct span |
| .env detection | ✅ Correct |
| SSH key detection | ✅ Correct |
| False positives | ✅ None |
| Integration in engine.rs | ✅ After regex, before entropy |

**Veredicto final: ✅ PASS — REVISOR 2 aprueba multiline-blocks.**