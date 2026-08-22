# Evidence Pack: REVIEWER 3 (Security) — entropy-detector

**Phase:** 1 | **Unit:** entropy-detector | **Reviewer:** Security  
**Date:** 2026-08-17 | **Worktree:** `cerberus-wt-f1-review-entropy`

---

## 1. Build & Baseline

| Tool | Result | Evidence |
|---|---|---|
| `cargo build` | ✅ PASS — 0 errors | 14.48s, no warnings |
| `cargo test` | ✅ PASS — 166 tests | 6+1+115+11+3+0+4+7+11+8 = 166 passed |
| `cargo clippy --all-targets` | ✅ PASS — 0 warnings | No lint errors |
| `cargo fmt --check --all` | ✅ PASS — 0 diff | Consistent formatting after initial fix |

## 2. Code Review — `entropy.rs`

### `shannon_entropy(text: &str) -> f64`

**Formula:** `H = -Σ p(x)·log₂(p(x))` — ✅ mathematically correct.

- Operates at the **byte** level (`text.as_bytes()`, `counts[256]`)
- Edge cases: empty → 0.0, single char → ~0.0, all-256 → ~8.0
- Uses `mul_add` for precision — ✅
- Uses `wrapping_add` for counts (overflow control) — ✅

### `detect_near_keywords(text, threshold) -> Vec<Finding>`

- Compiles regex `(?i)\b(keyword1|keyword2|…)\b` — ✅ case-insensitive
- Window `NEAR_KEYWORD_WINDOW = 200` bytes post-keyword — ✅
- `extract_value()` filters separators (`=`, `:`, `"`, `'`, `,`, `;`, `}`, whitespace) — ✅
- Omits values < `MIN_VALUE_LENGTH = 8` — ✅
- Generates `Finding` with flag `entropy.high_entropy_secret`, severity `Medium`, action `Warn`
- Hashing with `hash_value()` — ✅ does not expose raw value

## 3. Adversarial Tests

| Input | Expected | Actual | Result |
|---|---|---|---|
| `"aaaa"` | H ≈ 0.0 | 0.0 | ✅ PASS |
| `"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"` (40-char) | H > 4.0 | 4.8219 | ✅ PASS |
| `"password=abc123"` | Not detected | 0 findings | ✅ PASS |
| `"password=J8sK2m9x…"` (30-char) | Detected | 1 finding | ✅ PASS |
| Short value `"key=abc"` (< 8) | Not detected | 0 findings | ✅ PASS |
| All 256 bytes | H ≈ 8.0 | 8.0 | ✅ PASS |
| 100k repetitions of `'a'` | H ≈ 0.0 | 0.0 | ✅ PASS |

## 4. Scan Integration

- `engine.rs:246`: `crate::entropy::detect_near_keywords(text, self.entropy_threshold)` is ALWAYS invoked as a virtual rule — it does not depend on rule listings.
- Findings are merged with regex findings.
- `action_overall` is computed as the maximum of all actions — ✅ correct.

## 5. SECURITY FINDINGS

### 🔴 CRITICAL: Duplication of `shannon_entropy` byte-level vs char-level

- `entropy.rs:47`: uses **bytes** (`text.as_bytes()`) → fixed array `[u64; 256]`
- `validator.rs:185`: uses **chars** (`s.chars()`) → `HashMap<char, usize>`
- **Problem:** for multi-byte text (UTF-8), both give DIFFERENT results:
  - A repeated emoji 4× → byte-level: H=2.0, char-level: H=0.0
  - This can cause **false positives** or inconsistent results between the internal detector and the validation system.
  - **Risk:** an attacker could inject multi-byte text to evade detection or, worse, generate false positives to hide a real secret among alarms.

### 🟡 MEDIUM: No Unicode normalization

- The detector operates at the byte level, not the character level. An attacker can use:
  - Unicode homoglyphs (e.g. `pαssword` with alpha instead of 'a')
  - Different NFC/NFD normalization
  - UTF-8 escape sequences
- **Impact:** a secret with Unicode characters may have artificially inflated entropy (false positive) or not be detected if the keyword uses Unicode variants.

### 🟡 MEDIUM: Fixed post-keyword window (200 bytes)

- A valid secret > 200 bytes after the keyword is not detected.
- **Low risk** in practice (typical secrets are < 200 chars), but an attacker could place the secret beyond the window.
- **Recommendation:** consider a configurable window or multi-line scanning.

### 🟢 LOW: No non-standard separators in `extract_value`

- `SKIP_CHARS` does not include `|`, `\`, `@`, `#`, `` ` ``, `~`
- If a secret uses exotic separators, `extract_value` may not parse correctly.
- **Risk:** very low in standard environments (JSON, YAML, env, config).

### 🟢 LOW: `wrapping_add` on byte offsets

- `kw_end.wrapping_add(NEAR_KEYWORD_WINDOW)` and `kw_end.wrapping_add(value_offset)` can wrap on extremely long texts (>2GB).
- **Risk:** purely theoretical at this phase.

---

## Verdict

```
╔════════════════════════════════════════╗
║            VERDICT: FAIL               ║
║                                        ║
║   ❌ 1 CRITICAL (shannon duplication)   ║
║   ⚠️  2 MEDIUM  (Unicode, fixed window)║
║   ℹ️  2 LOW    (separators, wrapping)  ║
╚════════════════════════════════════════╝
```

**Blocking finding:** The duplication of `shannon_entropy` with byte-level vs char-level implementations (DRY and functional divergence) must be resolved before advancing to Phase 2.

**Recommendations:**
1. Unify both implementations into a single function in `entropy.rs` and re-export it from `validator.rs` or vice versa.
2. Choose byte-level (consistent with hashing, raw content analysis) or char-level (semantically correct for humans) — document the decision.
3. Add NFC normalization for Unicode inputs.
4. Add an adversarial test with mixed emoji/Unicode.
5. Make `NEAR_KEYWORD_WINDOW` configurable.
