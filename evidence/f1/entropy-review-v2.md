# Evidence Pack — Phase 1 · Unit entropy-detector (v2)

**Date**: 2026-08-17  
**Worktree**: `cerberus-wt-f1-review-entropy-v2`  
**Reviewer**: REVIEWER (v2)

---

## Verdict: PASS ✅

---

## Criteria

| # | Criterion | Status | Evidence |
|---|----------|--------|-----------|
| 1 | `cargo build --workspace` without errors | ✅ | `Finished dev profile` (0 errors, 0 warnings) |
| 2 | `cargo test -p cerberus-engine` — 126 tests | ✅ | 115 unit + 11 integration + 0 doc-tests = **126 total** — 0 failed |
| 3 | `cargo clippy -p cerberus-engine --all-targets -- -D warnings` | ✅ | 0 warnings, 0 errors |
| 4 | `cargo fmt --check` | ✅ | No differences |
| 5a | `validator.rs` uses `pub use crate::entropy::shannon_entropy;` | ✅ | Line 185: re-export, no duplicated implementation |
| 5b | `entropy.rs` has char-level implementation with HashMap | ✅ | `entropy.rs:47-64` — iteration over `text.chars()`, `HashMap<char, usize>`, `mul_add` |
| 6 | Consistency: `entropy::shannon_entropy` == `validator::shannon_entropy` | ✅ | Test `entropy_consistent` passes: diff < 1e-12 for all cases. **Identical function pointer**: both routes point to the same address |
| 7 | UTF-8 multi-byte: "🔥🔥🔥🔥" → H ≈ 0.0 | ✅ | Entropy = 0.000000 (all chars equal). "🔥🌟⭐✨" → 2.0 (4 distinct chars) |
| 8 | `detect_near_keywords` calls the unified function | ✅ | `entropy.rs:88` — `let ent = shannon_entropy(value);` |

---

## Confirmation of the duplication bug fix

**Yes, the bug is completely fixed.**

- Before: there were two separate implementations of `shannon_entropy` — one in `entropy.rs` and another in `validator.rs` (duplication, divergence risk).
- Now: `validator.rs:185` does `pub use crate::entropy::shannon_entropy;`. The function lives exclusively in `entropy.rs` as a char-level implementation with `HashMap<char, usize>`.
- The consistency test confirms that both routes (`entropy::shannon_entropy` and `validator::shannon_entropy`) resolve to the same function pointer and produce identical results.
- The char-level implementation correctly handles multi-byte UTF-8 characters (emoji, Unicode), unlike a byte-level implementation that would fragment them.

---

## Technical summary

- **Single source file**: `entropy.rs` contains `shannon_entropy`, `detect_near_keywords`, and `extract_value`.
- **Re-export**: `validator.rs` re-exports `shannon_entropy` without duplicating logic.
- **Tests**: 17 internal tests in entropy.rs + 126 global crate tests pass without failures.
- **UTF-8**: The implementation iterates over `char` (not `u8`), guaranteeing correct entropy for Unicode text.
