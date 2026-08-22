# Evidence Pack — Fase 1 · Unidad entropy-detector (v2)

**Fecha**: 2026-08-17  
**Worktree**: `cerberus-wt-f1-review-entropy-v2`  
**Revisor**: REVISOR (v2)

---

## Veredicto: PASS ✅

---

## Criterios

| # | Criterio | Estado | Evidencia |
|---|----------|--------|-----------|
| 1 | `cargo build --workspace` sin errores | ✅ | `Finished dev profile` (0 errores, 0 warnings) |
| 2 | `cargo test -p cerberus-engine` — 126 tests | ✅ | 115 unit + 11 integración + 0 doc-tests = **126 total** — 0 failed |
| 3 | `cargo clippy -p cerberus-engine --all-targets -- -D warnings` | ✅ | 0 warnings, 0 errores |
| 4 | `cargo fmt --check` | ✅ | Sin diferencias |
| 5a | `validator.rs` usa `pub use crate::entropy::shannon_entropy;` | ✅ | Línea 185: re-export, no implementación duplicada |
| 5b | `entropy.rs` tiene implementación char-level con HashMap | ✅ | `entropy.rs:47-64` — iteración sobre `text.chars()`, `HashMap<char, usize>`, `mul_add` |
| 6 | Consistencia: `entropy::shannon_entropy` == `validator::shannon_entropy` | ✅ | Test `entropy_consistent` pasa: diff < 1e-12 para todos los casos. **Function pointer idéntico**: ambas rutas apuntan a la misma dirección |
| 7 | UTF-8 multi-byte: "🔥🔥🔥🔥" → H ≈ 0.0 | ✅ | Entropía = 0.000000 (todos chars iguales). "🔥🌟⭐✨" → 2.0 (4 chars distintos) |
| 8 | `detect_near_keywords` llama a la función unificada | ✅ | `entropy.rs:88` — `let ent = shannon_entropy(value);` |

---

## Confirmación de corrección del bug de duplicación

**Sí, el bug está completamente corregido.**

- Antes: existían dos implementaciones separadas de `shannon_entropy` — una en `entropy.rs` y otra en `validator.rs` (duplicación, riesgo de divergencia).
- Ahora: `validator.rs:185` hace `pub use crate::entropy::shannon_entropy;`. La función vive exclusivamente en `entropy.rs` como implementación char-level con `HashMap<char, usize>`.
- La prueba de consistencia confirma que ambas rutas (`entropy::shannon_entropy` y `validator::shannon_entropy`) resuelven al mismo puntero de función y producen resultados idénticos.
- La implementación char-level maneja correctamente caracteres multi-byte UTF-8 (emoji, Unicode), a diferencia de una implementación byte-level que los fragmentaría.

---

## Resumen técnico

- **Archivo fuente único**: `entropy.rs` contiene `shannon_entropy`, `detect_near_keywords`, y `extract_value`.
- **Re-export**: `validator.rs` re-exporta `shannon_entropy` sin duplicar lógica.
- **Tests**: 17 tests internos en entropy.rs + 126 tests globales del crate pasan sin fallos.
- **UTF-8**: La implementación itera sobre `char` (no `u8`), garantizando entropía correcta para texto Unicode.