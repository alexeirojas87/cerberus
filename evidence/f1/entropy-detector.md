# Evidence Pack — F1/entropy-detector
- Intento: 1    Revisor: BUILDER (self-verify)    Veredicto: PASS

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| Compila | `cargo build -p cerberus-engine` | `Finished dev profile` | ✅ |
| Tests pasan | `cargo test -p cerberus-engine` | `53 passed; 11 passed; 0 failed` | ✅ |
| Clippy | `cargo clippy -p cerberus-engine --all-targets` | `Finished, no warnings` | ✅ |
| Formato | `cargo fmt -p cerberus-engine --check` | `FMT OK` | ✅ |
| Shannon entropy `("aaaa") ≈ 0.0` | `entropy::tests::entropy_repeated_char` | PASS | ✅ |
| Shannon entropy `("sk-abc...") > 4.0` | `entropy::tests::entropy_high_random_token` | PASS | ✅ |
| `password=abc123` → no detecta | `entropy::tests::detect_low_entropy_near_keyword_no_finding` | PASS | ✅ |
| `password=J8sK2m9x...` → detecta | `entropy::tests::detect_high_entropy_near_keyword` | PASS | ✅ |
| Sin keywords → no detecta | `entropy::tests::detect_no_keywords_no_findings` | PASS | ✅ |
| Integración engine: findings se añaden | `engine::tests::scan_detects_secret` (2 findings: regex + entropy) | PASS | ✅ |
| Valor corto (< 8 chars) no detecta | `entropy::tests::detect_short_value_no_finding` | PASS | ✅ |
| Case-insensitive keywords | `entropy::tests::detect_case_insensitive_keyword` | PASS | ✅ |
| JSON-style `{"password": "..."}` | `entropy::tests::detect_json_style` | PASS | ✅ |
| Hash ≠ raw value | `entropy::tests::detect_hashed_value_not_raw` | PASS | ✅ |
| Múltiples keywords, solo alta entropía | `entropy::tests::detect_within_window_multiple_keywords` | PASS | ✅ |

## Casos adversariales probados

- **String vacío**: `shannon_entropy("")` = 0.0 ✅
- **Repetitivo**: `shannon_entropy("aaaa")` ≈ 0.0 ✅
- **Baja entropía**: `shannon_entropy("abc123")` < 3.0 ✅
- **Alta entropía**: `shannon_entropy("J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE")` > 4.0 ✅
- **Secret con hash**: Finding.hashed_value nunca contiene el raw value ✅
- **Texto sin keywords**: 0 findings ✅
- **Keyword con valor corto**: no detecta (min 8 chars) ✅
- **Integración con engine existente**: findings de entropía se agregan a los del scan regex ✅
- **Operación normal inalterada**: tests preexistentes siguen pasando (scan_no_secrets, action_per_rule_honoured, etc.) ✅

## NFR aplicables
- Sin dependencias nuevas (solo `regex` ya existente + math de std)
- Sin fuga de secretos: los findings usan `hash_value` (SHA-256) nunca el raw value
- Latencia: O(n) en bytes para entropía, O(k * w) para detección (k = keywords, w = ventana 200 chars)

## Archivos modificados

| Archivo | SHA-256 | Cambio |
|---------|---------|--------|
| `crates/cerberus-engine/src/entropy.rs` | `f839b0bdbbd29cc909602633126d750f1df62507ecbbbefea01ba004de9c9be5` | Nuevo: Shannon entropy + detector genérico |
| `crates/cerberus-engine/src/engine.rs` | `1d31a3d3cf899e47f0da2d3570d89af5efd15d615ea95f9037231a6c4f1b069c` | Modificado: integración entropy en scan + builder |
| `crates/cerberus-engine/src/lib.rs` | `6ba810ba3ce30359d56b52d1127f39ff05464911986c2213768c0f9ec1fa8fba` | Modificado: `pub mod entropy;` |

## Desviaciones
- Ninguna. Implementación sigue el spec del build plan §4.3 y §8 F1.
- Threshold default 4.0 configurable vía `EngineBuilder::with_entropy_threshold()`.
- Flag: `entropy.high_entropy_secret`, category: `Secrets`, severity: `Medium`, action: `Warn`.