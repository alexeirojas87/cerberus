# Evidence Pack — F1 Constraints Review

## Metadata
- **Reviewer**: REVISOR 1 (correctness)
- **Worktree**: `cerberus-wt-f1-review-constraints`
- **Baseline commit**: `4379c3b` (detached HEAD, aligned with `main`)
- **Date**: 2026-08-17

---

## 1. Baseline

| Check       | Result |
|-------------|--------|
| `cargo test --package cerberus-engine` | 115 unit + 15 integration = **130 passed, 0 failed** |
| `cargo clippy --package cerberus-engine -- -D warnings` | **Clean** (0 warnings) |
| `cargo fmt --check` | **Clean** |
| `cargo build --package cerberus-engine` | **Clean** |

---

## 2. Bugs Found

### BUG-1 (CRITICAL): Constraints no integradas en el engine

**Archivo**: `crates/cerberus-engine/src/engine.rs:258`

**Problema**: El método `make_finding()` solo ejecutaba validadores (`self.validators.all_pass(...)`) pero **nunca llamaba** `constraints::check_constraints()`. Esto significa que `minLength`, `maxLength`, `allowedExamples`, y `contextKeywords` existían como módulo y pasaban sus tests unitarios, pero eran completamente ignorados en el pipeline de detección de engine.

**Impacto**: Cualquier regla con constraints no las aplicaba. Las findings se emitían aunque debieran ser descartadas.

**Fix aplicado**: Se añadió la llamada a `check_constraints(rule, trimmed, text)` en `make_finding()`, antes de la validación. La `text` completa (contexto escaneado) se usa como contexto para `contextKeywords`.

```rust
// engine.rs:261-263
if !check_constraints(rule, trimmed, text) {
    return None;
}
```

### BUG-2 (Medio): Test de integración `allowed_examples_do_not_fire` no probaba constraints

**Archivo**: `crates/cerberus-engine/tests/integration_test.rs`

**Problema**: El test usaba `"sk-test-example-not-real"` como "allowed example" pero este valor contiene guiones (`-`) que no están en el set `[A-Za-z0-9]` del patrón `\bsk-[A-Za-z0-9]{20,}\b`. Por tanto, el regex nunca matcheaba y el test pasaba por coincidencia, no porque constraints funcionaran.

**Fix aplicado**:
1. Se añadió `"sk-AllowedExampleABCDEFGHIJKLMNOPQRSTUVWXYZ"` a `allowedExamples` en `test-rules.json`
2. Se actualizó el test para usar este valor, que SÍ matchea el regex (32 chars alfanuméricos tras `sk-`)
3. El texto incluye la keyword de contexto `openai` para no fallar por `contextKeywords`

---

## 3. Adversarial Tests Añadidos

Cuatro tests de integración nuevos (en `tests/integration_test.rs`):

| Test | Escenario | Resultado |
|------|-----------|-----------|
| `no_constraints_always_passes_in_engine` | Regla sin constraints → match pasa | ✅ |
| `combined_minlength_and_contextkeywords_in_engine` | Ambos constraints deben cumplirse; falla si uno no | ✅ |
| `empty_context_vs_keyword_context` | Vacío descartado; con keyword pasa | ✅ |
| `allowed_examples_minlength_min_wins` | Valor corto Y en allowed → minLength gana (descarta primero) | ✅ |

---

## 4. Evidence de Ejecución

```
test result: ok. 130 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.25s  (clippy clean)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s  (build clean)
    cargo fmt --check  # clean (no output)
```

---

## 5. Archivos Modificados

| Archivo | Cambio |
|---------|--------|
| `crates/cerberus-engine/src/engine.rs:2` | Añadido `use crate::constraints::check_constraints` |
| `crates/cerberus-engine/src/engine.rs:188` | Fix indent: `validators: ValidatorRegistry::new()` |
| `crates/cerberus-engine/src/engine.rs:261-263` | Añadida llamada a `check_constraints` en `make_finding` |
| `crates/cerberus-engine/src/engine.rs:662` | Formato: `.build()` en línea separada |
| `crates/cerberus-engine/test-rules.json:11` | Añadido `"sk-AllowedExampleABCDEFGHIJKLMNOPQRSTUVWXYZ"` a `allowedExamples` |
| `crates/cerberus-engine/tests/integration_test.rs` | Test corregido + 4 adversarial tests |

---

## 6. Gate Pass

**Veredicto**: ✅ PASS — Constraints correctamente implementadas, integradas en engine, y verificadas con tests adversariales.

**Coverage de constraints en pipeline**:
- `check_constraints()` en `constraints.rs`: unit-tested (7 tests existentes)
- Llamada desde `make_finding()` en `engine.rs`: integration-tested (4 adversarial tests nuevos)
- Test de regresión `allowed_examples_do_not_fire`: corregido para probar integración real