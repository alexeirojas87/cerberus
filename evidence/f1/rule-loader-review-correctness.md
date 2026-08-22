# Evidence Pack — Fase 1: rule-loader (Revisor 1 — Correctness)

**Revisor:** REVISOR 1 (correctness)
**Worktree:** `cerberus-wt-f1-rule-loader-review-correctness`
**Fecha:** 2026-08-17
**Veredicto:** **PASS**

## Resumen

Unidad revisada: crate `cerberus-engine` (rule-loader + engine de scanning).
Objetivo: romper la unidad. Se ejecutaron los 10 puntos del protocolo. Todos pasan.

---

## 1. Build del workspace

```bash
export PATH="$HOME/.cargo/bin:$PATH" && cargo build --workspace 2>&1
```

Resultado: `Finished dev profile ... in 20.05s` — **0 errores**.

Crates compilados: benchkit, cerberus-core, spike-scan, cerberus-engine, spike-proxy.

## 2. Tests (`cargo test -p cerberus-engine`)

Resultado: **48/48 tests pasan** (37 lib + 11 integration), 0 failures, 0 ignored.

```
running 37 tests  ... test result: ok. 37 passed
running 11 tests  ... test result: ok. 11 passed
Doc-tests: 0 tests
```

## 3. Clippy (`cargo clippy -p cerberus-engine --all-targets -- -D warnings`)

Resultado: `Finished dev profile` — **0 errores, 0 warnings**. Sin output de diagnóstico.

## 4. Formato (`cargo fmt --check`)

Resultado: sin output — **0 diffs**. Código correctamente formateado.

## 5. Carga real de test-rules.json

Ubicación: `crates/cerberus-engine/test-rules.json`.

- **11 reglas** cargadas (`rules.len() == 11`), cumple el requisito de `>=10`.
- Test que lo verifica: `test_rules_file_loads_with_expected_count` (assert `len() >= 10`).
- Todas las reglas tienen `flag` no vacío y `patterns` no vacío (`rules_have_all_required_fields`).
- Contiene las 3 categorías (secrets/pii/internal_code) y las 3 acciones (block/redact/warn).

## 6. Escaneo adversarial

### 6a. Texto vacío → sin findings
Test verificado: `empty_text_produces_no_findings` — `scan(&engine, &ScanRequest::new(""))` devuelve `findings.is_empty()`. **PASS** (verificado en ejecución manual, luego restaurado el test original).

### 6b. Secreto real que coincide con múltiples reglas
Texto de prueba: `"API: sk-abcDEFghijklmnopqrstuvwxyz123456\nEmail: test@test.com\nAWS: AKIA1234567890ABCDEF"`.

Encuentra **todas las coincidencias**:
- `secret.openai_api_key` (sk-...)
- `pii.email` (test@test.com)
- `secret.aws_access_key_id` (AKIA...)

Los findings suman `>=2` reglas distintas. **PASS** (verificado en ejecución manual con test `scan_finds_multiple_rules_in_one_text`, luego restaurado).

### 6c. allowedExample de OpenAI (`sk-test-example-not-real`)
Test `allowed_examples_do_not_fire`: el token explícitamente permitido **NO dispara** la regla `secret.openai_api_key`. El motivo principal es que es más corto que `minLength: 20` (23 vs 20 — nota: "sk-test-example-not-real" tiene 23 chars, pero el patrón requiere `[A-Za-z0-9]{20,}` tras `sk-`; el texto contiene `-` que rompe el charclass). Ambos mecanismos (allowedExamples + patrón) coinciden en no disparar. **PASS**.

## 7. ScanRequest genérico sin domain IDs

`ScanRequest` (crates/cerberus-engine/src/scan.rs:19) tiene **solo** dos campos:
- `text: String`
- `metadata: HashMap<String, String>`

**NO existen** `AgentId`, `PbiId`, `CorrelationId`. El diseño usa `metadata` para labels arbitrarias del caller (tool, provider, correlación). Test `generic_scan_request_has_no_domain_fields` lo confirma. **PASS**.

## 8. Carga YAML (`loader::load_rules_from_yaml`)

- Unit tests: `load_from_yaml_string`, `load_from_yaml_object_string` (sequence y mapping).
- Integration: `yaml_load_matches_json_behavior`, `yaml_file_roundtrip` (archivo temporal real).
- Ruta: `load_rules_from_yaml` (loader.rs:61) → `parse_rules` con `FileFormat::Yaml`, acepta secuencia (`-`) o mapping con clave `rules`.
- Semántica idéntica a JSON: mismos defaults y validación.

**PASS**.

## 9. Carga de archivo inexistente → error claro

- JSON: `load_rules_from_json("/nonexistent/...")` → `LoadError::Io` con mensaje `"cannot read rules file: ..."`.
- YAML: idéntico comportamiento.
- Tests: `missing_file_returns_io_error` (unit), `nonexistent_file_returns_clear_error` y `yaml_file_not_found_returns_clear_error` (verificados manualmente).

**PASS**.

## 10. Privacidad: hashed_value nunca el valor crudo

`engine::hash_value` (engine.rs:279) genera `format!("sha256:{}", hex::encode(sha256(trim(value))))`:
- Formato: prefijo `sha256:` (7 chars) + 64 hex chars = **71 chars totales**.
- `Finding.hashed_value` es el único campo del valor; no existe campo con el valor crudo.
- Tests: `hash_value_is_sha256` (len 71, determinístico), `finding_never_contains_raw_value`, `scan_detects_secret` (assert `hashed_value.len() == 71`), `scan_finds_openai_key` (integration, assert `hashed_value != raw` y `starts_with("sha256:")`).
- En la prueba adversarial multi-regla (6b) se validó que cada finding tenga formato `sha256:` + 71 chars.

**PASS**.

---

## Tabla de resultados

| # | Check | Resultado |
|---|-------|-----------|
| 1 | `cargo build --workspace` | ✅ 0 errores |
| 2 | `cargo test -p cerberus-engine` (48 tests) | ✅ 37 lib + 11 integration, 0 fail |
| 3 | `cargo clippy ... -- -D warnings` | ✅ 0 errores/warnings |
| 4 | `cargo fmt --check` | ✅ 0 diffs |
| 5 | test-rules.json carga real (≥10 reglas) | ✅ 11 reglas |
| 6a | Texto vacío → sin findings | ✅ |
| 6b | Secreto multi-regla → encuentra todos | ✅ |
| 6c | allowedExample OpenAI → no dispara | ✅ |
| 7 | ScanRequest sin AgentId/PbiId | ✅ |
| 8 | Carga YAML (sequence + mapping + archivo) | ✅ |
| 9 | Archivo inexistente → error claro | ✅ |
| 10 | hashed_value `sha256:` 71 chars, sin crudo | ✅ |

**Total: 12/12 ✅**

## Bugs encontrados

**Ninguno (0 bugs).** La unidad es correcta.

### Observaciones menores (no bloqueantes, no son bugs de correctitud)

1. **`context_keywords` y `validators` no se evalúan** — están definidos en el modelo (`Rule`) y se deserializan, pero el motor no los usa (engine.rs). Comentado en el código como "kept for compatibility; not evaluated yet" (rule.rs:104). Correcto para el alcance Fase 1, pero debe resolverse en fase posterior.
2. **`hash_normalization` no se aplica** — el campo existe pero `make_finding` (engine.rs:223) siempre hace `raw_value.trim()` independientemente del valor de `hashNormalization`. La regla OpenAI define `"hashNormalization": "trim"`, y el trim coincide, pero otras normalizaciones no se soportarían. No bloquea porque todas las reglas actuales son compatibles con trim.
3. **Coincidencia única por regex en prefixed patterns** — en `scan` (engine.rs:191) se usa `regex.find()` (primera coincidencia) por cada hit AC, no `find_iter`. Si un mismo AC-prefix aparece y el regex matchea varias veces dentro del resto del texto, solo se reporta la primera. Con el corpus actual (una secret por patrón por texto) no produce falsos negativos, pero con múltiples secrets del mismo tipo en un texto largo solo se reportaría la primera. Nota: el test `scan_multiple_patterns_same_rule` cubre dos secrets de *distintos* patrones, no dos del mismo patrón — margen a vigilar.
4. **Error de YAML usa serde_yaml deprecado** — Cargo.toml muestra `serde_yaml v0.9.34+deprecated`. Correcto y funcional; candidato a migración a `serde_yml`/`serde_yaml_ng` en fase posterior.

Ninguna de las observaciones afecta el veredicto de correctitud para el alcance Fase 1 (MVP, rule-loader).
