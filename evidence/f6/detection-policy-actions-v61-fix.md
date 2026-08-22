# Evidence Pack — F6 DetectionPolicy action semantics v6.1 FIX

**Fecha:** 2026-08-21  
**Checkout base:** `09612f2` + cambios locales preexistentes  
**Unidad:** F6 `config-api` / `pantallas-config` — semántica de acciones efectivas  
**Veredicto:** **PASS**

## Defecto reproducido

`DetectionPolicy::seeded()` persistía `secrets: redact` y `pii: warn` como si
fueran decisiones explícitas del operador. `effective_rules()` aplicaba esas
categorías sobre todas las reglas base, por lo que
`secret.openai_api_key: block` quedaba rebajada a `redact`; el simulador
observaba **25 PASS / 4 FAIL** (block, flag, allowlist previa y auditoría shadow).

## Corrección estructural

- `crates/cerberus-proxy/src/detection_policy.rs:129`: la política seeded queda
  sin overrides; las acciones declaradas por cada regla son el default efectivo.
- `crates/cerberus-proxy/src/detection_policy.rs:235`: se conserva la precedencia
  explícita `rules[flag] > categories[category] > rule.action`.
- Backward compatibility: un YAML v6.1 que ya contiene `policy.categories`
  sigue deserializando esas entradas como overrides explícitos; un YAML legado
  sin `policy` hereda las acciones de las reglas.
- F6 CRUD mantiene `null = borrar override` y clave ausente = preservar.
- Dashboard: las tres categorías válidas siguen visibles; una categoría no
  configurada aparece como `inherit` / “acción declarada por la regla”, y al
  fijarla o quitarla usa el mismo `PUT /api/policy` existente.

## Tests añadidos/actualizados

- `default_openai_rule_keeps_its_declared_block_action`: OpenAI conserva
  `Action::Block` con la política default.
- `explicit_category_override_replaces_the_declared_rule_action`: un operador
  que fija `secrets: redact` sí reemplaza el `block` declarado.
- YAML: ausencia de policy = herencia; YAML v6.1 con categorías = override
  explícito y estable tras deserializar.
- HTTP F6: categorías inicialmente vacías, patch parcial, borrado con `null` y
  rollback de patch inválido.

## Gauntlet v6.1

| Comando | Evidencia | Resultado |
|---|---|---|
| `cargo fmt --all -- --check` | sin diff | **PASS** |
| `cargo build --workspace --all-targets` | dev, 3 crates compilados | **PASS** |
| `cargo build --release --workspace --all-targets` | release, 3 crates compilados | **PASS** |
| `cargo clippy --workspace --all-targets -- -D warnings` | `No issues found` | **PASS** |
| 4 tests focalizados de default/override/YAML/patch | `1 passed` cada uno | **PASS** |
| `cargo test -p cerberus-proxy --all-targets` | **155 passed / 0 failed**, 2 suites | **PASS** |
| `git diff --check` | sin errores | **PASS** |
| `python3 tools/simulate.py` tras rebuild release | **29 PASS / 0 FAIL** | **PASS** |

Transcript E2E PASS:
`evidence/sim/sim-run-20260821-194614.log`.

El primer intento del simulador, antes de reconstruir `target/release`, repitió
el baseline **25 PASS / 4 FAIL** porque el harness ejecuta el binario release
preexistente. Se reconstruyó release y se repitió el mismo gate hasta obtener
29/29; la corrida fallida queda en
`evidence/sim/sim-run-20260821-194538.log` como evidencia del loop.

## Riesgos residuales / migración

- Configuraciones ya persistidas con `categories.secrets: redact` mantienen esa
  conducta por compatibilidad: ahora se consideran, correctamente, una
  configuración explícita. Para volver a la acción de cada regla, el operador
  debe borrar la entrada (UI “Quitar” o `null` en la Config API).
- No se cambió el wire de F6 (`categories`, `rules`, `custom_rules`,
  `allowlist`) ni se añadieron campos de migración; clientes y YAML v6.1 siguen
  siendo legibles.
- No se hizo commit.
