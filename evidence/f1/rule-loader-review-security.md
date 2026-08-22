# Evidence Pack — f1/rule-loader-security

- **Rol**: REVISOR 3 (Security)
- **Panel**: Fase 1 — rule-loader (`crates/cerberus-engine`)
- **Veredicto**: PASS
- **Fecha**: 2026-08-17

## Resumen

Verificación de seguridad del rule-loader y el motor híbrido AC+regex
(heredado de F0). Build, tests, ReDoS, `unsafe`, hashing de valores,
carga de archivos, errores y parsing YAML revisados. Todos los criterios PASS.
Se documentan 4 riesgos residuales (ninguno bloqueante para el MVP).

## Criterios de Seguridad

### 1. Build ✅

| Comando | Resultado |
|---------|-----------|
| `cargo build --release --workspace` | ✅ 0 errores, 0 warnings (`Finished release profile [optimized] in 26.14s`) |

### 2. Tests ✅

| Comando | Resultado |
|---------|-----------|
| `cargo test -p cerberus-engine` | ✅ 48/48 passed (37 unit + 11 integration) |

### 3. ReDoS — sin backtracking ✅

**Contexto**: el motor usa `regex` 1.13.1 + `regex-automata` 0.4.18 (DFA, sin
backtracking; complejidad O(n) garantizada por la crate `regex`). El prefilter
Aho-Corasick solo acota la búsqueda, no introduce backtracking.

**Verificación dinámica** (test de revisión temporal, ejecutado en el worktree):

| Patrón | Tipo de ataque | Payload | Tiempo | Resultado |
|--------|----------------|---------|--------|-----------|
| `(a\|aa\|aaa)+b` | prefijado, catastrófico clásico | 10 000 × `a` | <5 ms | ✅ sin colgarse, 0 findings |
| `((a)*)*b` | prefijado, cuantificadores anidados | 10 000 × `a` | <5 ms | ✅ sin colgarse |
| `\d+(\d+)*` | unprefixed (RegexSet), catastrófico | 10 000 dígitos | <5 ms | ✅ sin colgarse |

**Detalle de código**: `engine.rs:191` `regex.find(&text[m.start()..])` y
`engine.rs:204` `self.unprefixed_regexes[set_idx].find(text)` — ambas rutas usan
la DFA de `regex`, sin backtracking. **Conclusión: sin riesgo de ReDoS.**

### 4. `unsafe` ✅

- `grep -rn "unsafe" crates/cerberus-engine/` → **0 coincidencias** (exit 1).
- Workspace `Cargo.toml:8` → `[workspace.lints.rust] unsafe_code = "forbid"`.
- Clippy pedantic + nursery también se aplican a nivel workspace.
- **Conclusión: 0 `unsafe` en el crate; el lint lo garantiza en compilación.**

### 5. Hashed values — nunca el valor crudo ✅

**Flujo en `engine.rs:220-234`** (`make_finding`):

```rust
let raw_value = &text[start..end];
let hashed = hash_value(raw_value.trim());
Finding { ..., start, end, hashed_value: hashed }
```

- `raw_value` es un *slice local* de `text`; **solo se usa** como entrada de
  `hash_value()` (SHA-256 hex, prefijo `sha256:`, `engine.rs:279`).
- El `Finding` NO retiene `raw_value` — único campo de valor es `hashed_value`
  (`engine.rs:265`). Sin `text[start..end]` guardado en el struct.
- Tests que lo blindan: `finding_never_contains_raw_value` (unit, engine.rs:426)
  y verificación dinámica adicional: `f.hashed_value != &text[f.start..f.end]`.
- **Nota (baja):** `Finding.start`/`Finding.end` son offsets. Un caller que
  conserve el texto original puede recomputar el valor crudo a partir de los
  offsets. El Finding aislado no contiene el secreto; se documenta para
  el diseño del pipeline de salida (el reporte no debe exponer el texto + offsets
  juntos sin redacción).

### 6. Carga de archivos ✅ (riesgo documentado)

`loader.rs:48-51` `load_rules_from_json` → `fs::read_to_string(path)`:
- Lee **cualquier ruta** que reciba (path arbitrario, sin sandboxing) — la lib es
  pura y no restringe rutas por diseño.
- `/etc/passwd`: se lee y falla con `invalid rules JSON` (verificado dinámicamente;
  no expone el contenido en el error).
- `/dev/random` / FIFOs: `read_to_string` bloquea hasta EOF → **DoS potencial si
  el caller pasa un device file**. **Aceptable para MVP** (cargador de config en
  proceso, no atacable desde red), pero documentar en README/plan: el caller debe
  validar la ruta antes de llamar.

### 7. Error messages — sin fuga de rutas sensibles ✅

- `LoadError` (`loader.rs:12-30`): `Io` → `"cannot read rules file: {e}"`,
  `Json` → `"invalid rules JSON: {e}"`, `Yaml` → `"invalid rules YAML: {e}"`.
- El `io::Error` de `fs::read_to_string` no incluye el path (mensaje OS puro,
  ej. "No such file or directory"). **Verificado dinámicamente**: el error de
  `/tmp/cerberus_nonexistent_file_xyz.json` NO contiene la ruta absoluta.
- Los errores JSON/YAML de serde exponen la *línea/columna del input* (contenido
  de las rules), nunca paths del sistema.

### 8. YAML parsing ✅ (riesgo bajo documentado)

- `serde_yaml` 0.9.34 (deprecated) — **se deserializa a `Vec<Rule>` tipado, NO a
  `serde_yaml::Value`** (`loader.rs:101-108`). Los anclas/alias solo sirven como
  referencias a datos ya parseados; no hay recursión desbocada hacia estructuras
  ilimitadas.
- **Verificado dinámicamente**:
  - Anchors + alias simples (`&a` + 9 × `*a`) → carga correcta (10 rules).
  - "YAML bomb" con expansión anidada (10^5 items via alias) → falla con error de
    tipo (el target tipado no acepta la estructura) en <5 ms; **sin expansión de
    entidades ni OOM**.
- **Riesgo residual (bajo):** `serde_yaml` es un crate deprecated sin un límite de
  alias explícito. El ataque billion-laughs clásico solo es efectivo contra
  deserialización a `Value`/tipos recursivos, no contra `Vec<Rule>`. La migración
  natural es a `serde_yml`/`serde_yaml_ng` o `serde_json` (ya aceptado) cuando el
  mantenimiento lo exija. **Aceptable para MVP.**

## Hallazgos de Seguridad

| # | Severidad | Hallazgo | Estado |
|---|-----------|----------|--------|
| S-1 | Baja | `Finding.start/end` + texto original en manos del caller permiten reconstruir el valor crudo | Documentado; mitigar en el diseño del reporte de salida |
| S-2 | Baja | `load_rules_from_json` acepta rutas arbitrarias (`/etc/passwd`, `/dev/random`); devices pueden bloquear | Aceptable (lib pura); validar ruta en el caller |
| S-3 | Baja | `serde_yaml` deprecated; sin límite de alias explícito (billion-laughs solo contra `Value`) | Aceptable (target tipado); migrar cuando sea oportuno |
| S-4 | Info | `regex` crate (DFA) garantiza tiempo lineal; sin backtracking posible | Sin riesgo |

## Conclusión

- **Veredicto**: PASS
- Todos los criterios de la checklist de REVISOR 3 cumplidos con evidencia:
  build OK, tests 48/48, sin ReDoS, 0 `unsafe`, valores siempre hasheados,
  errores sin rutas, YAML con riesgo bajo documentado.
- Sin bloqueantes para el MVP.
