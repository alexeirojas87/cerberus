# Evidence Pack — f0/spike-escaneo-security-v2

- **Rol**: REVISOR 3 (Security)
- **Intento**: 2 (segunda verificación)
- **Veredicto**: PASS

## Resumen

Verificación de seguridad completa sobre el motor híbrido AC+regex y el workspace. Todos los criterios PASS.

## Criterios de Seguridad

### 1. Build ✅

| Comando | Resultado |
|---------|-----------|
| `cargo build --release --workspace` | ✅ 0 errores, 0 warnings |
| `cargo clippy --workspace --all-targets` | ✅ 0 issues |

### 2. Tests ✅

| Comando | Resultado |
|---------|-----------|
| `cargo test -p spike-scan` | ✅ 26/26 passed (7 unit lib + 11 unit main + 8 integration) |

### 3. ReDoS (tiempo lineal garantizado) ✅

**Escenario**: 3 patrones ReDoS clásicos contra payload de 100KB de `'a'` + `'b'`:

| Patrón | Categoría | Riesgo |
|--------|-----------|--------|
| `(a|aa|aaa)+b` | ReDoS clásico | Catastrophic backtracking en NFA |
| `(a|aa)*b` | ReDoS | Exponential backtracking |
| `(a+)+b` | ReDoS | Exponential backtracking |

**Resultado**: `extract_prefix()` retorna `None` para los 3 (empiezan con `(` → break). Van a `RegexSet` (unprefixed). `regex` crate de Rust usa DFA internamente → **tiempo lineal garantizado**.

Test directo con payload real de 100KB + `'b'`:
- `RegexSet::matches()` en 100KB de 'a's completó en **188µs** — sin hang
- Binary con `--patterns-file /tmp/redos.txt` completó en **0.068ms** (hybrid) y **0.001ms** (regex)

**Evidencia**: `cargo test` con test temporal `redos_hybrid_no_hang_100k` → PASS en 0.01s. Revertido.

### 4. `unsafe` ✅

| Búsqueda | Resultado |
|----------|-----------|
| `grep -rn 'unsafe' crates/spike-scan/src/` | ❌ 0 ocurrencias |
| `grep -rn 'unsafe' crates/spike-scan/tests/` | ❌ 0 ocurrencias |
| `grep -rn 'unsafe' crates/benchkit/src/` | ❌ 0 ocurrencias |
| `grep -rn 'unsafe' crates/cerberus-core/src/` | ❌ 0 ocurrencias |

**Workspace lint**: `unsafe_code = "forbid"` en `[workspace.lints.rust]` — verificado funcionalmente:
- Se inyectó `unsafe { std::ptr::null() }` en `main.rs` → `cargo clippy` denegó con: `error: usage of an unsafe block`
- `unsafe_code = "forbid"` bloquea todo `unsafe` en el workspace

**Dependencia `aho-corasick`**: usa `unsafe` internamente para SIMD (`memchr`). Esto es normal y esperado. El lint `forbid` solo aplica al código del workspace, no a dependencias externas. Seguro.

### 5. Manejo de Errores ✅

| Escenario | Comportamiento | Exit Code |
|-----------|---------------|-----------|
| `--engine invalid` | Fallback silencioso a `EngineKind::Hybrid` | 0 |
| `--patterns -1` | `unwrap_or(300)` → default 300 | 0 |
| `--payload-size -1` | `unwrap_or(100)` → default 100 | 0 |
| `--iterations -1` | `unwrap_or(1000)` → default 1000 | 0 |
| `--patterns-file /nonexistent` | Error claro: "Cannot read file: No such file or directory" | 1 |
| `--patterns-file` con JSON inválido | Error claro: "Invalid JSON array: expected value at line 1 column 2" | 1 |
| `--patterns-file` con JSON válido | Funciona correctamente | 0 |

**Hallazgo**: `--engine invalid` no produce error; cae a `EngineKind::Hybrid` silenciosamente por el `match` con catch-all `_ => EngineKind::Hybrid`. Esto es un comportamiento de **fallback silencioso** — aceptable para un spike, pero documentado para futura corrección.

### 6. Prefiltros AC (Falsos Positivos de Prefijo) ✅

**Análisis de`engine_hybrid.rs`**:

- `extract_prefix()` extrae el prefijo literal más largo al inicio del patrón
- `AhoCorasick::find_iter()` encuentra todas las ocurrencias del prefijo en el payload
- Por cada hit AC, se ejecuta `regex.shortest_match(&payload[m.start()..])` con la regex completa

**Seguridad del prefiltro**:
1. **No falsos negativos**: Si la regex matchea, el prefijo literal debe estar presente en la posición de match. AC encuentra todas las ocurrencias del prefijo. Por lo tanto, ningún match real se pierde.
2. **No falsos positivos permanentes**: AC puede encontrar un prefijo donde la regex no matchea (ej. `abcXYZ` vs patrón `abc[0-9]+`). La regex se ejecuta igual y rechaza el match. El flag `matched[pat_idx]` evita re-evaluaciones redundantes una vez que el patrón ya matcheó.
3. **Patrones sin prefijo**: Van a `RegexSet` (unprefixed) que se ejecuta en paralelo con DFA — no hay riesgo de falsos negativos.

**Veredicto**: La lógica de prefiltros es correcta y completa. Ni un falso positivo de prefijo puede llevar a omitir un match real.

### 7. No Debug Leaks ✅

| Búsqueda | Resultado |
|----------|-----------|
| `dbg!` en `crates/spike-scan/` | ❌ 0 ocurrencias |
| `dbg!` en `crates/` (todo el workspace) | ❌ 0 ocurrencias |
| `println!` en `crates/spike-scan/` | 1 ocurrencia → `main.rs:182`: **intencional** (salida JSON del benchmark) |
| `eprintln!` en `crates/spike-scan/` | 3 ocurrencias → `main.rs:95,100,111`: **intencionales** (errores de compilación/archivo) |

## Hallazgos de Seguridad

### 🔴 Medium: `--engine invalid` fallback silencioso
- **Archivo**: `crates/spike-scan/src/main.rs:80-83`
- **Descripción**: El flag `--engine` con valor inválido cae al catch-all `_ => EngineKind::Hybrid` sin warning.
- **Impacto**: El usuario puede pensar que está usando otro engine (ej. `--engine vectorscan`) y obtener resultados híbridos sin notarlo.
- **Recomendación**: Añadir `eprintln!("Warning: unknown engine '...', falling back to hybrid")` o retornar error. Post-spike.

### 🟢 Info: Manejo de valores negativos con `unwrap_or`
- **Archivo**: `crates/spike-scan/src/main.rs:61-69`
- **Descripción**: `--patterns -1`, `--payload-size -1`, `--iterations -1` son silenciosamente reemplazados por defaults.
- **Impacto**: Bajo. `unwrap_or` es intencional para parseo robusto en un benchmark.
- **Recomendación**: Post-spike, usar `--patterns -1` como error explícito. Aceptable para MVP.

### 🟢 Info: Payload-size 0 produce throughput 0
- **Archivo**: `crates/spike-scan/src/main.rs:210-215`
- **Descripción**: Con `payload_size_bytes = 0`, `throughput_mbps` se calcula como 0.0 (división por cero evitada con `if p50_secs > 0.0`).
- **Impacto**: Ninguno — manejo correcto del edge case.

## Evidencia Reproducible

```bash
# Build
cargo build --release --workspace

# Tests
cargo test -p spike-scan

# ReDoS (100KB payload)
echo -e '(a|aa|aaa)+b\n(a|aa)*b\n(a+)+b' > /tmp/redos.txt
target/release/spike-scan --engine hybrid --patterns-file /tmp/redos.txt --payload-size 100 --iterations 10
# Result: 0.068ms p50, no hang

# Error handling
target/release/spike-scan --engine invalid --patterns -1 --payload-size -1 --iterations -1

# Clippy
cargo clippy --workspace --all-targets
```

## Decisión

**VEREDICTO: PASS** ✅

Todos los criterios de seguridad cumplen el estándar del Gauntlet. El motor híbrido es resistente a ReDoS (regex DFA + AC lineal), no contiene `unsafe` en código del workspace, maneja errores correctamente (con hallazgo menor documentado), y el prefiltro AC no introduce falsos negativos. Sin bloqueos de seguridad.