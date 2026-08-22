# Evidence Pack: spike-escaneo correctness v2

**Revisor:** REVISOR 1 (correctness)
**Intento:** 2 (post-fixer)
**Worktree:** cerberus-wt-f0-scan-rv2-correctness
**Fecha:** 2026-08-16

---

## Veredicto: FAIL

## Criterios

### 1. `cargo build --workspace` → 0 errores
✅ **PASS** — Compila sin errores ni warnings en 4.88s (dev profile).

### 2. `cargo test -p spike-scan` → todos pass
✅ **PASS** — 26 tests pasan:
- 7 lib unit tests (patterns, payload)
- 11 main unit tests (engine_hybrid)
- 8 integration tests (binary, schemas, edge cases)

### 3. `cargo clippy -p spike-scan --all-targets -- -D warnings` → 0 errores
✅ **PASS** — Clippy 0 errores, 0 warnings.

### 4. `cargo fmt --check` → sin diferencias
✅ **PASS** — Sin diferencias.

### 5. Bench rápido: JSON válido con campos requeridos
✅ **PASS** — `--patterns 50 --payload-size 10 --iterations 50` produce JSON válido con engine default (hybrid) y campos `compile_ms, scan_p50_ms, scan_p99_ms, throughput_mbps, matches_found`.

### 6. Engine híbrido produce JSON correcto
✅ **PASS** — `--engine hybrid --patterns 300 --payload-size 100 --iterations 100` produce JSON con `engine: "hybrid"` y sub-objeto `hybrid` con campos: `compile_ms, matches_found, scan_p50_ms, scan_p99_ms, throughput_mbps`.

### 7. Tests adversariales: --patterns 0, --payload-size 0, --engine invalid
❌ **FAIL** — `--engine invalid` no produce error. Corre silenciosamente con engine default (hybrid). Bug en `crates/spike-scan/src/main.rs:80-83`:

```rust
"--engine" => {
    i += 1;
    args.engine = match raw[i].as_str() {
        "regex" => EngineKind::Regex,
        _ => EngineKind::Hybrid,  // BUG: catch-all silencia errores
    };
}
```

`--patterns 0` y `--payload-size 0` pasan sin error ✅ (edge cases válidos que producen JSON coherente). `--engine invalid` debe fallar con error decente, no correr con default.

### 8. Revisión de `engine_hybrid.rs`
✅ **PASS** — Análisis del código:

| Aspecto | Estado | Detalle |
|---------|--------|---------|
| `extract_prefix` maneja escapes | ✅ | `\b`, `\B` zero-width → skip; `\d`, `\w`, `\p`, etc. → break |
| `extract_prefix` maneja regex meta | ✅ | `(`, `)`, `[`, `]`, `.`, `?`, `*`, `+`, `|`, `^`, `$`, `{`, `}` → break |
| `extract_prefix` retorna `None` sin prefijo literal | ✅ | `MIN_PREFIX_LEN = 2` → `\d{5}` → `None`, `[a-f]{32}` → `None` |
| `extract_prefix` captura `\bkey\b` → `"key"` | ✅ | Test lo verifica |
| Prefilter Aho-Corasick ventana correcta | ✅ | `shortest_match(&payload[m.start()..])` verifica regex desde posición del prefijo |
| Patrones sin prefijo → RegexSet fallback | ✅ | `unprefixed_set` + `unprefixed_indices` manejan correctamente |
| Empty patterns → 0 matches | ✅ | Test lo verifica |
| Empty payload → 0 matches | ✅ | Test lo verifica |
| Sin falsos positivos | ✅ | Test lo verifica |

## Bug encontrado

**`main.rs:80-83`** — `--engine invalid` es silenciosamente aceptado como `EngineKind::Hybrid`. Debería imprimir error y salir con código != 0, o parsear solo "regex"/"hybrid" y rechazar otros valores.

## Conclusión

No pasa el **Gauntlet de §8B**: criterion 7 falla. El fixer debe corregir la validación de `--engine` en `parse_args()` antes de que esta unidad se considere completa.