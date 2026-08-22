# Evidence Pack — Fase 0: spike-escaneo · Correctness v3

## Contexto
- **Objetivo**: verificar que el criterio que falló en el intento 2 (manejo de `--engine invalid`) AHORA pasa, y que no se rompió nada.
- **Worktree**: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/cerberus-wt-f0-scan-rv3-verify`
- **Rol**: revisor de verificación rápida.
- **Fecha**: 2026-08-16

## Veredicto: **PASS**

El criterio clave (`--engine bogus` → exit=1 + error claro en stderr) fue corregido y el resto de la batería permanece verde. No se detectó regresión.

## Resultados por comando

### 1. Build workspace
`cargo build --workspace 2>&1`
```
Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.09s
```
**PASS** — compila sin errores (crates: benchkit, cerberus-core, spike-scan).

### 2. Formato
`cargo fmt --check 2>&1`
```
(exit 0, sin salida)
```
**PASS** — sin diferencias.

### 3. Clippy
`cargo clippy -p spike-scan --all-targets -- -D warnings 2>&1`
```
Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.74s
```
**PASS** — 0 errores / 0 warnings.

### 4. Tests
`cargo test -p spike-scan 2>&1`
```
Unittests src/lib.rs      : 7 passed; 0 failed
Unittests src/main.rs     : 11 passed; 0 failed
tests/integration.rs      : 8 passed; 0 failed
--------------------------------------------------
Total: 26 passed; 0 failed (3 suites)
```
**PASS** — 26/26 (7 lib + 11 unit + 8 integration).

### 5. Criterio clave
a) Engine inválido — `cargo run --bin spike-scan -- --engine bogus --patterns 5 --payload-size 1 --iterations 1`:
- stdout (con `2>/dev/null`): vacío
- stderr: `invalid engine 'bogus' (expected 'regex' or 'hybrid')`
- `exit=1`
**PASS** — error claro en stderr y exit code 1 (el fallo del intento 2).

b) `--engine regex` (con `2>/dev/null`):
```
{
  "engine": "regex",
  "iterations": 3,
  "patterns": 3,
  "payload_size_kb": 1,
  "regex": { "compile_ms": ..., "matches_found": 3, "scan_p50_ms": 0.003, "scan_p99_ms": 0.004, "throughput_mbps": ... },
  "vectorscan": null
}
```
Validado con `python3 -c 'import json,sys; json.load(sys.stdin)'` → **JSON válido**.

c) `--engine hybrid` (con `2>/dev/null`):
```
{
  "engine": "hybrid",
  "hybrid": { "compile_ms": ..., "matches_found": 3, "scan_p50_ms": 0.033, "scan_p99_ms": 0.036, "throughput_mbps": ... },
  "iterations": 3,
  "patterns": 3,
  "payload_size_kb": 1,
  "vectorscan": null
}
```
Validado con el mismo parser → **JSON válido**.

## Conclusión
- Fix del disparador confirmado: `--engine invalid` retorna `exit=1` con mensaje `invalid engine 'bogus' (expected 'regex' or 'hybrid')` exclusivamente en stderr, sin fuga a stdout.
- Sin regresión: build, fmt, clippy (-D warnings) y 26/26 tests verdes; salida JSON correcta para regex y hybrid.
- **Veredicto: PASS** — gate de correctness autorizado.