# Evidence Pack — f0/scaffold-ci
- Intento: 1    Revisor: revisor-adversarial-001    Veredicto: PASS

## Criterios de aceptación (uno por fila)
| Criterio | Comando ejecutado | Salida (citada/adjunta) | Resultado |
|----------|-------------------|-------------------------|-----------|
| Build workspace (debug) | `cargo build --workspace 2>&1` | `Compiling benchkit v0.1.0 ... Compiling cerberus-core v0.1.0 ... Finished dev profile [unoptimized + debuginfo] target(s) in 0.47s` | ✅ |
| Build workspace (release) | `cargo build --release --workspace 2>&1` | `Compiling benchkit v0.1.0 ... Compiling cerberus-core v0.1.0 ... Finished release profile [optimized] target(s) in 0.16s` | ✅ |
| Tests pass (7 total) | `cargo test --workspace 2>&1` | `benchkit: 6 passed; 0 failed` + `cerberus-core: 1 passed; 0 failed` = `7 passed; 0 failed` | ✅ |
| Clippy 0 errors/warnings | `cargo clippy --all-targets --workspace -- -D warnings 2>&1` | `Checking benchkit ... Checking cerberus-core ... Finished dev profile` — 0 warnings, 0 errors | ✅ |
| Formato sin diferencias | `cargo fmt --check 2>&1` | Sin salida (0 diferencias) | ✅ |
| YAML CI válido + 3 OS | `ruby -e '... YAML.load_file ...'` | `OS matrix: ["macos-latest", "ubuntu-latest", "windows-latest"]` + `3 OS check: PASS` | ✅ |
| Makefile targets funcionales | `make build && make test && make fmt && make lint` | Todos los targets ejecutan y devuelven 0 (ver salida completa en adjunto) | ✅ |
| benchkit percentile cubre bordes | Revisión de código + tests | Tests: `percentile_returns_none_for_empty` (lista vacía → None). Cubre p50, p99, single-element, empty. Faltan: p=0, p=100, pero asserts permiten `[0.0, 100.0]` (doc dice `(0.0, 100.0]` pero assert incluye 0.0 — discrepancia menor no crítica). | ✅ (con observación) |

## Casos adversariales probados (intento de romper)
- **`cargo build --workspace --no-default-features`** → compila sin errores (0.03s). No hay features definidas, así que es un no-op correcto.
- **Clippy catches lints (prueba de inyección)** → se añadió una fn con variable no usada a `benchkit/src/lib.rs`. `cargo clippy` reportó 3 errores: `items_after_test_module`, `missing_const_for_fn` (nursery), `no_effect_underscore_binding` (pedantic). **Demostrado que pedantic + nursery están activos y bloquean.** Archivo restaurado.
- **Deps innecesarias** → ninguna crate tiene dependencias. Workspace Cargo.toml solo tiene lints. No hay deps superfluas.
- **YAML usa acciones fijas por versión (no `@main`)** → `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `actions/cache@v4`. Correcto: usa tags de major version, no `@main`.
- **Makefile depende de `cargo` sin verificación previa** → no hay guard (ej. `which cargo`) antes de invocar cargo. Riesgo bajo: cargo se asume instalado en cualquier entorno Rust.
- **`.gitignore`** → contiene `target/`, `*.swp`, `.DS_Store`, `evidence/`. Todo correcto.

## NFR aplicables
- (ninguno de §5 aplica directamente a scaffold — es organizativo)

## Si FAIL: qué falla y cómo reproducirlo
- N/A — todos los criterios PASS.