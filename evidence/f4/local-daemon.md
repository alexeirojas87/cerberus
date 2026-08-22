# Evidence Pack — Fase 4 / local-daemon
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors (6 crates) | ✅ |
| `cargo test --workspace` | `cargo test --workspace` | 285 passed; 0 failed | ✅ |
| `cargo clippy --all-targets --workspace -- -D warnings` | `cargo clippy --all-targets --workspace -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| `cerberus status` muestra estado | `test::status()` | String con STOPPED/RUNNING | ✅ |
| `cerberus start` inicia proxy en puerto | `daemon::start(port)` | Inicia proxy + escribe PID | ✅ |
| `cerberus stop` detiene proxy | `daemon::stop()` | Mata proceso + limpia PID | ✅ |
| PID path en directorio de config | `test::pid_path_is_in_config_dir` | Pass | ✅ |
| Config dir es ~/.cerberus | `test::config_dir_is_dot_cerberus` | Pass | ✅ |

## Casos adversariales probados
- start con daemon ya corriendo → error claro
- stop sin daemon corriendo → error claro
- PID stale → status detecta y limpia
- ANSI styling para estados

## Archivos
- `crates/cerberus/src/main.rs` (nuevo)
- `crates/cerberus/src/daemon.rs` (nuevo)

## Desviaciones del plan
Ninguna. Daemon con start/stop/status vía PID file.