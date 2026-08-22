# Evidence Pack — f6/daemon-config-path-injection-v61-fix
- Intento: FIX 1    Revisor: worker `task_07d5cf6d1c11` (sin subagentes por instrucción del dispatch)    Veredicto: PASS

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| Producción conserva `config_file()` y la lectura admite una ruta explícita | `cargo test -p cerberus daemon::tests::load_proxy_config -- --nocapture` | `2 passed; 0 failed` | ✅ |
| La ausencia de config se prueba en un directorio temporal aislado, sin leer el HOME del usuario | mismo test focalizado debug | `load_proxy_config_none_when_no_file` incluido; `2 passed; 0 failed` | ✅ |
| Una config presente en la ruta inyectada se lee realmente | mismo test focalizado debug | `load_proxy_config_reads_explicit_file` incluido; `2 passed; 0 failed` | ✅ |
| Regresión focalizada optimizada | `cargo test --release -p cerberus daemon::tests::load_proxy_config -- --nocapture` | `2 passed; 0 failed` | ✅ |
| Formato | `cargo fmt --all -- --check` | exit 0, sin diff | ✅ |
| Lints estrictos del workspace | `cargo clippy --workspace --all-targets -- -D warnings` | `No issues found` | ✅ |
| Gate release que originó el fallo | `cargo test --release --workspace --all-targets` | `533 passed` en `23 suites`; exit 0 | ✅ |

## Casos adversariales probados

- El usuario puede tener un `~/.cerberus/config.yaml` real: el test de ausencia construye una ruta no creada dentro de `tempfile::tempdir()` y llama exclusivamente a `load_proxy_config_from(&missing)`; el estado real del HOME no participa.
- Una ruta temporal con YAML válido (`mode: shadow`) devuelve `Some(ProxyConfig)` y conserva el valor leído; esto evita un falso positivo donde la función parametrizada ignorase su argumento.
- Auditoría de tests vecinos en `daemon::tests`: `config_dir_is_dot_cerberus`, `pid_path_is_in_config_dir` y `packs_dir_is_under_config_dir` sólo comprueban composición/sufijos y no leen archivos globales; los tests que mutan variables de entorno están serializados por `ENV_LOCK`. No se encontró otra dependencia equivalente del contenido de la config real.

## NFR aplicables

- Latencia: no aplica; el cambio sólo afecta la selección de ruta durante el arranque y no el dataplane.
- Seguridad/privacidad: el test no lee, modifica ni elimina la config real del usuario; `tempfile::TempDir` elimina el fixture al salir.

## Riesgos residuales

- Se añadió `tempfile = "3"` sólo como dependencia de desarrollo; actualizó la entrada de `cerberus` en `Cargo.lock`, pero reutilizó la versión ya resuelta en el workspace y no añadió un paquete/version nueva.
- El árbol principal contenía cambios previos extensos, incluido `daemon.rs`; este FIX se limitó al helper de carga, dos tests y la dependencia de desarrollo, sin commits.
