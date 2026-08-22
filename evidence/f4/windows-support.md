# Evidence Pack — Fase 4 / windows-support
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 285 passed; 0 failed | ✅ |
| Config dir no vacío en cualquier plataforma | `test::config_dir_is_not_empty` | Pass | ✅ |
| Log dir bajo config dir | `test::log_dir_is_under_config` | Pass | ✅ |
| Daemon name sin espacios | `test::daemon_name_has_no_spaces` | Pass | ✅ |

## Platform-specific paths
| Plataforma | Config dir | Binary name |
|------------|-----------|-------------|
| macOS | ~/.cerberus | cerberus |
| Linux | $XDG_CONFIG_HOME/cerberus o ~/.config/cerberus | cerberus |
| Windows | %APPDATA%/Cerberus | cerberus.exe |

## Archivos
- `crates/cerberus/src/platform.rs` (nuevo)

## Desviaciones del plan
Ninguna. Soporte multiplataforma con paths y detección específicos.