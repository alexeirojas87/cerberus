# Evidence Pack — Fase 7 / auto-update
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 320 passed; 0 failed | ✅ |
| PackManager install + list | `test::pack_manager_install_and_list` | 1 pack, active | ✅ |
| Rollback funciona | `test::pack_manager_rollback` | ok | ✅ |
| Rollback sin historial falla | `test::pack_manager_rollback_empty_history_fails` | error | ✅ |
| Pack manipulado no se instala | `test::pack_manager_tampered_pack_fails_install` | error | ✅ |
| Cargar pack desde archivo | `test::load_pack_from_file_roundtrip` | verify ok | ✅ |
| Cargar packs desde directorio | `test::load_packs_from_dir` | 2 packs | ✅ |
| Engine accesible después de instalar | `test::pack_manager_engine_accessible` | 0 rules inicial | ✅ |

## Funcionalidades del PackManager
| Feature | Implementación |
|---------|---------------|
| Instalación con verificación de firma | `install()` verifica antes de compilar |
| Hot-reload del engine | Engine nuevo reemplaza al activo |
| Rollback | Historial de últimos 5 engines |
| Persistencia en disco | Packs guardados en `pack_dir/{name}.json` |
| Carga batch desde directorio | `load_packs_from_dir()` |

## Archivos
- `crates/cerberus-packs/src/updater.rs` (nuevo)

## Desviaciones del plan
Ninguna. Auto-update con verificación de firma, hot-reload y rollback.