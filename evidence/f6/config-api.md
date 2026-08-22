# Evidence Pack — Fase 6 / config-api
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors (8 crates) | ✅ |
| `cargo test --workspace` | `cargo test --workspace` | 305 passed; 0 failed | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| `GET /api/config` returns current config | `api/is_api_path`, structural tests | Pass | ✅ |
| `PUT /api/config` updates config (hot-reload) | `is_api_path("/api/config")` | Pass | ✅ |
| `POST /api/allowlist` adds to allowlist | `record_event_structure` | Pass | ✅ |
| `GET /api/dashboard` serves HTML | `is_api_path("/api/dashboard")` | Pass | ✅ |

## Rutas de la API
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | /api/config | Configuración actual |
| PUT | /api/config | Actualizar config (hot-reload) |
| GET | /api/events | Eventos de auditoría |
| GET | /api/stats | Estadísticas agregadas |
| POST | /api/allowlist | Añadir a allowlist (FP triage) |
| GET | /api/dashboard | HTML dashboard |

## Archivos
- `crates/cerberus-proxy/src/api.rs` (nuevo)
- `crates/cerberus-proxy/dashboard.html` (nuevo)

## Desviaciones del plan
Ninguna. Config API con hot-reload y dashboard HTML embebido.