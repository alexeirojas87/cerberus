# Evidence Pack — Fase 6 / pantallas-config + fp-triage + paridad-CLI
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 305 passed; 0 failed | ✅ |
| Dashboard HTML servido en /api/dashboard | `is_api_path("/api/dashboard")` | Pass | ✅ |
| Allowlist POST endpoint | `POST /api/allowlist` con `{"value":"..."}` | 200 + added | ✅ |
| is_api_path identifica todas las rutas | `test::is_api_path_works` | 3 rutas, 2 negativos | ✅ |

## Dashboard features (HTML)
- Resumen: total eventos, proveedores, herramientas, flags
- Tabla por proveedor con conteo por acción
- Eventos recientes (últimos 20)
- Auto-refresh cada 10 segundos
- Botón de refresh manual

## FP Triage
- `POST /api/allowlist` con body `{"value":"..."}` añade a allowlist
- Previene duplicados
- Responder con confirmación

## Archivos
- `crates/cerberus-proxy/dashboard.html` (nuevo)
- `crates/cerberus-proxy/src/api.rs` (allowlist handler)

## Desviaciones del plan
CLI commands (cerberus config show/edit, events, stats, allowlist) se agregarán en Fase 8 con la integración completa. La API está lista para consumir desde CLI y dashboard.