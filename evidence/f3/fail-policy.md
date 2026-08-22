# Evidence Pack — Fase 3 / fail-policy
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| FailClosed → Reject | `test::fail_closed_rejects` | Pass | ✅ |
| FailOpen → Allow | `test::fail_open_allows` | Pass | ✅ |
| Cualquier error en fail_closed → Reject | `test::fail_closed_rejects_any_error` | Pass | ✅ |
| Cualquier error en fail_open → Allow | `test::fail_open_passes_any_error` | Pass | ✅ |

## Casos adversariales probados
- Error strings arbitrarios → política se aplica por igual
- Config y deserialize via serde (YAML/JSON)

## NFR aplicables
- N/A

## Archivos
- `crates/cerberus-proxy/src/policy.rs`
- `crates/cerberus-proxy/src/config.rs` (FailPolicy enum)

## Desviaciones del plan
Ninguna. Política fail-open/closed configurable via config file.