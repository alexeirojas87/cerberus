# Evidence Pack — Fase 3 / healthcheck-logs
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| Healthcheck devuelve status ok | `test::health_status_is_ok` | Pass | ✅ |
| Healthcheck refleja modo shadow | `test::health_status_shadow` | Pass | ✅ |
| Health JSON es válido | `test::health_json_is_valid` | Pass | ✅ |
| /health path detectado | `test::is_health_path_matches` | Pass | ✅ |
| Custom health path configurable | `test::custom_health_path` | Pass | ✅ |
| Upstream count en health | `test::upstream_count` | Pass | ✅ |
| Uptime incrementa | `test::uptime_increases` | Pass | ✅ |
| SecurityEvent niveles correctos | `test::security_event_levels` | Pass | ✅ |
| SecurityEvent mensajes | `test::security_event_messages` | Pass | ✅ |
| Log sin secretos no panic | `test::log_security_event_no_panic` | Pass | ✅ |
| Config YAML/JSON parse | `test::parse_yaml_minimal`, `test::parse_json` | Pass | ✅ |

## Casos adversariales probados
- Custom health path → se usa en vez de /health
- Upstreams vacíos → count=0 en health
- Log con findings → solo flags/hashes, nunca raw values
- Config inválida → error claro

## NFR aplicables
- **Logs sin secretos:** solo flags, categorías, hashes se loggean. Nunca raw values.

## Archivos
- `crates/cerberus-proxy/src/health.rs`
- `crates/cerberus-proxy/src/log.rs`
- `crates/cerberus-proxy/src/config.rs`

## Desviaciones del plan
Ninguna. Healthcheck + logging sin secretos + config file YAML/JSON.