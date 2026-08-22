# Evidence Pack — Fase 8 / telemetry
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 334 passed; 0 failed | ✅ |
| Telemetría deshabilitada por defecto | `test::telemetry_disabled_by_default` | enabled=false | ✅ |
| Disabled → no envía | `test::telemetry_send_does_nothing_when_disabled` | ok | ✅ |
| Payload contiene datos correctos | `test::telemetry_payload_contains_version` | rule/event counts | ✅ |
| Enabled → envía ok | `test::telemetry_enabled_sends_ok` | ok | ✅ |
| Privacy policy no vacía | `test::privacy_policy_not_empty` | contiene OPT-IN | ✅ |
| Install ID persistente | `test::install_id_is_persistent` | misma instancia | ✅ |

## Privacidad
- **Opt-in:** deshabilitado por defecto
- **Datos NO recolectados:** secretos, PII, findings, hashes, nombres, emails
- **Datos recolectados:** versión, OS, rule count, event count, uptime
- **Configurable via:** `telemetry.enabled` en config.yaml

## Archivos
- `crates/cerberus-packs/src/telemetry.rs` (nuevo)

## Desviaciones del plan
Ninguna. Telemetría opt-in con política de privacidad clara.