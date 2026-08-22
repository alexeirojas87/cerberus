# Evidence Pack — Fase 5 / event-schema
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors (7 crates) | ✅ |
| `cargo test --workspace` | `cargo test --workspace` | 298 passed; 0 failed | ✅ |
| `cargo clippy --all-targets --workspace -- -D warnings` | `cargo clippy --all-targets --workspace -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Evento construido tiene ID único | `test::event_from_findings_has_id` | evt_ prefix | ✅ |
| Evento no contiene valores crudos | `test::event_has_no_raw_values` | Pass | ✅ |
| Conteos por flag correctos | `test::event_counts_multiple_flags` | flag.a=2, flag.b=1 | ✅ |
| Serialización JSON sin secretos crudos | `test::event_serializes_to_json` | Sin raw values | ✅ |
| Severidad máxima correcta | `test::event_severity_maps_correctly` | critical | ✅ |
| Timestamp presente y válido | `test::event_has_timestamp` | ts_unix > 0 | ✅ |

## Esquema (conforme a §6)
```json
{
  "id": "evt_<uuid>",
  "ts": "2026-08-17T12:00:00Z",
  "mode": "local",
  "tool": "claude-code",
  "provider": "anthropic",
  "flags": ["secret.openai_api_key"],
  "counts": {"secret.openai_api_key": 1},
  "action_taken": "redact",
  "hashed_values": ["sha256:..."],
  "severity": "critical"
}
```

## Archivos
- `crates/cerberus-store/src/event.rs` (nuevo)
- `crates/cerberus-store/src/lib.rs` (nuevo)

## Desviaciones del plan
Ninguna. Esquema de eventos conforme a §6 con fuga cero de secretos.