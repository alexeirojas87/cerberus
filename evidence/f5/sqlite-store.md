# Evidence Pack — Fase 5 / sqlite-store + async-writer + retention + no-leak
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 298 passed; 0 failed | ✅ |
| Abrir SQLite crea tablas | `test::store_can_open_and_create_tables` | is_empty = true | ✅ |
| Escribir y leer evento | `test::store_write_and_read_back` | 1 evento, id coincide | ✅ |
| No leak: raw values no persisten | `test::store_no_raw_values_persisted` | Serialización sin raw | ✅ |
| Purge elimina eventos viejos | `test::store_purge_removes_old_events` | purged > 0 | ✅ |
| Múltiples eventos | `test::store_multiple_events` | count = 5 | ✅ |
| Eventos ordenados por tiempo | `test::store_recent_events_ordered_by_time` | DESC orden | ✅ |
| Conteo inicial cero | `test::store_event_count_zero_initially` | is_empty = true | ✅ |

## Funcionalidades
| Feature | Implementación |
|---------|---------------|
| SQLite local | `rusqlite` con `bundled` feature (sin dependencia externa) |
| Async writer | `tokio::sync::mpsc` con capacidad 1024, fire-and-forget |
| Retention configurable | `with_retention(days)`, purge on Drop |
| No leak garantizado | Solo flags/counts/hashes persisten, nunca raw values |
| Índices | ts_unix, action_taken, provider para queries eficientes |

## Archivos
- `crates/cerberus-store/src/store.rs` (nuevo)
- `crates/cerberus-store/Cargo.toml` (nuevo)

## Desviaciones del plan
Ninguna. SQLite local con writer async no bloqueante, retención configurable y fuga cero garantizada.