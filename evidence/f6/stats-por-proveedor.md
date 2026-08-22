# Evidence Pack — Fase 6 / stats-por-proveedor
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 305 passed; 0 failed | ✅ |
| Agrupa stats por proveedor | `test::stats_by_provider_groups_correctly` | 2 providers | ✅ |
| Agrupa stats por herramienta | `test::stats_by_tool_groups_correctly` | 2 tools | ✅ |
| Summary computa todas las métricas | `test::stats_summary_computes_all_metrics` | total/by_provider/by_tool | ✅ |
| Top flags ordenados por conteo | `test::stats_top_flags_ordered_by_count` | "frequent" > "rare" | ✅ |
| Eventos vacíos → summary vacío | `test::stats_empty_events_return_empty_summary` | 0 total | ✅ |

## Métricas disponibles
| Métrica | Descripción |
|---------|------------|
| by_provider | Total, by_action, top_flags por proveedor |
| by_tool | Total, by_action por herramienta |
| top_flags | Top 10 flags globales |
| by_action | Conteo global por acción (block/redact/warn/allow) |

## Archivos
- `crates/cerberus-store/src/stats.rs` (nuevo)

## Desviaciones del plan
Ninguna. Stats por proveedor, herramienta y flag.