# Evidence Pack — Fase 2 / action-precedence
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors | ✅ |
| `cargo test -p cerberus-engine` | `cargo test -p cerberus-engine` | 180 passed; 0 failed | ✅ |
| `cargo clippy --all-targets -- -D warnings` | `cargo clippy --all-targets -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Block > Redact > Warn > Allow en spans solapados | `test::full_precedence_chain_block_over_redact_over_warn_over_allow` | Pass | ✅ |
| Redact gana sobre Warn+Allow en overlap | `test::redact_wins_over_warn_and_allow_span_overlap` | Pass | ✅ |
| resolve_spans ordena por precedencia | `test::resolve_spans_ordered_by_precedence` | Pass | ✅ |
| Spans no solapados se conservan todos | `test::resolve_non_overlapping_spans_all_kept` | Pass | ✅ |
| resolve_spans es pública y documentada | `pub fn resolve_spans` con `#[must_use]` | Pass | ✅ |

## Casos adversariales probados
- 4 acciones solapadas (Block > Redact > Warn > Allow) → Block gana
- Redact + Warn + Allow solapados → Redact gana (más severa sin Block)
- Dos Allow solapados → primero se conserva (misma acción)
- Spans disjuntos → ambos se conservan
- Block global siempre se aplica antes de resolver spans (apply_redaction check)

## NFR aplicables
- N/A (no aplica latencia/seguridad para esta unidad)

## Archivos modificados
- `crates/cerberus-engine/src/redact.rs` (resolve_spans/y action_severity públicos + tests)
- No se añadieron nuevas dependencias

## SHAs
```
TODO: sha256sum de archivos modificados
```

## Desviaciones del plan
Ninguna. La precedencia sigue exactamente el diseño: Block > Redact > Warn > Allow, con resolve_spans como API pública para que otros módulos la usen.