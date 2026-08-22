# Evidence Pack — Fase 2 / break-glass
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors | ✅ |
| `cargo test -p cerberus-engine` | `cargo test -p cerberus-engine` | 180 passed; 0 failed | ✅ |
| `cargo clippy --all-targets -- -D warnings` | `cargo clippy --all-targets -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Break-glass deshabilitado devuelve findings originales | `test::disabled_returns_original` | Pass | ✅ |
| Break-glass habilitado sin Block devuelve original | `test::enabled_without_block_returns_original` | Pass | ✅ |
| Break-glass remueve Block y devuelve BypassRecord | `test::enabled_with_block_removes_block` | Pass | ✅ |
| allow_once estático funciona | `test::allow_once_static_works` | Pass | ✅ |
| Múltiples blocks todos bypasseados | `test::multiple_blocks_all_bypassed` | Pass | ✅ |

## Casos adversariales probados
- Break-glass deshabilitado → comportamiento normal, bypass no aplica
- Sin findings Block → bypass no hace nada
- Block + Redact/Warn → solo Block se remueve, los demás pasan
- allow_once con razón arbitraria → registrada en BypassRecord
- Múltiples Block → todos se remueven, conteo correcto

## NFR aplicables
- N/A (no aplica latencia/seguridad para esta unidad)

## Archivos
- `crates/cerberus-engine/src/break_glass.rs` (nuevo)
- `crates/cerberus-engine/src/lib.rs` (modificado: +pub mod break_glass)

## SHAs
```
TODO: sha256sum de archivos nuevos
```

## Desviaciones del plan
Ninguna. Implementa exactamente el diseño de break-glass: header o allow_once que deja pasar findings Block y deja registro auditado.