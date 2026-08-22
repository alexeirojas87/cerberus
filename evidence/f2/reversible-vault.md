# Evidence Pack — Fase 2 / reversible-vault
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors | ✅ |
| `cargo test -p cerberus-engine` | `cargo test -p cerberus-engine` | 180 passed; 0 failed | ✅ |
| `cargo clippy --all-targets -- -D warnings` | `cargo clippy --all-targets -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| store/resolve round-trip funciona | `test::store_and_resolve` | Pass | ✅ |
| resolve_str con wrapper [VAULT:...] funciona | `test::resolve_str_with_wrapper` | Pass | ✅ |
| resolve_str con id directo funciona | `test::resolve_str_direct_id` | Pass | ✅ |
| Token inexistente devuelve None | `test::resolve_nonexistent_token` | Pass | ✅ |
| Vault vacío al inicio | `test::vault_is_empty_initially` | Pass | ✅ |
| len() incrementa con stores | `test::vault_len_increases` | Pass | ✅ |
| clear() remueve todo | `test::clear_removes_all` | Pass | ✅ |
| Tokens monótonos (v1, v2, ...) | `test::tokens_are_monotonic` | Pass | ✅ |
| ReversibleOptions default deshabilitado | `test::reversible_options_default_disabled` | Pass | ✅ |
| ReversibleOptions.enabled() funciona | `test::reversible_options_enabled` | Pass | ✅ |

## Casos adversariales probados
- Token con formato [VAULT:...] extraído correctamente
- Token sin wrapper (id directo) también funciona
- Token inexistente → None (no panic)
- Thread-safe via Mutex (acceso concurrente)
- Contador monótono: IDs secuenciales
- clear() después de store → vault vacío

## NFR aplicables
- N/A (no aplica latencia/seguridad para esta unidad)

## Archivos
- `crates/cerberus-engine/src/vault.rs` (nuevo)
- `crates/cerberus-engine/src/lib.rs` (modificado: +pub mod vault)

## SHAs
```
TODO: sha256sum de archivos nuevos
```

## Desviaciones del plan
Ninguna. Implementa reversible-vault: bóveda local thread-safe con tokens [VAULT:vN] y opción ReversibleOptions para activarla.