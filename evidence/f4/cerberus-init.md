# Evidence Pack — Fase 4 / cerberus-init
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 285 passed; 0 failed | ✅ |
| Detecta agentes conocidos | `test::detect_agents_returns_vec` | len >= 4 | ✅ |
| scan_text sin secretos → clean | `test::scan_empty_text_returns_clean` | "No se detectaron" | ✅ |
| scan_text con API key → findings | `test::scan_with_skey_detects` | "Hallazgos" | ✅ |
| scan_file inexistente → error | `test::scan_nonexistent_file_returns_error` | is_err | ✅ |
| `cerberus init` crea config dir + yaml | `run_init("/tmp/cerberus-test")` | Report + archivos | ✅ |
| `cerberus test <text>` escanea inline | `scan_text()` | Findings o clean | ✅ |
| `cerberus scan <file>` escanea archivo | `scan_file()` | Findings o error | ✅ |

## Casos adversariales probados
- init sin agentes instalados → reporta con tips de config manual
- agentes configurados → detecta y marca como listo
- archivo inexistente → error claro
- texto sin secretos → mensaje clean (no findings)

## Archivos
- `crates/cerberus/src/init.rs` (nuevo)

## Desviaciones del plan
Ninguna. Autodetección de Claude Code, Codex, opencode, pi, Continue/Cursor.