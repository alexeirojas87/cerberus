# Evidence Pack — Gate v6 (Revisor independiente adversarial)

- Commit: `31c14cd` — fix(gauntlet v6): resolver 7 hallazgos funcionales del code review v6
- Worktree: v6-gate (detached HEAD), commit `31c14cd`
- Fecha: 2026-08-21
- Rol: REVISOR INDEPENDIENTE de gate. No modifica código; solo ejecuta y audita.

## Resultados

| # | Comando | Resultado | Valor esperado / observado |
|---|---------|-----------|----------------------------|
| 1 | `cargo fmt --all -- --check` | **PASS** | exit 0 (0 divergencias) |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** | 0 warnings; exit 0 |
| 3 | `cargo test --workspace --all-targets` | **PASS** | **454 passed / 0 failed** |
| 4 | `cargo test --release --workspace --all-targets` | **PASS** | **454 passed / 0 failed** (2 corridas: run1=454, run2=454 → determinista, mismo total) |
| 5 | `python3 tools/simulate.py` | **PASS** | **29 PASS / 0 FAIL**; transcript en `evidence/sim/sim-run-*.log` |
| 6 | `cargo test --release -p cerberus-engine --test precision_recall_test -- --test-threads=1` ×2 + `shasum -a256 evidence/f1/raw/precision_recall_results.txt` | **PASS** | 2/2 corridas ok; **sha estable `969e8490…15114d2e`** (idéntico en ambas corridas) |
| 7 | `cargo test --release -p cerberus --bin cerberus` | **PASS** | 30 passed / 0 failed; exit 0 |
| 8 | Tests P0 de firmas + update (cerberus-packs) | **PASS con salvedad CLI** | ver abajo |

## Detalle comando 8 (P0 de firmas + update)

El comando literal delegado (`cargo test -p cerberus-packs --test tampered_pack_rejected_on_reopen boot_without_trust_root_loads_no_packs`)
**falla con exit 101**: `--test` no es un subtarget válido en la CLI; esos P0 son *unit tests*
(viven en `crates/cerberus-packs/src/updater.rs`), no targets de integración.

Ejecutados por filtro posicional (forma válida), **los 4 tests subyacentes pasan, todos exit 0**:

- `tampered_pack_rejected_on_reopen` → **PASS** (exit 0)
- `boot_without_trust_root_loads_no_packs` → **PASS** (exit 0)
- `update_invalid_leaves_engine_and_disk_unchanged` (update test) → **PASS** (exit 0)
- `reopen_preserves_engine_composition_and_order` → **PASS** (exit 0)

Esto no es un defecto funcional del build (todos los tests pasan y además la suite completa
`cerberus-packs` corrigió 46/0). La salida del comando tal cual indado es inválida por
**uso erróneo de la CLI**, no por falla de tests. Verificado independientemente que los
P0 están presentes y verdes.

## Resumen cubierto
- fmt: limpio
- clippy: 0 warnings
- debug + release run: suite completa 454/0 en ambos perfiles, determinista en release
- sim e2e: 29/0
- f1 precision/recall: determinista, sha estable
- binario cerberus: 30/0
- P0 de firmas + update: presentes y pasando

## Conclusión
**GATE V6: PASS** — ninguna fr original del builder se quebró bajo escrutinio adversarial.
Un único matiz de comportamiento: el comando #8 tal como se delegó es inválido por CLI,
pero los tests que intenta cubrir existen y son green. No requiere fix de código.