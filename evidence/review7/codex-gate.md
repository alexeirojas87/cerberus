# Evidence Pack — review7/codex-gate

- Intento: 1
- Revisor: Codex independiente (no builder)
- Fecha: 2026-08-21 (America/New_York)
- Veredicto: **PASS**
- Alcance: Gauntlet v6.1 ejecutado desde cero sobre el checkout `CURRENT`, con cambios sin commit.
- Política de ejecución: todos los comandos shell se invocaron mediante el prefijo obligatorio `rtk`; se usó `rtk proxy` cuando era necesario conservar la salida completa.

## Identidad exacta del checkout evaluado

- Directorio: `/Users/alexeirojas/Work/Personal/Cerberus`
- Rama: `main`
- Commit base / `HEAD` antes y después de los gates: `09612f2142b8ab4e7655da6682231b2548e78bef`
- Commit base: `docs(gauntlet v6): evidence revisores + loop cerrado (7/7 PASS)`
- El `HEAD` no cambió durante la auditoría; no se hicieron commits ni fixes.
- Estado inicial: 17 archivos tracked modificados y archivos untracked preexistentes.

`git diff --stat` del estado evaluado (idéntico antes y después de los gates, sin contar untracked):

```text
Cargo.lock                                   |    2 +
crates/cerberus-engine/src/rule.rs           |    4 +-
crates/cerberus-packs/src/lib.rs             |    1 +
crates/cerberus-packs/src/updater.rs         |  429 ++++++-
crates/cerberus-proxy/Cargo.toml             |    3 +-
crates/cerberus-proxy/dashboard.html         |  408 ++++++-
crates/cerberus-proxy/src/api.rs             | 1606 +++++++++++++++++++++++---
crates/cerberus-proxy/src/config.rs          |   83 ++
crates/cerberus-proxy/src/lib.rs             |    1 +
crates/cerberus-proxy/src/proxy.rs           |  142 ++-
crates/cerberus-proxy/src/test_utils.rs      |    8 +-
crates/cerberus-proxy/tests/smoke_harness.rs |  738 ++++++++++++
crates/cerberus-store/src/store.rs           |  611 +++++++++-
crates/cerberus/Cargo.toml                   |    3 +-
crates/cerberus/src/cli_pack.rs              |  325 +++++-
crates/cerberus/src/daemon.rs                |  238 +++-
crates/cerberus/tests/pack_cli_via_api.rs    |  131 ++-
17 files changed, 4400 insertions(+), 333 deletions(-)
```

## Resultados reproducibles

| # | Comando realmente ejecutado | Exit | Evidencia / conteo | Resultado |
|---|---|---:|---|---|
| 1 | `rtk proxy cargo fmt --all -- --check` | 0 | Sin salida; 0 divergencias de formato. | PASS |
| 2 | `rtk proxy cargo clippy --workspace --all-targets -- -D warnings` | 0 | `Finished dev profile`; 0 warnings bajo `-D warnings`. | PASS |
| 3 | `rtk proxy cargo test --workspace --all-targets` | 0 | **534 passed / 0 failed** en 24 test binaries; 0 ignored y 0 measured. | PASS |
| 4 | `rtk proxy cargo test --release --workspace --all-targets` | 0 | **534 passed / 0 failed** en 24 test binaries; 0 ignored y 0 measured. | PASS |
| 5 | `rtk proxy python3 tools/simulate.py` | 0 | **29 PASS / 0 FAIL**; transcript automático indicado abajo. | PASS |
| 6 | `rtk proxy cargo test -p cerberus-packs --all-targets` | 0 | **59 passed / 0 failed**. | PASS |
| 7 | `rtk proxy cargo test -p cerberus --test pack_cli_e2e` | 0 | **3 passed / 0 failed** (`install`, `list/rollback` y gates Pro). | PASS |
| 8 | `rtk proxy cargo test --release --test load_test -- --nocapture` | 0 | **7 passed / 0 failed**; todos los p99 medidos bajo 5 ms. | PASS |
| 9a | `rtk proxy cargo test --release -p cerberus-engine --test precision_recall_test -- --test-threads=1` (corrida 1) | 0 | **6 passed / 0 failed**. | PASS |
| 9b | `rtk proxy shasum -a 256 evidence/f1/raw/precision_recall_results.txt` (corrida 1) | 0 | `969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e` | PASS |
| 9c | `rtk proxy cargo test --release -p cerberus-engine --test precision_recall_test -- --test-threads=1` (corrida 2) | 0 | **6 passed / 0 failed**. | PASS |
| 9d | `rtk proxy shasum -a 256 evidence/f1/raw/precision_recall_results.txt` (corrida 2) | 0 | `969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e` | PASS |
| 10 | `rtk proxy git diff --check` | 0 | Sin salida: 0 errores de whitespace. | PASS |

Conteo de la suite workspace obtenido sumando los resultados declarados por cada test binary: `6+35+2+3+4+1+175+15+6+0+6+7+5+59+117+38+22+3+0+4+7+0+11+8 = 534`. La suite release produjo el mismo desglose y total.

## Precision / recall determinista

El reporte generado en ambas corridas contiene:

```text
Corpus positives: 6 files
Corpus negatives: 4 files
Total expected instances: 35
Total detected instances: 33
False negatives:          2
True positives:           33 (28 regex + 5 entropy + 0 other)
False positives:          4  (3 regex + 1 entropy + 0 other)
Total findings (TP+FP):   37
Recall:    94.3% (33/35)
Precision: 89.2% (33/37)
```

- Gate recall: 94.3% >= 90% → PASS.
- Gate precision: 89.2% >= 85% → PASS.
- SHA-256 corrida 1 == corrida 2, byte por byte → PASS determinista.

## NFR de latencia

Salida de `load_test` release, presupuesto 5.0 ms:

| Caso | Medición | Resultado |
|---|---:|---|
| 50 KiB con secretos | p99 1.412 ms | PASS |
| 100 KiB limpio | p99 1.104 ms | PASS |
| 10 KiB limpio | p99 0.843 ms | PASS |
| scan + redact | p99 1.004 ms | PASS |
| decode + scan | p99 1.049 ms | PASS |
| engine vacío | avg 0.449 ms | PASS |
| 1 KiB limpio | p99 0.807 ms | PASS |

Peor p99 observado: **1.412 ms**, con margen de 3.588 ms frente al límite de 5 ms.

## Casos adversariales y cobertura observable

- Suite workspace debug y release completas: mismo total, **534/0** en ambos perfiles.
- Simulación real enforce/shadow: bloqueo, redacción JSON, keyword cross-field, allowlist, hot reload, break-glass, límite 413, no-leak/HMAC, CLI y auditoría shadow; **29/0**.
- Contrato de packs: firma/trust root, tamper, rollback, reopen, update transaccional, wire v2, límites de tamaño y gate Pro incluidos en los **59/0** tests del crate.
- CLI packs E2E: licencia Pro requerida para install/rollback y flujo install/list/rollback completo; **3/0**.
- Load test release ejercitó payloads de 1/10/50/100 KiB, decode/scan y redact; **7/0**.
- Precision/recall se serializó y verificó dos veces con `--test-threads=1`; hashes idénticos.

## Flakes, reintentos y mutaciones automáticas

- Flakes observados: **0**.
- Reintentos por fallo: **0**. Cada comando pasó en su primera ejecución; las dos corridas de precision/recall son un requisito de determinismo, no un retry.
- El test de precision/recall reescribió automáticamente `evidence/f1/raw/precision_recall_results.txt`, pero su contenido quedó idéntico al tracked (no aparece en `git diff`).
- `tools/simulate.py` generó automáticamente el log untracked `evidence/sim/sim-run-20260821-195542.log`; se declara como artefacto de test, no como edición intencional.
- Única edición intencional del revisor: `evidence/review7/codex-gate.md`.

## Veredicto

**PASS.** Todos los gates obligatorios devolvieron exit 0, los conteos fueron reproducibles, precision/recall superó sus umbrales con SHA-256 idéntico en dos corridas, el peor p99 quedó por debajo de 5 ms y `git diff --check` quedó limpio. Conforme a §8B, esta evidencia permite cerrar la unidad revisada; el avance del gate de fase sigue requiriendo el visto bueno del coordinador/humano.
