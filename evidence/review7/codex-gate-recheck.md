# Evidence Pack — review7/codex-gate-recheck

- Intento: RECHECK independiente posterior a FIX dashboard wire v2
- Revisor: Codex independiente (no builder)
- Fecha: 2026-08-21 (America/New_York)
- Checkout: `CURRENT`, con cambios sin commit
- Veredicto: **PASS**
- Alcance: Gauntlet v6.1 completo solicitado por el coordinador y revalidación
  focalizada del P1 original de paridad dashboard file → wire v2.
- Restricciones respetadas: ningún fix, ningún commit y ninguna edición de
  evidencia previa. El único archivo escrito intencionalmente es este Evidence
  Pack.

## Identidad exacta del checkout evaluado

- Directorio: `/Users/alexeirojas/Work/Personal/Cerberus`
- Commit base / `HEAD`: `09612f2142b8ab4e7655da6682231b2548e78bef`
- Subject: `docs(gauntlet v6): evidence revisores + loop cerrado (7/7 PASS)`
- `HEAD` no cambió durante la auditoría.
- Estado de partida: 17 archivos tracked modificados y un conjunto de archivos
  untracked preexistentes. Los tests no añadieron cambios tracked observables.

`git diff --stat` final, que no incluye untracked:

```text
Cargo.lock                                   |    2 +
crates/cerberus-engine/src/rule.rs           |    4 +-
crates/cerberus-packs/src/lib.rs             |    1 +
crates/cerberus-packs/src/updater.rs         |  429 ++++++-
crates/cerberus-proxy/Cargo.toml             |    3 +-
crates/cerberus-proxy/dashboard.html         |  451 ++++++-
crates/cerberus-proxy/src/api.rs             | 1656 +++++++++++++++++++++++---
crates/cerberus-proxy/src/config.rs          |   83 ++
crates/cerberus-proxy/src/lib.rs             |    1 +
crates/cerberus-proxy/src/proxy.rs           |  142 ++-
crates/cerberus-proxy/src/test_utils.rs      |    8 +-
crates/cerberus-proxy/tests/smoke_harness.rs |  738 ++++++++++++
crates/cerberus-store/src/store.rs           |  611 +++++++++-
crates/cerberus/Cargo.toml                   |    3 +-
crates/cerberus/src/cli_pack.rs              |  325 ++++-
crates/cerberus/src/daemon.rs                |  238 +++-
crates/cerberus/tests/pack_cli_via_api.rs    |  131 +-
17 files changed, 4492 insertions(+), 334 deletions(-)
```

## Gauntlet ejecutado desde cero

Todos los comandos shell se invocaron mediante el prefijo obligatorio `rtk`.

| # | Comando ejecutado | Exit | Evidencia / conteo | Resultado |
|---|---|---:|---|---|
| 1 | `rtk proxy cargo fmt --all -- --check` | 0 | Sin salida; 0 divergencias. | PASS |
| 2 | `rtk proxy cargo clippy --workspace --all-targets -- -D warnings` | 0 | `Finished dev profile`; 0 warnings bajo `-D warnings`. | PASS |
| 3 | `rtk cargo test --workspace --all-targets` | 0 | **534 passed / 0 failed**, 23 suites, 37.55 s. | PASS |
| 4 | `rtk cargo test --release --workspace --all-targets` | 0 | **534 passed / 0 failed**, 23 suites, 4.35 s de tests. | PASS |
| 5 | `rtk proxy python3 tools/simulate.py` | 0 | **29 PASS / 0 FAIL**. | PASS |
| 6 | `rtk cargo test -p cerberus-packs --all-targets` | 0 | **59 passed / 0 failed**. | PASS |
| 7 | `rtk cargo test -p cerberus --test pack_cli_e2e` | 0 | **3 passed / 0 failed**. | PASS |
| 8 | `rtk cargo test -p cerberus --test pack_cli_via_api` | 0 | **4 passed / 0 failed**. | PASS |
| 9 | `rtk proxy cargo test --release --test load_test -- --nocapture` | 0 | **7 passed / 0 failed**; todos los presupuestos release pasan. | PASS |
| 10a | `rtk proxy cargo test --release -p cerberus-engine --test precision_recall_test -- --test-threads=1` (corrida 1) | 0 | **6 passed / 0 failed**. | PASS |
| 10b | `rtk proxy shasum -a 256 evidence/f1/raw/precision_recall_results.txt` (corrida 1) | 0 | `969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e` | PASS |
| 10c | mismo test de precision/recall (corrida 2) | 0 | **6 passed / 0 failed**. | PASS |
| 10d | mismo `shasum` (corrida 2) | 0 | `969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e` | PASS |
| 11 | `rtk proxy git diff --check` | 0 | Sin salida; 0 errores de whitespace. | PASS |

### Incidente de invocación no atribuible al código

Antes del comando canónico #2 se intentó por error `rtk clippy --workspace
--all-targets -- -D warnings`: `rtk` respondió `No such file or directory` y
exit 127, por lo que Cargo/Clippy no llegó a ejecutarse. Se corrigió la
invocación a `rtk proxy cargo clippy ...`; el gate real pasó a la primera con
exit 0. No hubo retry por fallo del código ni flakes de tests.

`tools/simulate.py` creó automáticamente
`evidence/sim/sim-run-20260821-204435.log`. Tras capturar el resultado 29/0 en
este pack, se eliminó únicamente ese transcript recién generado para respetar
la restricción de no escribir evidencia distinta de este archivo; no se tocó
ningún transcript preexistente. Precision/recall reescribió su resultado con
contenido byte-a-byte idéntico y por ello no añadió diff tracked.

## Precision / recall determinista

El reporte producido en ambas corridas contiene:

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

- Recall 94.3% >= 90%: PASS.
- Precision 89.2% >= 85%: PASS.
- SHA-256 corrida 1 == corrida 2: PASS determinista.

## NFR de latencia

`load_test` release usó presupuesto de 5.0 ms:

| Caso | Medición | Resultado |
|---|---:|---|
| 50 KiB con secretos | p99 1.151 ms | PASS |
| 100 KiB limpio | p99 1.020 ms | PASS |
| 10 KiB limpio | p99 0.827 ms | PASS |
| scan + redact | **p99 1.169 ms** | PASS |
| decode + scan | p99 1.157 ms | PASS |
| engine vacío | avg 0.405 ms | PASS |
| 1 KiB limpio | p99 0.742 ms | PASS |

Peor p99 observado: **1.169 ms**, 3.831 ms por debajo del límite estricto de
5 ms y también dentro del objetivo p99 de 3–5 ms.

## Recheck focalizado del P1 dashboard file → wire v2

| Criterio adversarial | Comando | Exit | Evidencia | Resultado |
|---|---|---:|---|---|
| Selector file; body wire v2; sin `path` ni `origin_name`; body representativo aceptado por `PackInstallRequest::parse_body` | `rtk cargo test -p cerberus-proxy dashboard_html_has_no_inline_event_handlers` | 0 | **1 passed**, 154 filtered. | PASS |
| CSP sin `unsafe-inline`/`unsafe-eval`/`unsafe-hashes` y hashes exactos de script/style servidos | `rtk cargo test -p cerberus-proxy dashboard_csp_has_no_unsafe_inline_and_hashes_the_served_blocks` | 0 | **1 passed**, 154 filtered. | PASS |
| Response real incluye CSP, `X-Frame-Options: DENY` y `nosniff` | `rtk cargo test -p cerberus-proxy dashboard_response_carries_the_csp_header` | 0 | **1 passed**, 154 filtered. | PASS |
| Envelope wire v2 máximo cabe en control plane | `rtk cargo test -p cerberus-proxy control_plane_max_bytes_is_1_mibe` | 0 | **1 passed**, 154 filtered. | PASS |
| HTTP acepta bytes wire v2 y rechaza `{"path":...}` antes del worker | `rtk cargo test -p cerberus-proxy --test smoke_harness pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path` | 0 | **1 passed**, 37 filtered. | PASS |
| Parser wire: roundtrip, fail-safe, legacy path y oversize | `rtk cargo test -p cerberus-packs wire` | 0 | **8 passed**, 51 filtered. | PASS |

El primer test inspecciona exactamente la función `installPack()` incluida en
el HTML servido y exige:

- `<input type="file" id="pack-file">` y ausencia de `pack-path`;
- `await file.arrayBuffer()` y `TextDecoder('utf-8', { fatal: true })`;
- constantes de UI iguales a `PACK_WIRE_VERSION` y `MAX_PACK_BYTES` de Rust;
- request única `const request = { wire_version: PACK_WIRE_VERSION, pack };`;
- envío a `/api/packs/install` de esa request;
- ausencia completa de los identificadores `path` y `origin_name` en el flujo;
- construcción de un body representativo con `{wire_version, pack}` y
  aceptación real por `PackInstallRequest::parse_body`.

La invariante de tamaño también queda ejecutada: `MAX_PACK_BYTES = 523,776`,
de modo que `2 * MAX_PACK_BYTES + 1024 = 1,048,576`, exactamente el límite de
1 MiB del colector HTTP. La CSP continúa derivando los hashes del mismo
`include_str!` servido y el test de response confirma que la cabecera efectiva
conserva las defensas.

## Cierre del P1 original

El FAIL histórico estaba demostrado por una incompatibilidad total: el
dashboard producía `{path}` y `PackInstallRequest::parse_body` devolvía
`LegacyPathRequest`/HTTP 400 antes de encolar al worker. En `CURRENT`, el mismo
contrato se prueba por ambos lados:

1. el productor dashboard sólo puede construir `{wire_version, pack}` desde
   los bytes del archivo y no transporta ruta/origen;
2. un ejemplar de esa forma pasa el parser servidor;
3. el smoke HTTP acepta wire v2 y mantiene el rechazo explícito de wire v1;
4. CLI local y vía API permanecen verdes, junto con workspace debug/release.

No queda una ruta reproducible del P1 original y todos los gates solicitados
son PASS. Por tanto el P1 **queda realmente cerrado** en este checkout.

## Veredicto

**PASS.** Todos los comandos canónicos solicitados devolvieron exit 0; las
suites workspace dieron 534/0 en debug y release, precision/recall fue
determinista con SHA idéntico, el peor p99 fue 1.169 ms, el diff está limpio y
los tests focalizados demuestran la compatibilidad dashboard file → wire v2,
la validez de CSP y la cota de control-plane. Conforme a §8B.7, el visto bueno
del gate de fase sigue perteneciendo al coordinador/humano.
