# Evidence Pack — Recheck adversarial v6.1 del FIX P1-1 (worktree CURRENT, sin commit)

- **Checkout auditado:** `HEAD = 09612f2142b8ab4e7655da6682231b2548e78bef` + working tree completo
  (17 archivos tracked modificados, mismo diff que la review previa menos los cambios del FIX:
  `dashboard.html`, `wire.rs`, `api.rs` y el test de contrato). No se hicieron commits.
- **Rol:** REVISOR independiente (adversario). Solo lectura + ejecución de tests/gates; ningún fix,
  ningún commit. Único archivo escrito: este evidence.
- **Herramienta:** `cargo` (workspace), `cargo fmt`, `cargo clippy`, `python3 tools/simulate.py`.
- **Dictamen global: PASS (0 P0 / 0 P1 del MVP).** El P1-1 de la review previa (dashboard wire v1)
  está reparado y verificado con tests; no se encontraron bypasses ni regresiones en
  config/policy/packs/store/daemon. P2 residuales listados en §3.

> Este dictamen revalida únicamente el FIX y sus alrededores sobre el mismo checkout. El dictamen
> histórico FAIL de `evidence/review7/opencode-findings.md` se conserva intacto; este documento no
> lo reescribe.

---

## 1. Veredicto sobre el P1 previo

### P1-1 (cerrado): el dashboard rompía la paridad CLI↔dashboard enviando `{"path":…}` (wire v1) que `api.rs` rechaza con 400

Fijado en el mismo checkout y confirmado por lectura estática + tests ejecutados:

| Criterio del fix | Ref exacta en CURRENT | Verificación |
|---|---|---|
| Input file REAL (no `pack-path`/input.value) | `dashboard.html:108-110` `<input type="file" id="pack-file" accept=".json,application/json">` | ✅ no existe `pack-path`; el contrato test lo prohíbe (`api.rs:2266`) |
| Lectura File→ArrayBuffer→TextDecoder fatal | `dashboard.html:565-566` `file.arrayBuffer()` + `new TextDecoder('utf-8',{fatal:true}).decode(bytes)` | ✅; el test exige `await file.arrayBuffer()` y el TextDecoder fatal (`api.rs:2276-2277`) |
| Límite cliente acotado | `dashboard.html:524` `MAX_PACK_BYTES=523776`; checks `file.size===0` y `>MAX_PACK_BYTES` (`:553-560`); `523776` == `wire::MAX_PACK_BYTES` | ✅ el contrato exige el valor literal `const MAX_PACK_BYTES = {wire::MAX_PACK_BYTES};` (`api.rs:2282-2285`) |
| Shape wire v2 exacta = `{wire_version:2, pack}` | `dashboard.html:575` `const request = { wire_version: PACK_WIRE_VERSION, pack };` (`PACK_WIRE_VERSION=2`) | ✅ test: `install_pack.contains("const request = { wire_version: PACK_WIRE_VERSION, pack };")`; el representative body parsea por `parse_body` OK (`api.rs:2286-2302`) |
| Ausencia de ruta local y de `origin_name` | `installPack` no toca `input.value` ni rutas; no envía `origin_name` | ✅ `assert!(!install_pack.contains("path"))` y `!install_pack.contains("origin_name")` (`api.rs:2272-2288`) |
| Manejo de errores accionable | `:549-559` (sin archivo/vacío/oversize), `:567-571` (UTF-8), `:580-594` (daemon rechaza / conexión) vía `textContent` | ✅ (lectura estática + `dashboard_html_has_no_inline_event_handlers` pasa) |
| Auth del endpoint | `/api/packs/install` pasa por `auth_gate` (`api.rs:319-324`, 270-277); `sendJson` manda `X-Cerberus-Admin-Token` | ✅ ninguna prueba de ruta sin token pasó |
| CSP sin `unsafe-inline` | `build_dashboard_csp` hashea el mismo `include_str!`; `api.rs:1261-1271`, 1446-1460 | ✅ `dashboard_csp_has_no_unsafe_inline_and_hashes_the_served_blocks` + `dashboard_serves_an_effective_csp_header` pasan |

El formato del request generado por la UI coincide exactamente con lo que `PackInstallRequest::parse_body`
acepta (`wire.rs:173-219`): `validate_signed_pack` exige `pack_json`/`signature_hex`/`signer_public_key_hex`
no vacíos; la firma se verifica contra el trust root en el daemon, jamás en cliente. El test HTTP real
`pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path` (smoke) demuestra 200 para bytes wire v2 y
**400 antes del worker** para `{"path":…}`.

Con esto el flujo UI cubre la paridad en §4.5/4.6; la instalación desde el panel queda resuelta.

---

## 2. Revisión de regresiones y bypasses (config/policy/packs/store/daemon)

Además del P1 se revisaron todas las unidades del v6.1 y su trama común, con lectura estática y corrida
de focused tests. Resultados por claim del v6.1 (idénticos a la matriz previa tras el FIX):

| Claim | Ref | Dictamen |
|---|---|---|
| `ConfigView` sin `admin_token`; PATCH vía `PatchField` | `api.rs:466-580` | PASS |
| Revalidación exposición == `check_listen_security` antes de persistir | `api.rs:590-626` == `proxy.rs:135-151` | PASS |
| Persistencia transaccional (validar→YAML→publicar) | `api.rs:660-667,688-739,812-865` | PASS |
| `DetectionPolicy` seeded, precedencia `flag>cat>rule`, YAML | `detection_policy.rs:129-136,235-251` | PASS |
| Hot-reload engine dataplane + convivencia con packs | `api.rs:1019-1053`, `daemon.rs:676-695` | PASS |
| Trust root explícito; boot Free cero packs | `updater.rs:78-140,264-270`; `daemon.rs:341-354` | PASS |
| Gate Pro boot + rollback local + worker | `daemon.rs:659-664,416-473,706-707` | PASS |
| Wire v2 por bytes; LegacyPathRequest 400; CLI por bytes + canonicalización local | `wire.rs:173-219`, `cli_pack.rs:268-299` | PASS |
| Store: no-admisión post-cierre, timeout único, drenaje, honestidad rejected/dropped | `store.rs:375-424,488-550` | PASS |
| Graceful: `spawn_managed_proxy` + flush/close + pid/endpoint cleanup | `proxy.rs:175-258`; `daemon.rs:497-552` | PASS |
| CSP sin `unsafe-inline`, sha256 del mismo asset | `api.rs:1240-1460` | PASS |
| Determinismo precision/recall | sha256 `969e8490…` reproducido (ver §5) | PASS |

No se halló ninguno nuevo bypass: el `parse_body` rechaza vacío/no-UTF-8/malformed/un­supported­version/demasiado
grande; el daemon nunca acepta una ruta del cliente (el CLI + UI transportan bytes); el worker instala solo
después de verificar firma contra trust-root y gate Pro; el store no admite eventos tras iniciar cierre (test `close_stops_writer…`).

---

## 3. P2 residual (no bloqueantes; fuera del MVP)

- **P2-A (nuevo) · contrato estricto del wire y `deny_unknown_fields`.** `PackInstallRequest` (definido en `wire.rs:114-124`) no declara `#[serde(deny_unknown_fields)]`, así que `parse_body` tolera claves accidentales (incluido `"path"`) cuando `pack` está presente (solo lo rechaza si `pack` falta → `LegacyPathRequest`). No hay impacto de seguridad (el daemon jamás abre la ruta) pero el contrato "rechaza la forma legada" es menos estricto de lo declarado.
- **P2-2 (heredado, sin fix) · `endpoint.json` stale.** El CLI degrada ante descriptor corrupto pero no comprueba PID vivo; documentado como fuera de alcance.
- **P2-3 (heredado, mitigado por test) · relación cota envelope.** La invariante `2·MAX_PACK_BYTES+1024 ≤ MAX_PACK_BODY_BYTES` ahora está vigilada por `control_plane_max_bytes_is_1_mibe` (`api.rs:1690-1698`); con escape de `"`/`\` del pack el body enviado puede superar 1 MiB y el server responde 413/`TooLarge` (fail-safe, sin instalación). Nota de honestidad, no bypass.
- **P2-4 (heredado) · opacidad del 400.** La UI muestra `body.error` ("envía los bytes del pack…") solo si el daemon devuelve error; ya no ocurre en el flujo normal (sin wire v1 desde la UI).
- **P2-5 (nuevo, hardening) · `metadata.name`/`version` → filename.** `updater.rs:182-184,456-457` arman `pack_{name}-v{version}.json` sin validar separadores de ruta/guiones en el metadata. Requiere pack firmado por la clave raíz (dominio del operador), así que no es vía de ataque externo; añadir un charset definido al escribir sería más robusto.

---

## 4. Límites honestos de `MAX_PACK_BODY_BYTES`

El cambio sí mantiene límites honestos y compartidos:
- `wire.rs:39` `MAX_PACK_BODY_BYTES = 1 MiB`; `api.rs:101` `CONTROL_PLANE_MAX_BYTES = MAX_PACK_BODY_BYTES`
  (colector `Limited::new(…,1 MiB)` → 413) ; `parse_body` body ≤ 1 MiB + `pack.len()` ≤ `MAX_PACK_BYTES`
  (`wire.rs:179-209`); CLI chequia `fs::metadata.len() ≤ MAX_PACK_BYTES` antes de leer.
- El dashboard hard-codea `523776` cliente, acoplado por test del contrato; si `wire::MAX_PACK_BYTES`
  cambiara, la suite falla.
- El envelope: `2·MAX_PACK_BYTES+1024 = 1 MiB` exactamente (límite justo, no estallido: cualquier
  inflado por escape da 400/413, nunca instalación).

**Addenda de evidence:** el FAIL histórico se conserva: `evidence/review7/opencode-findings.md` mantiene su
dictamen FAIL y su addendum marcado como posterior que "no reescribe este dictamen histórico"; `GAUNTLET_V61_CONFIG_B.md`
conserva la corrida original de 485 y las cifras de 532/533 como historia, y la cifra final de 534 se atribuye
explícitamente al re-fix. Ningún evidence anterior fue modificado.

---

## 5. Comandos ejecutados (evidencia)

```
cargo build --workspace                                      → OK
cargo test -p cerberus-packs --lib wire                      → 8 passed; 0 failed
cargo test -p cerberus-proxy --lib dashboard_html_has_no_inline_event_handlers → 1 passed; 0 failed
cargo test -p cerberus-proxy --lib                            → 117 passed; 0 failed
cargo test -p cerberus-proxy --test smoke_harness pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path → 1 passed; 0 failed
cargo test -p cerberus-proxy --test smoke_harness             → 38 passed; 0 failed (incl. hot_reload, policy…, config_get_then_put…)
cargo test -p cerberus-packs --lib                            → 59 passed; 0 failed
cargo test -p cerberus-store --lib                            → 22 passed; 0 failed
cargo test -p cerberus --test pack_cli_via_api                → 4 passed; 0 failed
cargo test -p cerberus                                        → 35+2+3+4 passed; 0 failed
cargo test --workspace                                        → 534 passed; 0 failed (debug)
cargo test --release --workspace --all-targets                → 534 passed; 0 failed (release) — repetido y estable
cargo fmt --all -- --check                                     → exit 0; sin diff
cargo clippy --workspace --all-targets -- -D warnings          → Finished; No issues found
git diff --check                                               → exit 0
python3 tools/simulate.py                                      → 29 PASS / 0 FAIL (release; transcript evidence/sim/sim-run-20260821-205522.log)
cargo test --release -p cerberus-engine --test precision_recall... → 6 passed; sha256 969e8490… (idéntico a las dos corridas previas)
```

Suma del workspace (24 bins): `6+35+2+3+4+1+175+15+6+0+6+7+5+59+117+38+22+3+0+4+7+11+8 = 534` en ambos perfiles.
Flakes observados: 0. No se hicieron commits.

---

## 6. Conclusión

El P1-1 (dashboard→wire v2 incompatible que impedía instalar packs desde la UI) está **reparado y revalidado en este
recheck**: el panel lee bytes reales (`type=file`), aplica el límite compartido, construye exactamente
`{wire_version:2,pack}`, no transporta `path`/`origin_name`, maneja errores accionables, se autentifica
con el header y la CSP sigue sin `unsafe-inline`. Con **0 P0 / 0 P1** el veredicto es **PASS**
conforme al gate 8B.1 del Gauntlet, con los P2 listados en §3. Las unidades previas
(config-api, policy, packs/wire, store, daemon graceful, CSP) no muestran regresión al ejecutarse
todas las suites sobre el estado CURRENT.