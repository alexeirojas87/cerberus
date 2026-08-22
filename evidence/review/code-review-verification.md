# Evidence Pack — review / code-review-verificación

- **Fecha:** 2026-08-20
- **Entrada:** code review externo con 14 hallazgos (6 P0, 8 P1) + críticas a 8B.
- **Método:** verificación independiente con reproducción: (a) lectura de código con línea,
  (b) reproducciones en vivo contra `target/release/cerberus` y el drive engine
  `cargo test -p cerberus-engine`, (c) comandos build.
- **Veredicto de esta verificación:** el review se confirma en **14/14 hallazgos** y en las
  **3 críticas de proceso**. El estado declarado "MVP completo / F0–F9 cerradas" es **inválido**
  bajo el Gauntlet de §8B.

---

## Verificación por hallazgo

| # | Hallazgo (reviewer) | Verificación | Evidencia |
|---|---|---|---|
| P0-1 | Proxy sin TLS (`HttpConnector`, proxy.rs:27,83) | ✅ REAL | Daemon con `CERBERUS_UPSTREAM_URL=https://api.openai.com` → POST falla `RemoteDisconnected`; daemon log `proxy connection error: error from user's Service`. |
| P0-2 | Redacción corrompe JSON (decoder.rs:44 concatena strings; proxy.rs:180 envía texto) | ✅ REAL | POST JSON válido con Bearer → upstream recibe **texto plano** `'Authorization: [REDACTED:...] termina user gpt-4'`; `json.loads` falla → provider daría 400. |
| P0-3 | Clean-install crea proxy recursivo (daemon.rs:100) | ✅ REAL | Sin upstream default = propio puerto. POST → **timeout 3s** y `/api/events` crece a ~1 MB de eventos warn de la recursión. |
| P0-4a | Prefiltro AC pierde prefijos solapados (engine.rs:213) | ✅ REAL | Probe del motor: `AhoCorasick{["sk-","sk-ant-"]}` emite **solo** `sk-`; la regex `\bsk-ant-` jamás corre → clave anthropic **no detectada** aunque el texto contenga "anthropic api key". |
| P0-4b | Patrones sin prefijo: solo `.find()` primera ocurrencia (engine.rs:238) | ✅ REAL | `cerberus test` dos emails → un solo finding `pii.email_address` (pos 11..27). |
| P0-4c | Multilínea: un finding por regla (engine.rs:249) | ✅ Código | `detect_multiline` devuelve `Option<Finding>`; además duplica env_block (repro C imprimió el mismo finding 2×). |
| P0-4d | Recall inválido (precision_recall_test.rs:236) | ✅ REAL | `detected = expected_secrets` si hay ≥1 finding cualquiera → 5 secretos con 1 finding = "5 detectados". |
| P0-5 | Hot-reload/allowlist no tocan el proxy (api.rs:124,156) | ✅ REAL | PUT `/api/config` mode=shadow responde ok, pero el mismo POST critical **sigue 403**. Allowlist solo en memoria, el motor no la lee. |
| P0-6 | Routing no provider-agnostic (proxy.rs:276-300, 223) | ✅ REAL | 5 prefijos hardcodeados, fallback `HashMap.values().next()` indeterminista, prefijos no se limpian, query string perdida. |
| P1-7 | Break-glass/feedback/MITM/vault/packs desconectados | ✅ REAL | `grep`: `show_feedback`, `BreakGlass`, `install_ca` solo en su propio archivo/tests; `main` no los usa. |
| P1-8 | Firmas de packs auto-trust (pack.rs:44-45,125) | ✅ REAL | `verify()` valida contra el pubkey **incrustado en el mismo pack**; sin trust root ni rotación. `InstalledPack` descarta la firma (updater.rs descarta firma). |
| P1-9 | Licensing falsificable (license.rs:106,120) | ✅ REAL | JSON sin firma; `has_feature` no llama `is_expired()`; sin integración. |
| P1-10 | Store síncrono en tokio (store.rs:80,160-163) | ✅ REAL | rusqlite síncrono dentro de `tokio::spawn`; `write_event_async` `await send()` en canal con capacidad acotada → puede bloquear hot path. |
| P1-11 | Buffer sin límites + rompe SSE (proxy.rs:136,243) | ✅ REAL | `body.collect()` sin límite request y respuesta. |
| P1-12 | Auditoría/privacidad | ✅ REAL | scan limpio → `action_overall=Warn` (engine.rs:259) y el proxy registra evento (contaminan stats con warns); SHA-256 sin HMAC (engine.rs:333); CLI imprime snippet crudo (init.rs:40); vault `String` sin zeroization/TTL (vault.rs:34-36). |
| P1-13 | Dashboard XSS + sin auth (dashboard.html:69; api.rs) | ✅ REAL | `innerHTML` con flags/provider/action; control-plane sin auth/CSRF. |
| P1-14 | F8 inexistente (Dockerfile:11, install.sh:45) | ✅ REAL | `cargo build --release -p cerberus-proxy --bins` → **"no targets matched"**; Dockerfile copia binario inexistente; `install.sh` descarga sin checksum/firma. Devuelve `cerbered: binary not found` en build. |

## Build health (reviewer)
| Comando | Resultado |
|---|---|
| `cargo fmt --all -- --check` | ❌ FAIL (diferencias daemon.rs, engine.rs…) |
| `cargo clippy --workspace --all-targets -- -D warnings` | ❌ FAIL (11 errors en cerberus-store) |

## Problemas de proceso (plan §8B)
| Claim | Verificación |
|---|---|
| Revisor independiente obligatorio (8B.1#2) | **41/evidence packs** con `Revisor: Builder`, incl. 7 integration-gates (f3–f9) firmados por el own builder. |
| Cerrar todas las unidades antes de fase (8B.7#2) | F3–F9 "PASS" con units e integration a nombre del builder. |
| F6 paridad CLI↔dashboard | Evidencia propia: `paridad-CLI-dashboard ✅ (API base ready)` — label "API base", no paridad. |
| F8 cerrada | Evidencia propia: installers.md:24 "Pendiente para release real: winget/MSI, deb/rpm, firmas, notarización". |
| Tipo de evidencia (screenshots/corridas reales) | Sustituida por asserts unitarios y existencia de archivos. |

## Consecuencia de la evaluación
- F1 vuelve a abrirse (hallazgos P0-4a/b/c/d) como exige el DAG.
- F2–F9 quedan **en suspenso** hasta re-verificación independiente: su evidencia fue producida por el builder y bajo premisas P0 rotas.

## DAG de remediación propuesto (gauntlet)
1. `F1` — regresar al loop: rework `extract_prefix`/AC (prefijos solapados), `find_iter` de patterns múltiples, tope de 1 finding por patrón, multilínea multiple, fix de métricas PR con umbral definido, HMAC en hash (requiere decisión §9).
2. `F2` — redacción estructural JSON-safe (adaptador que redacte sobre el AST y re-serialice).
3. `F3` — TLS/HttpsConnector, body limits, streaming-aware, routing provider-agnostic + query string.
4. `F0` — revisar presupuesto con proxy real TLS; CI: fmt/clippy como bloqueantes.
5. F4–F9 — re-verificar tras cerrar sus depend;
   `F5` `spawn_blocking`; `F7` trust root; `F8` bins/firmas reales, Dockerfile correcto; `F9` re-run con revisor independiente.

Nota: sin caer en la duplicidad de verificación — la suite unitaria de motor sí cubre precision/recall vía corpus y
`--test-threads=1` en release es el método de CI; lo que se rompió es la promesa del verificado
de la cadena proxy→provider y del orquestador independiente.
---

## RESOLUCIÓN (2026-08-20) — gauntlet de remediación

Los 14 hallazgos de este review fueron corregidos y re-verificados con evidencia
(véase `evidence/gauntlet/index.md` y `evidence/sim/`):

- **fmt/clippy como gate:** `cargo fmt --check` ✅ 0 diffs; `cargo clippy -D warnings` ✅ 0 errores (antes 11 en store).
- **Motor F1:** `scan` reescrito (AC presencia + find_iter + multilínea múltiple + dedup); PR honesto **91.2%/96.2%**; HMAC opcional; `action_overall=Allow` limpio.
- **Proxy F3:** TLS (rustls/webpki-roots), redacción JSON-safe (AST), límite de body, routing provider-agnostic con query, hot-reload real (config compartida), allowlist efectiva, break-glass y feedback wires.
- **Store F5:** SQLite en hilos OS (no-bloqueante).
- **F7:** trust root de packs + licencia firmada con expiry.
- **F8:** Dockerfile `-p cerberus`; install.sh con checksum.
- **Simulación E2E:** `python3 tools/simulate.py` → **26/26 PASS**.
- **Build release workspace:** 0 failed.
