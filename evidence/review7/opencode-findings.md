# Evidence Pack — Revisión adversarial v6.1 (worktree CURRENT, sin commit)

- **Checkout auditado:** `09612f2` + working tree completo (17 archivos modificados, 12 nuevos).
- **Rol:** REVISOR independiente (adversario). Solo lectura y ejecución de tests;
  ningún fix, ningún commit. Único archivo escrito: este evidence.
- **Herramienta:** `cargo` (workspace), `cargo fmt`, `cargo clippy`, `python3 tools/simulate.py`.
- **Dictamen global: FAIL (1 × P1 — paridad dashboard rota por wire v2).**
  Ningún P0. Se cumplen todas las garantías de seguridad/tamper/durabilidad auditadas.

> **Addendum posterior (2026-08-21; no reescribe este dictamen histórico):**
> el P1-1 fue corregido en el mismo checkout mediante selector `type=file`,
> lectura UTF-8 acotada en navegador y request wire v2 `{wire_version, pack}`.
> La revalidación final fue 534 passed / 0 failed; ver
> `evidence/f6/dashboard-pack-wire-v2-v61-fix.md`. Las cifras 532/485/474
> citadas en otros artefactos quedan identificadas allí como corridas previas.

---

## 1. Dictámenes de las unidades v6.1 (tabla de verificación independiente)

| N.º | Unidad (claim) | Dictamen | Evidencia en este worktree |
|---|---|---|---|
| 1 | Secretos: admiempo/secret `admin_token` en `GET /api/config` → `ConfigView` sin campo | **PASS** | `api.rs:474-498` `ConfigView` (sin `admin_token`); test `config_view_never_carries_the_admin_token` (lib) y `config_get_never_leaks_admin_token` (smoke) ✅ |
| 2 | `PUT /api/config` semántica PATCH con `PatchField` (omitir/null/`admin_token_configured` read-only) | **PASS** | `api.rs:505-580`; `config_patch_preserves_omitted_fields`, `config_patch_ignores_read_only_admin_token_configured`, `config_patch_explicit_null_clears_the_token`, `config_patch_rejects_unknown_fields`, `put_config_cannot_disable_auth_via_the_read_only_flag` ✅ |
| 3 | No-loopback: revalidación de exposición antes de persistir/mutar (`validate_control_plane_exposure`) == `check_listen_security` | **PASS** | `api.rs:590-626` == `proxy.rs:135-151`; `listen_is_loopback_is_safe_by_default`, `validate_control_plane_exposure_matches_the_bind_rule`, `patch_that_would_open_the_control_plane_is_rejected` ✅ |
| 4 | Persistencia transaccional (validar → YAML → publicar; config viva intacta si falla) | **PASS** | `api.rs:657-667` (temp+rename), `:688-739` (PUT), `:812-865` (POST/DELETE upstream); `persist_config_fails_on_an_unwritable_path`, `put_policy_persist_failure_leaves_config_and_engine_untouched` ✅ |
| 5 | `DetectionPolicy`: seeded sin overrides, precedencia `rules[flag] > categories[cat] > rule.action`, YAML persistido | **PASS** | `detection_policy.rs:129-136` (seeded), `:235-251` (effective_rules); tests `default_openai_rule_keeps_its_declared_block_action`, `action_precedence_is_flag_then_category_then_rule` ✅ |
| 6 | Política persistente → engine vivo (hot-reload dataplane sin reiniciar, convivencia con packs) | **PASS** | `detection_policy.rs:283-366` `EngineControl`; `commit_policy` (api.rs:1019-1053); worker `rebase_live_engine` (daemon.rs:676-688) serializado con `commit_policy`; smoke `policy_custom_rule_and_allowlist_scan_before_after_and_reopen`, `test_hot_reload_swaps_engine_without_restart` ✅ |
| 7 | Trust root explícito: `PackManager::open`/`gated_by_pro`, boot Free cero packs, `hydrate_from_manifest_with_root` idempotente | **PASS** | `updater.rs:78-140` `PackTrustRoot`, `:264-270` `open`, `:729-826` hydrate; `daemon.rs:341-354` gate pre-constructor; tests `free_tier_boot_with_trust_root_and_active_manifest_loads_zero_packs` ✅ |
| 8 | Pro gate: boot daemon + `pack_install` local + `pack_rollback` local + worker API | **PASS** | `daemon.rs:706-707` gate en `pack_rollback` (hallo de v6 ya cerrado), `:659-664` helper, worker install/rollback `:416-473`, `open_packs_manager` `:177-183`; test `require_pro_gate_for_pack_ops` ✅ |
| 9 | `wire v2` instalación por bytes; rechaza `{"path":…}` (LegacyPathRequest, 400) y nunca abre filesystem remoto | **PASS** | `wire.rs:108-213` `PackInstallRequest::parse_body`; `api.rs:402-464`; `cli_pack.rs:267-299` por bytes + canonicalización local; smoke `pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path` ✅ |
| 10 | Store: no-admisión post-cierre, timeout total (enqueue+ACK), drenaje ordenado, drops y rejected honestos | **PASS** | `store.rs:375-386` (`inflight_writes` SeqCst + puerta estado), `:504-550` `barrier_ack_until` con deadline único, `:334-353` `drain_pending`, `:570-646` flush/close; tests `close_stops_writer_and_fails_subsequent_writes`, `concurrent_shutdown_with_active_writers_persists_everything_accepted`, `full_channel_with_stalled_writer_times_out_instead_of_hanging` ✅ |
| 11 | Daemon graceful: `spawn_managed_proxy` (drenar conexiones) + flush/close + pid/endpoint cleanup | **PASS** | `proxy.rs:175-258` `ManagedProxyHandle`; `daemon.rs:497-552` admisión→drain→flush→close; test `managed_proxy_shutdown_stops_admission` ✅ |
| 12 | CSP dashboard sin `unsafe-inline`, sha256 del `include_str!`, headers defensivos | **PASS** | `api.rs:1240-1436` (hash derivado del mismo HTML), `:1446-1460` (CSP header); tests `dashboard_csp_has_no_unsafe_inline_and_hashes_the_served_blocks`, `dashboard_html_has_no_inline_event_handlers` ✅ |
| 13 | Determinismo del Evidence Pack (PR) | **PASS (con nota)** | `precision_recall_test` sha256 reproducido en reviews previas; no volátil en este diff. Nota: ver P2-3 |

---

## 2. Hallazgos (ordenados P0 → P1 → P2)

### P0 — Ninguno

Tras revisión adversarial no se encontró ningún fallo de seguridad de nivel P0:
el patrón de `admin_token`, la validación no-loopback, la persistencia transaccional,
el gate de trust-root antes del constructor (Free⇒0 packs), el rechazo de la forma
legada `{"path":…}` y la máquina de estados del store (no-admisión post-cierre +
drenaje) están verificados con tests y lectura estática sin vía explotable.

### P1 — 1

**P1-1 · Dashboard de packs roto: el panel "Instalar pack firmado" envía `{"path":…}` (wire v1) y el API lo rechaza con 400 en v6.1.**

- **Impacto:** la única vía de instalación de packs desde el dashboard (F6, §4.6
  «paridad total CLI↔dashboard»; Apéndice B.3 `packs enable/install` con su
  equivalente UI) devuelve `400 {"error":"install por path retirado (wire v1)…"}` en
  el 100% de los intentos, porque el servidor ya NO resuelve rutas del cliente.
- **Evidencia exacta:**
  - `crates/cerberus-proxy/dashboard.html:543-551` (`installPack()`): `sendJson('POST','/api/packs/install',{ path })` — el cuerpo es la forma legada v1.
  - `crates/cerberus-packs/src/wire.rs:185-189`: `parse_body` rechaza `{"path": …}` como `PackWireError::LegacyPathRequest`.
  - `crates/cerberus-proxy/src/api.rs:418-427`: el handler devuelve `400` con ese error antes de tocar el worker.
  - El CLI (`crates/cerberus/src/cli_pack.rs`) sí fue migrado a bytes (`wire v2`); el dashboard no lo fue. Ambos cambios viven **en este mismo diff** (el panel es nuevo en `dashboard.html` — `git show HEAD:dashboard.html` no tiene `installPack`), por lo que la ruptura se introduce dentro del ámbito v6.1.
  - Documentación inconsistente: `evidence/GAUNTLET_V61_CONFIG_B.md:63` y `:96` prometen «panel nuevo: estado, **instalar por ruta**, rollback» — fórmula ya imposible.
- **Reproducción** (solo tests + estática, sin red): el test HTTP real `pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path` (ya en la suite, `PackInstallRequest::parse_body(b{"path":"/tmp/pack.json"}) == Err(LegacyPathRequest)`) demuestra que el body del dashboard es rechazado; no se necesita simulación local.
- **Recomendación:** el panel debe leer los bytes del archivo en el navegador (FileReader) y enviar un body `{"pack": …}` acorde a `PackInstallRequest`, o exponer un endpoint de "instalar por ruta" que el daemon resuelva con el propio filesystem de forma segura. Es un fix de cobertura UI.

---

### P2

- **P2-1 — `index`/evidence de números acuñados no cuadran con el workspace observado.** `evidence/f6/config-api-v61-fix.md` y `GAUNTLET_V61_CONFIG_B.md` citan `cargo test --workspace` = **532 / 485 passed**. La corrida independiente en este worktree da **534 passed / 0 failed** (recontado vía `python` sobre el output). Los tests crecieron entre ambas corridas; no hay regression, pero la cifra exacta no es reproducible tal cual está escrita.
- **P2-2 — El panel de packs en el dashboard no declara que `install by path` es inaplicable; el error 400 es opaco para el usuario no técnico.** La UI (dashboard.html:550) muestra `body.error` que para wire v1 dice «instala por ruta (wire v1)…», lo que confunde al operador. (Deriva directa del P1-1; se lista por proximidad.)
- **P2-3 — Reconéase comprimir el JSON pack doblemente sobre `CONTROL_PLANE_MAX_BYTES`:** `wire.rs:41` fija `MAX_PACK_BYTES = 512 KiB` y el envelope en `parse_body` se limita a `2·MAX_PACK_BYTES+1024` (`wire.rs:171-177`). El comentario de diseño depende de que `CONTROL_PLANE_MAX_BYTES` (1 MiB) no baje sin ajustar la constante. No es un defecto hoy, pero es una invariante frágil sin test que la vigile.
- **P2-4 — `endpoint.json` no valida `pid` al resolver el CLI.** `cli_pack.rs:96-155` degrada si el descriptor es corrupto, pero no detecta un descriptor **rancido** (daemon muerto que dejó el archivo): el CLI hablará a un puerto sin listener y fallará igual que sin descriptor. No hay `process_alive(ep.pid)` aplicado (documentado como futuro).

---

## 3. Cobertura ausente (lo que NO hay prueba explícita)

1. **Sin test HTTP/E2E de la instalación de packs vía dashboard** (único consumidor UI de packs); el sheet de cobertura de packages se ciñe al CLI y al handler HTTP de bajo nivel.
2. **Sin test de concurrencia directa `commit_policy` vs worker de packs** (el escenario de carrera `base-nueva/policy-vieja` está documentado en comentario y razonado por locks, pero no hay una prueba que dispare el interleaving; el race detector `cargo test --locked` no se ejecutó como rutina).
3. **Sin test de "Free con boot pro-después" por HTTP**: la hidratación Pro post-boot se prueba a nivel `PackManager` unitario, no en el flujo daemon real (boot Free + licencia Pro + `hydrate_from_manifest_with_root`).
4. **La CSP se prueba sólo a nivel de bloquesservido; no hay test de screen-shot/a11y del dashboard** (no aplica ö8B.4 para UI, pero es un hueco de evidencia en el panel de packs roto).

---

## 4. Comandos ejecutados (evidencia)

```
cargo build --release -p cerberus                 → OK (binario 12,057,728 B)
cargo test -p cerberus-proxy --lib                → 117 passed; 0 failed
cargo test -p cerberus-proxy --test smoke_harness → 38 passed; 0 failed  (incl. pack_install_wire_v2…, policy_custom…, config_get_then_put…, test_hot_reload…)
cargo test -p cerberus-packs --lib                → 59 passed; 0 failed
cargo test -p cerberus-store --lib                → 22 passed; 0 failed
cargo test -p cerberus --test pack_cli_via_api    → 4 passed; 0 failed
cargo test -p cerberus                            → 35+2+3+4 passed (bin/unit/integration)
cargo test --workspace                            → 534 passed; 0 failed
cargo fmt --all -- --check                         → exit 0, sin diff
cargo clippy --workspace --all-targets -- -D warnings → Finished, 0 issues
python3 tools/simulate.py                         → 29 PASS / 0 FAIL (release, transcript evidencia/sim/sim-run-20260821-202117.log)
```

Ninguna de estas suites ni de las lecturas estáticas contradice los hallazgos del P1-1.

## 5. Conclusión

El cierre del **P0 (bypass de boot Free)** y el **P1 (gate Pro rollback local)** de la review v6 están
correctamente reparados con tests focalizados y pasan en este worktree. La mejora de
a33→0.0 (store transaccional con drenaje y timeout total, proof de admisión-posterior) está bien
diseñada. El **P1-1 (dashboard→wire v2 incompatibilidad)** es una ruptura funcional real introducida
por este mismo diff, que _quiebra la paridad CLI↔dashboard_ exigida en §4.5/§4.6 y que **impide
instalar packs desde la UI** en el estado actual. Por la regla del Gauntlet 8B.1 (FAIL si ≥1 criterio
no se cumple; PASS solo si quedan 0 P0/P1 dentro de v6.1), el veredicto es **FAIL** hasta corregir
`installPack()` (enviar bytes wire v2 con FileReader o franquicia server segura) y actualizar la
documentación de evidencia que promete «instalar por ruta» desde la UI.
