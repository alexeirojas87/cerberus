# Audit Independiente — 10 hallazgos del code review (v4)

- reviewer: findings-review-02
- worktree: /var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/review-findings
- commit auditado: 2b5ed4c (detached HEAD)
- alcance: verificación con evidencia file:line + tests puntuales. Sin modificación de código.
- fecha: 2026-08-21

## Verificación de tests (ejecutados puntualmente)

| Test | Salida |
|------|--------|
| `cargo test -p cerberus-engine --test precision_recall_test -- --test-threads=1 --nocapture` | `Corpus precision/recall (per-instance): recall=94.3% precision=89.2%` — `test result: ok. 6 passed; 0 failed` |
| `cargo test -p cerberus-proxy --lib` | `test result: ok. 67 passed; 0 failed` |
| `cargo test -p cerberus-proxy --test smoke_harness -- --test-threads=1` | `test result: ok. 22 passed; 0 failed` (incl. `test_admin_token_header_not_forwarded_to_upstream ... ok`, `test_bypass_data_plane_requires_admin_header_not_bearer ... ok`) |
| `cargo test -p cerberus-store --all-targets` | `test result: ok. 18 passed; 0 failed` (incl. `flush_reports_prev_insert_failure`, `flush_is_durability_barrier_for_all_pending_writes`, `close_stops_writer_and_fails_subsequent_writes`) |
| `cargo test --workspace --test load_test` (x2) | run1 `ok. 7 passed; 0 failed` · run2 `ok. 7 passed; 0 failed` (budgets por perfil: `assert_p99_budget` usa is_release para debug/release, tests/load_test.rs:29-37) |

## Dictámenes

### 1. P0 Auth default-secure — **PASS**
- `check_listen_security` en crates/cerberus-proxy/src/proxy.rs:130-146: rechaza bind no-loopback si `admin_token` es `None` o `< 24` bytes (test `non_loopback_listener_requires_strong_admin_token` proxy.rs:944).
- `spawn_proxy` evalúa `check_listen_security(&listen, &ctx)?` ANTES del bind (proxy.rs:161).
- `ADMIN_TOKEN_MIN_BYTES: usize = 24` en crates/cerberus-proxy/src/api.rs:39.
- `docker-compose.yml:16` `CERBERUS_ADMIN_TOKEN=${...:?set a strong admin token (>=24 chars)}` — compose falla si no hay token.
- Test `test_spawn_non_loopback_requires_admin_token` smoke_harness.rs:763-770 (0.0.0.0 sin token → Err) y e2e en compose.

### 2. P0 Admin token no filtrado al upstream — **PASS**
- `ADMIN_TOKEN_HEADER = "x-cerberus-admin-token"` en api.rs:32.
- Forwarding: proxy.rs:548-561 — en el loop de reenvío se omiten `host`, `BYPASS_HEADER`, `ADMIN_TOKEN_HEADER`, `SKIP_HEADERS` y tokens de Connection; el header NUNCA llega al upstream.
- Bypass: proxy.rs:371-390 — `X-Cerberus-Bypass` solo se honra si `admin_token_header_is_present(...)` (comparación `constant_time_eq`, api.rs:109-118 / 146-148); `Authorization: Bearer` se IGNORA para el data plane (test `test_bypass_data_plane_requires_admin_header_not_bearer` smoke_harness.rs:812).
- Test e2e `test_admin_token_header_not_forwarded_to_upstream` smoke_harness.rs:773-809 (asserts header automático ni valor del token llegan al echo upstream) — ejecutado OK.

### 3. P1 Dashboard con auth funcional — **PASS**
- `handle_dashboard` api.rs:330-344: inyecta `<var id="cerberus-token" value="{escape_html(t)}" hidden>` donde `expected_admin_token` está configurado; el dashboard está bajo la ruta `/api/dashboard` (api.rs:190), protegida por el gate de auth (api.rs:171-182).
- dashboard.html:56-57 `tokenFromDom()` lee el var; :70-74 `fetchJson` manda `headers['X-Cerberus-Admin-Token'] = tok`; :87-92 escape `esc()` para XSS.
- Test `dashboard_injects_token_var_only_when_configured` api.rs:436-472.

### 4. P1 Control plane bodies limitados — **PASS**
- `CONTROL_PLANE_MAX_BYTES: usize = 1 << 20` (1 MiB) api.rs:44.
- `collect_api_body` api.rs:208-218 usa `Limited::new(body, CONTROL_PLANE_MAX_BYTES)` → `LengthLimitError` → `ApiBodyError::TooLarge` → 413 `PAYLOAD_TOO_LARGE` en `handle_put_config` (api.rs:220-228). Aplica a PUT /api/config y POST /api/allowlist.
- Test `control_plane_max_bytes_is_1_mibe` api.rs:475-477.

### 5. P1 fail_policy cubre redaction — **PASS**
- `json_redact.rs`: `fallback_text` propaga el error de `apply_redaction` (:43-47); `redact_json`/`redact_value` propagan errores de leaf con `?` (:53-97); errores ya no se tragan.
- `decide_redact_result` proxy.rs:297-313: fail_policy Closed → `RedactDecision::Reject(502, "{...}redact failure...")` (sin raw secret); Open → Forward(original) con warn.
- Tests proxy.rs:970-997: `redact_failure_fail_closed_returns_502_without_raw_secret` y `redact_failure_fail_open_forwards_original` — ejecutados OK (proxy --lib).

### 6. P1 Durabilidad store — **PASS**
- `write_loop` store.rs:123-173: `last_error: Option<String>` retiene el primer INSERT fallido (:128, :144-147); el Flush ACK devuelve `Err` si `last_error` estaba pendiente (:157-163).
- `WriteMsg::Shutdown` + ack y return graceful del writer (:165-170); `close()` store.rs:241-254.
- Daemon: graceful loop Ctrl+C/SIGTERM → `store.flush_durable().await` (daemon.rs:375) + `store.close().await` (daemon.rs:379); `stop()` manda SIGTERM (daemon.rs:491-538).
- Retención: `CERBERUS_RETENTION_DAYS→retention_days_from_env` (daemon.rs:110-117, :255) → `AuditStore::open_with(path, retention)`; purge periódico cada 60s (store.rs:148-155).
- Test `flush_reports_prev_insert_failure` store.rs:518-543 — ejecutado OK.

### 7. P1 F7 conectado — **PARCIAL** (no hay hot-reload en runtime)
- Un solo engine: `build_base_engine()` daemon.rs:125-133 → `PackManager::new(packs_dir(), base_engine)` (daemon.rs:279) → `snapshot_engine(...)` (daemon.rs:302) → `ProxyContext { engine: Arc::new(engine_for_proxy), ... }` (daemon.rs:319-325). El MISMO engine del PackManager pasa al proxy.
- CLI: main.rs:72-82 `PackCmd {Install, List, Rollback}` + dispatch main.rs:161-198; gate Pro en `pack_install` daemon.rs:399-403 (`if !license.is_pro() → Err`).
- **PERO** daemon carga packs SOLO antes de arrancar: comentarios daemon.rs:276-281 y 285-291: "Hot-reload en runtime NO est soportado por `ProxyContext.engine` (inmutable): los packs se aplican en el pro-ximo arranque". `ProxyContext.engine` es `Arc<CompiledEngine>` inmutale — no hay mecanism de hot-reload de reglas puestente mientras el proxy vive. PARCIAL conforme al enunciado (solo al arranque, no runtime).

### 8. P1 PR por instancia con spans — **PASS**
- `ExpectedInstance { flag, value }` en precision_recall_test.rs (span_in :43-46 localiza el span por valor literal en el texto).
- `spans_overlap` :179-181; consumición greedy por instancia en `run_measurement` :334-485 (cada finding consume como máx. UNA instancia del MISMO flag cuyo span solapa; pasadas separadas no-entropía/entropía).
- Test `per_instance_recall_does_not_substitute_same_flag` :562-618 (recall honesto 1/2, no 2/2).
- Salida de test: `Corpus precision/recall (per-instance): recall=94.3% precision=89.2%` — gates ≥90% recall / ≥85% precision cumplidos (precision_recall_test.rs:488-522).

### 9. P2 Gate debug estable — **PASS**
- `cargo test --workspace --test load_test` ejecutado 2 veces: run1 `ok. 7 passed; 0 failed` · run2 `ok. 7 passed; 0 failed` (exit 0 ambas).
- Budgets por perfil: `assert_p99_budget` decide budget debug vs release con `cfg!(debug_assertions)` (tests/load_test.rs:29-37); perfiles cubieren 1kb/10kb/50kb/100kb + decode_and_scan + scan_and_redact + empty_engine. 0 failed en ambas corridas → gate estable no flakie.

### 10. P1 Independencia — **PASS**
- reviewer=findings-review-02; worktree aislado bajo /var/folders/.../opencode/review-findings; commit 2b5ed4c (detached HEAD, verificado `git rev-parse --short HEAD`); sin modificaciones de código (solo este archivo de evidencia).

## Resumen

| # | Punto | Dictamen | file:line clave | Verificación |
|---|-------|----------|-----------------|--------------|
| 1 | P0 Auth default-secure | PASS | proxy.rs:130-146,161; api.rs:39; docker-compose.yml:16 | no-loopback sin/`<24` token → Err; tests ok |
| 2 | P0 Admin token sin filtrar | PASS | api.rs:32; proxy.rs:548-561,371-390; api.rs:109-118 | e2e echo: header/value nunca al upstream; 22 ok |
| 3 | P1 Dashboard con auth | PASS | api.rs:330-344,190; dashboard.html:56-74 | var + header en fetch; test citado en source |
| 4 | P1 Control plane limitado | PASS | api.rs:44,208-228 | Limited 1MiB → 413; test source |
| 5 | P1 fail_policy redaction | PASS | json_redact.rs:43-97; proxy.rs:297-313 | test proxy.rs:970-997 ok |
| 6 | P1 Durabilidad store | PASS | store.rs:128,157-170,241; daemon.rs:375-379 | flush ACK condicionado; test store ok |
| 7 | P1 F7 conectado | PARCIAL | daemon.rs:279,302,319-325; main.rs:72-82; daemon.rs:399-403 | engine MISMO, CLI completo; SIN hot-reload runtime (inmutable) |
| 8 | P1 PR por instancia | PASS | precision_recall_test.rs:334-485,562-618 | salida: recall=94.3% precision=89.2% |
| 9 | P2 Gate debug estable | PASS | tests/load_test.rs:29-37 | 2/2 corridas: 7 passed; 0 failed |
| 10 | P1 Independencia | PASS | — | reviewer findings-review-02, commit 2b5ed4c, worktree aislado |

9 PASS · 1 PARCIAL (hallazgo 7: solo al arranque, no hot-reload en runtime).