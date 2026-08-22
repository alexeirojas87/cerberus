# Revisión de seguridad — verificación de los 12 puntos (v3)

Fecha: 2026-08-20. Working tree actual (ramas paralelas ya integradas). P-role:
solo verificación con evidencia; no se modificó código.

## Gate de compilación (previo)

`cargo build --workspace` → **OK, compila sin errores.** No hubo FAIL de build
que impidiera continuar.

| # | Hallazgo | Verificación realizada | file:line clave | Dictamen | Evidence |
|---|----------|------------------------|-----------------|----------|----------|
| 1 | P0 Control plane sin autenticación | `handle_api_request` aplica auth ANTES del dispatch para TODAS las rutas `/api/*`(excluye `/health`, que no pasa por `is_api_path`). Comparación `constant_time_eq` (xor+foreach, sin short-circuit). `X-Cerberus-Bypass` solo se honra con token válido o en dev-mode. Daemon inyecta `CERBERUS_ADMIN_TOKEN`; docker-compose define `CERBERUS_ADMIN_TOKEN=${...:-change-me}`. Smoke: `test_put_config_requires_admin_token` y `test_health_requires_admin_token_when_configured` pasan. | `proxy.rs:263` (dispatch), `proxy.rs:305-324` (bypass solo con token), `api.rs:93-128` (constant_time_eq/authorized/expected_admin_token), `api.rs:147-154` (guard 401), `daemon.rs:213-216`, `docker-compose.yml:14` | **PASS** | `cargo test -p cerberus-proxy --all-targets` → 58 unit + 17 smoke, 0 failed (incluye `test_put_config_requires_admin_token ... ok`, `test_health_requires_admin_token_when_configured ... ok`). Rutas dashboard/events: entran por `api.rs:156-164` (mismo guard previo). |
| 2 | P0 Licencias por trust propio del archivo | `from_file` raíz solo env `CERBERUS_LICENSE_PUBLIC_KEY` o `option_env!` embebida; `from_file_with_root` (raíz explícita); `owner_public_key_hex` solo aparece como campo/documentación, nunca como root. Test de ataque reemplazado por `license_rejects_owner_key_as_untrusted_root` que REVELA rechazo (is_err) y acepta solo con root explícito. | `license.rs:59` (embedded), `license.rs:187-202` (from_file→env/embedded; with_root), `license.rs:51`, `license.rs:412-447` (test ataque) | **PASS** | `cargo test -p cerberus-packs license` → 14/14 ok (`license_rejects_owner_key_as_untrusted_root ... ok`). Grep `owner_public_key_hex`: solo metadata/doc + test. |
| 3 | P1 fail_policy open = fail-open real | decode falla (content-type json no parseable) → `decode_failed`; Con `Closed` → 502 JSON `{"error":"cannot decode"}`; con `Open` → se instruye `final_bytes=body_bytes.to_vec()` (body ORIGINAL reenviado, línea 403) y se reenvía en `Full::new(Bytes::from(final_bytes))`. | `proxy.rs:333-341`, `proxy.rs:402-404`, `proxy.rs:484` | **PASS** | Smoke `test_fail_policy_open_forwards_non_json_body ... ok`; `test_fail_policy_closed_rejects_dead_body ... ok` (17 smoke total ok). |
| 4 | P1 Routing longest-prefix TRUE | Se ordena por longitud del `path_prefix` (desc) con desempate por nombre — `resolve_route`. Test unitario dedicado. | `proxy.rs:581-589`, `proxy.rs:754` (`routing_uses_longest_path_prefix`) | **PASS** | `routing_uses_longest_path_prefix ... ok`; `routing_strips_builtin_prefix ... ok`. |
| 5 | P1 Respuesta > límite NO corta socket | `collect_resp_body` distingue `LengthLimitError`; el handler `proxy_handler` convierte TooLarge → 502 `{"error":"response too large"}` y NO propaga → el cuerpo no corta el socket. | `proxy.rs:235-249`, `proxy.rs:520-524` | **PASS** | `test_upstream_response_too_large_is_502 ... ok` (smoke). |
| 6 | P1 Compose OpenAI routing | `CERBERUS_UPSTREAMS` JSON soportado (`serde_json::from_str`); `CERBERUS_UPSTREAM_URL` genera 3 upstreams (openai/anthropic con path_prefix, default None). `resolve_route` quita el prefijo del path antes de reenviar (`rest_path`), p.ej. `/openai/v1/...` → `base + /v1/...`. docker-compose define `CERBERUS_UPSTREAMS` con `"openai":{"url":"https://api.openai.com","path_prefix":"/openai/"...}`. | `daemon.rs:156-194`, `proxy.rs:590-604`, `proxy.rs:606-618`, `proxy.rs:464`, `docker-compose.yml:15` | **PASS** | daemon build pasa; test `config::tests::parse_yaml_with_upstreams` / `with_upstream_helper` ok; smoke shadow `provider: openai` con path `/v1/chat/completions` (sim). |
| 7 | P1 Bypass sin persistir secretos | `action_taken="bypass"`, `flags` solo `"bypass"` (literal NO), motivo → `hash_value(truncate_bypass_reason(reason))` → `bypass-hash:<sha256 hex>` en `hashed_values`; truncación a 200 bytes sin romper UTF-8. | `proxy.rs:438-449`, `proxy.rs:215-225`, `proxy.rs:444-449` | **PASS** | `test_bypass_reason_never_persisted_raw ... ok` (smoke): asserts que NO contiene el secreto raw y que contiene `bypass-hash:`. |
| 8 | P1 Store duración | `open_with(path, retention_days)` (open con retención configurable, default 90d); `flush()` = barrera de durabilidad (ACK escritor, timeout 2s); purga POR TIEMPO `>=60s` (PURGE_INTERVAL_SECS=60), no por conde; tests en `store.rs` con 0 ocurrencias de `sleep`. | `store.rs:81-88` (open_with+purge al open), `store.rs:186-198` (flush), `store.rs:17` + `store.rs:137-143` (purge ≥60s), `store.rs:116-151` | **PASS** | `grep sleep store.rs` = 0 (sync y async). Unit `flush_is_durability_barrier_for_all_pending_writes`, `open_purges_events_older_than_retention`, `open_with_zero_retention_purges_all_stale_events` corren sin sleeps; suite cerberus-store sin fallos. |
| 9 | P1 Hop-by-hop completo | `SKIP_HEADERS` incluye `te`, `trailer`, `proxy-authorization` además de la lista estándar; respuesta pasa por `filter_response_headers` (connection_tokens + lista fija `RESPONSE_HOP_BY_HOP` con te/trailer/proxy-auth*). | `proxy.rs:52-63` (SKIP_HEADERS), `proxy.rs:67-77`, `proxy.rs:199-210` (filtro resp.), `proxy.rs:534`; tests `proxy.rs:788`, `proxy.rs:815` | **PASS** | `response_hop_by_hop_headers_filtered ... ok`, `response_connection_tokens_stripped ... ok`; request-side test en la misma suite (`57 unit ok`). |
| 10 | P1 Gate release determinista | El reviewer gate (revisión g) verificó release; aquí se confirma que en cerberus-packs el único `set_var("CERBERUS_LICENSE_PUBLIC_KEY")` queda DENTRO del `test` `license_from_file_signed_with_env_root` y protegido por `ENV_LOCK` (mutex estático); fuera de guard: 0. | `license.rs:302` (ENV_LOCK), `license.rs:391`+`license.rs:403` (set_var bajo guard) | **PASS** | `cargo test --release -p cerberus-packs --all-targets -- --test-threads=16` → **37 passed, 0 failed**. |
| 11 | P2 Precision/recall por instancia | `CorpusFile.expected` es `&[(&str,usize)]` (flag,count); TP por (file,flag)=`min(found,count)`, exceso→FP (`over`), bajo→FN (`under`); entropía solapada no se cuenta 2 veces. Resultado per-instance. | `precision_recall_test.rs:41`, `precision_recall_test.rs:336-339` (tp/over/under), `precision_recall_test.rs:358-395` (entropy), `write_results:198` (`per-instance: true`) | **PASS** | `cargo test -p cerberus-engine --test precision_recall_test` → 5/5 ok; report escrito `evidence/f1/raw/precision_recall_results.txt`: línea 8 `per-instance: true`, Resto `Recall: 94.3% (33/35)` y `Precision: 89.2% (33/37)`; gates ≥90/≥85 ok. |
| 12 | P1 F7 conectado en producto | `daemon::start` crea `LicenseManager` (`load_license`) y `PackManager` en `~/.cerberus/packs`; CLI `cerberus license` definido y manejado en `main.rs`; test de integración. | `main.rs:50`+`main.rs:118-124` (subcomando), `daemon.rs:241`+`daemon.rs:259` (lic+packs), `daemon.rs:56-76` (load_license), `evidence/f7/license-daemon-wiring.md` (existe), `tests/license_cli_integration.rs` | **PASS** | `cargo test -p cerberus --all-targets` → 24 unit + 2 integración (`cli_license_activates_pro_from_signed_file`, `cli_license_falls_back_to_free_without_trust_root`), 0 failed. |

## Extra — simulador (herramienta oficial)

`python3 tools/simulate.py`:

```
RESULTADO: 29 PASS / 0 FAIL
```

Cumple el gate (>=29 PASS y 0 FAIL). La simulación arrancó daemon + proxy,
validó auth, redacción, events con `hmac:` y routing hacia `/v1/chat/completions`.
Transcript: `evidence/sim/sim-run-20260820-182206.log`.

## Dictamen FINAL

| Resultado | Cantidad |
|-----------|----------|
| PASS | 12 / 12 |
| FAIL | 0 |

Ningún hallazgo de la review v3 queda sin resolver: los 12 puntos verificados
pasan en el working tree actual (compilación + tests + sim). El workspace
compila; no hubo ningún FAIL que bloquease la verificación.