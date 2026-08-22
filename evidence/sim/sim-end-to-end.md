# Evidence Pack — sim / ejecución end-to-end de Cerberus

- **Fecha:** 2026-08-20
- **Método:** simulación conducida con el **binario release real**
  (`target/release/cerberus`) + mock upstream HTTP (`tools/mock-server.py`), fases
  **Enforce** y **Shadow** con HOME aislado por fase. Decisions/veredicto: automatizado
  vía assertions en `tools/simulate.py`.
- **Veredicto: PASS** ✅ (26/26 assertions live) + suites unitarias en release green.

## Transcripts
- `evidence/sim/sim-run-20260820-143618.log` (26 PASS / 0 FAIL)
- Harness reproducible: `tools/simulate.py`

---

## 1. Superficie HTTP (daemon real) — Fase ENFORCE

| # | Funcionalidad | Evidencia observada |
|---|---|---|
| 1 | `GET /health` | `{"status":"ok","mode":"enforce","upstream_count":1}` |
| 2 | **Block** (regla critical) | `POST /openai/...` con `OPENAI_API_KEY=sk-...` → **HTTP 403** `{"error":"blocked","flag":"secret.openai_api_key"}`. El secreto **no** llega al upstream. |
| 3 | **Redact** (regla `action=redact`, Bearer) | 200; el mock recibe el body **transformado**: `Authorization: [REDACTED:secret.generic_bearer_token]`. El raw token **no** viaja. |
| 4 | **Warn** (PII email, `action=warn`) | 200 y el email **llega intacto** al upstream (solo se audita). |
| 5 | Pass-through limpio | 200, body limpio intacto; el mock confirma la recepción. |
| 6 | Allowlist (triage FP) | `POST /api/allowlist` → `{"status":"ok","added":"sk-EXAMPLE-do-not-flag"}` |
| 7 | Config API | `GET /api/config` → 200 con `listen`/`mode`/`upstreams`/`fail_policy`. |
| 8 | Telemetría | `GET /api/events` → 4 eventos con flags, `action_taken`, `hashed_values`; **sin** valor crudo. |
| 9 | Stats por proveedor | `GET /api/stats` → `total>0` y `by_provider` desglosado (local: redact 1, warn 2; openai: block 1) con `top_flags`. |
| 10 | Dashboard | `GET /api/dashboard` → HTML (len 4844). |
| 11 | Fuga cero | grep de raw sobre **todo el HOME** (db/logs) + daemon log → 0 apariciones. |
| 12 | CLI dry-run | `cerberus doctor` (13 reglas cargadas, RUNNING), `cerberus test` detecta secreto con keyword de contexto. |

## Fase SHADOW — §4.7

| # | Funcionalidad | Evidencia |
|---|---|---|
| 13 | Shadow deja pasar | En modo `shadow` (config), el secreto critical **NO bloquea**: 200 y el body llega **intacto con el secreto crudo** al upstream. |
| 14 | Shadow sí audita | `/api/events` registra el evento con `action_taken":"block"` y `flags:["secret.openai_api_key","secret.env_block"]` pese a haberse dejado pasar. |

---

## 2. Suites unitarias / features internas (release)

| Paquete | Resultado |
|---|---|
| `cerberus-engine` (motor) | 168 passed / 0 failed |
| `cerberus-proxy` | 53 passed / 0 failed |
| `cerberus-packs` | 29 passed / 0 failed |
| `cerberus` (CLI) | 21 passed / 0 failed |
| `cerberus-store` | 11 passed / 0 failed |

### Cobertura de features internas (engine) verificadas
- **Redacción in-place que preserva JSON**: `json_structure_preserved`, `multiple_redactions`, `redact_replaces_span`, token custom (`custom_token_template`).
- **Precedencia de acciones**: `full_precedence_chain_block_over_redact_over_warn_over_allow`, `block__precedence`, `redact_wins_over_warn_and_allow`, `overlapping_spans_most_severe_wins`.
- **Break-glass / bypass auditado**: `allow_once`, `allow_once_static_works`, `allow_passes_through`, `block_returns_error`, `enabled_with_block_removes_block`.
- **Feedback al dev**: `feedback_block_message`, `feedback_redact_message`, `feedback_warn_message`, `feedback_by_category`, `feedback_summary_line_with_findings`.
- **Bóveda reversible** (opcional): `vault_is_empty_initially`, `store_and_resolve`, `resolve_nonexistent_token`, `entry_round_trip`, `reversible_options_enabled`/`default_disabled`.
- **Entropía genérica**: `detect_high_entropy_near_keyword`, `detect_low_entropy_no_finding`, `entropy_finding_never_raw`.
- **Bloques multilínea** (PEM / id_rsa / .env): `detects_pem_rsa/dsa/ec/openssh_private_key`, `detects_id_rsa_ssh_key`, `detects_env_file_with_secrets`, `pem_block_captures_full_range`.
- **Constraints / validators**: `context_keywords_case_insensitive_mixed_case`, `allowed_examples_known_false_positive_discarded`, Luhn (`apply_iban_char`), elementos `get_validator_*`.
- **Sin fuga cruda**: tests de `hash_only`, `findings_out_of_order_sorted`, span bounds (`invalid_span_end_before_start/out_of_bounds`).

## 3. NFR (release, determinista)
| NFR | Comando | Resultado |
|---|---|---|
| Latencia del scan | `cargo test --release --package cerberus-hardening --test load_test -- --test-threads=1` | 7 passed / 0 failed (los presupuestos de p99 se validan en release aislando; en debug son más laxos) |
| Sin ReDoS | `cargo test --release ... --test redos_fuzz` | 5 passed / 0 failed |
| Fail-safe | `cargo test --release ... --test failsafe` | 6 passed / 0 failed |

---

## Casos adversariales cubiertos
- Secreto env `OPENAI_API_KEY=` **mayúsculas** (caso que rompía en pre-R0) → block OK.
- Payload con 2 halls (openai_key + env) en **shadow**: registrado y pasado.
- Redact sobre JSON anidado: estructura intacta, solo el valor sustituido.
- Búsqueda de secretos crudos en **toda** la máquina virtual HOME (db + logs) → 0 restos.

## Nota de método
La simulación usó `cerberus test "mi openai api key es sk-..."` — con keyword de contexto `openai`. Sin ese keyword la constraint descarta el hallazgo (comportamiento correcto del motor de constraints, no un fallo; es exactamente el mecanismo anti-FP).