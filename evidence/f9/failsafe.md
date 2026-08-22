# Evidence Pack — Fase 9 / failsafe
- Intento: 2    Revisor: Builder (Codex via Orca)    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --test failsafe` | `cargo test --test failsafe` | `10 passed; 0 failed` | ✅ |
| `cargo test --release --test failsafe` | idem release | `10 passed; 0 failed` | ✅ |
| Fail-closed rechaza en error de engine | `fail_closed_rejects_on_engine_error` | Reject | ✅ |
| Fail-open permite en error de engine | `fail_open_allows_on_engine_error` | Allow | ✅ |
| Span inválido → error de redacción | `invalid_redaction_fail_closed` | Err (no panic) | ✅ |
| Engine vacío escanea sin error | `empty_engine_scan_succeeds` | 0 findings, Allow | ✅ |
| Pipeline scan+redact+policy | `scan_redact_policy_pipeline` | SECRET redactado | ✅ |
| **Default = Closed (secure-by-default)** (nuevo) | `fail_policy_default_is_closed_secure` | `FailPolicy::default() == Closed`; proxy default == Closed | ✅ |
| **Proxy pipeline con error simulado** (nuevo) | `proxy_pipeline_fail_closed_rejects_on_simulated_engine_error` | closed→Reject, open→Allow | ✅ |
| **Errores heterogéneos** (nuevo) | `fail_closed_rejects_on_heterogeneous_errors` (decode/redact/upstream/timeout) | todos Reject (closed) | ✅ |
| **Fail-open heterogéneo** (nuevo) | `fail_open_allows_on_heterogeneous_errors` | todos Allow (open) | ✅ |

## Casos adversariales probados
- Span inválido (end < start) → error, no panic.
- Engine vacío → no findings, sin error.
- Pipeline completo: rule → engine → scan → redact → span correcto.
- 5 tipos de error distintos (engine/decode/redact/upstream/timeout) → política
  agnóstica al mensaje; closed rechaza todo, open deja pasar todo.

## Cobertura codepath F4/F8 (referenciada, no duplicada)
- **MITM fail-closed antes de bind:** `crates/cerberus-proxy/src/forward.rs::mismatched_ca_pair_fails_closed_before_listener_bind` (verifica que CA mismatch rechaza antes del bind). `crates/cerberus/src/mitm.rs::strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime` (CA tampered → status "not ready" + daemon runtime rechaza). Estos tests viven en sus crates y se ejecutan en la suite workspace (596/0).
- **Telemetry no-secret:** `cerberus-packs` telemetry tests (12/0) — payload nunca contiene secretos/PII/findings/hashes.
- **Feedback_ux no-raw:** `cerberus` feedback tests (13/0) — notificación muestra flag+hash, nunca valor crudo.

## NFR
- **Disponibilidad:** fail-open/closed explícito, seguro por defecto (Closed),
  testeado para 5 clases de error → ✅
- **Determinismo:** release 596/0 estable tras fix del flake env-race
  (`pid_path_is_in_config_dir`/`config_dir_is_dot_cerberus` ahora toman ENV_LOCK).

## Archivos
- `tests/failsafe.rs` (extendido: +4 tests proxy-level + secure-default)
- `crates/cerberus/src/daemon.rs` (fix: 2 tests adquieren ENV_LOCK)

## Desviaciones del plan
Ninguna.
