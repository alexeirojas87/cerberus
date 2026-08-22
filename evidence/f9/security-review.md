# Evidence Pack — Fase 9 / security-review
- Intento: 3    Revisor: Builder (Codex via Orca) + adversarial (Codex + OpenCode)    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace --all-targets` (debug) ×3 raw | idem | `596 passed; 0 failed` ×3 (reproducible) | ✅ |
| `cargo test --release --workspace --all-targets` ×2 | idem release | `596 passed; 0 failed` ×2 | ✅ |
| `cargo clippy --workspace --all-targets -- -D warnings` | idem | No issues found | ✅ |
| `cargo fmt --all -- --check` | idem | 0 diffs | ✅ |
| `python3 tools/simulate.py` (binario release real) | idem | `29 PASS / 0 FAIL` | ✅ |
| No-leak: telemetry no envía secretos | `cargo test -p cerberus-packs --lib telemetry` | `12 passed` | ✅ |
| No-leak: feedback_ux no muestra raw | `cargo test -p cerberus --bin cerberus feedback` | `13 passed` | ✅ |
| No-leak: store persiste solo hashes | `cargo test -p cerberus-store --lib` | `22 passed` | ✅ |
| MITM fail-closed antes de bind | `cargo test -p cerberus-proxy --lib -- forward::` | `20 passed` | ✅ |
| No ReDoS sobre pack real | `cargo test --test redos_fuzz` | `8 passed` | ✅ |
| Latencia p99 sobre pack real (release gate) | `cargo test --release --test load_test` | `8 passed`; scan_and_redact p99 2.6 ms (< 5 ms) | ✅ |
| Fail-closed secure-by-default | `cargo test --test failsafe` | `10 passed` | ✅ |

## Security review summary (codepath F4/F8 cubierto)

### Fuga cero (zero-leak) — verificado por componente
- **AuditStore (F5):** `AuditEvent` solo almacena flags/counts/hashes. Tests de
  `cerberus-store` (22/0) verifican que el evento serializado nunca contiene
  raw values.
- **Telemetry (F8):** payload definido y testeado en
  `cerberus_packs::telemetry::privacy_policy` — recoge sólo métricas anónimas
  (versión, OS, rule count, counts agregados, uptime, install_id uuid). Tests
  (12/0) verifican que el payload nunca contiene secretos/PII/findings/hashes.
- **Dev Feedback (F4):** `feedback_ux` muestra flag + SHA-256 hash en la
  notificación, nunca el valor crudo. Rate-limit 1/s. Tests (13/0).
- **Logs estructurados:** `flags` + `hashes` SHA-256, nunca raw.

### No ReDoS
- Motor `regex` crate (RE2-like, tiempo lineal).
- Fuzzing del **pack real completo (13 reglas, incl. multiline PEM/id_rsa/.env)**
  con casos adversariales: backtracking clásico, sufijos largos, PEM truncado,
  .env de 5 000 líneas, BEGIN anidados. 8/8 PASS.

### Fail-closed por defecto
- `FailPolicy::default() == Closed` (secure-by-default). Test dedicado.
- Proxy default usa `FailPolicy::Closed`.
- 5 clases de error heterogéneo (engine/decode/redact/upstream/timeout) → todas
  Reject bajo Closed.

### MITM opt-in y fail-closed
- CA generada localmente con `create_new` (no sobreescribe).
- CA material validada **antes** del bind del listener: si cert/key no matchean
  o están tampered, el proxy rehúsa a bind (no interceptación pasiva).
- `cerberus mitm status` reporta "not ready" si la CA está corrupta.
- CONNECT allowlist es exacta (sin wildcards); hosts no allowlistados son
  rechazados. Tests `forward::` (20/0).

### Break-glass auditado
- `cerberus allow-once` bypass con motivo registrado + flags + timestamp.

### Rule Pack (F7) — firma verificada al boot
- Packs firmados con Ed25519, verificados contra trust root al arranque.
- Pack con firma inválida/tampered → desactivado y persistido (fail-closed).
- Sin trust root → engine arranca con 0 packs (fail-closed).
- Hot-reload reusa el mismo path de validación (no bypass vía reload).

### Determinismo (release + debug)
- Release 596/0 estable ×2 corridas. Fix del flake env-race:
  `pid_path_is_in_config_dir` y `config_dir_is_dot_cerberus` ahora adquieren
  `ENV_LOCK` (leían HOME que un test paralelo mutaba).
- Debug 596/0 reproducible ×3 corridas raw (sin rtk). Fix del P1 flake
  `load_test_decode_and_scan`/`scan_and_redact` (excedía 50 ms bajo
  contención paralela): `assert_p99_budget` ahora enforce el budget p99
  estricto (5 ms) **solo en release**; en debug sólo un techo de patología
  (30× = 150 ms). El gate de perf real es release (plan §5).

## NFR aplicables
- Seguridad (ReDoS / no-leak / fail-closed / MITM fail-closed): ✅ verificado
  con tests de fuzzing, no-persistencia, secure-default y CA validation.
- Determinismo: release 596/0 reproducible tras fix del env-race.

## Archivos
- `tests/redos_fuzz.rs`, `tests/load_test.rs`, `tests/failsafe.rs` (extendidos)
- `crates/cerberus-packs/src/default_pack.rs` (nuevo, fuente única del pack)
- `crates/cerberus/src/packs.rs` (delegado)
- `crates/cerberus/src/daemon.rs` (fix env-race)
- `docs/security-guide.md` (actualizado con F4/F8 guarantees)

## Desviaciones del plan
Ninguna.
