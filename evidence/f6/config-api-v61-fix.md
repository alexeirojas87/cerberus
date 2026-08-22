# Evidence Pack — f6/config-api-v61-fix
- Intento: FIX 1    Revisor: worker `task_47c1514d5bc0`    Veredicto: PASS

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| Build del workspace | `cargo build --workspace` | `18 crates compiled`; exit 0 | ✅ |
| Categorías, overrides, reglas custom MVP y allowlist persisten y cambian el dataplane sin restart | `cargo test -p cerberus-proxy policy_custom_rule_and_allowlist_scan_before_after_and_reopen` | `1 passed; 0 failed` | ✅ |
| Scan before/after/reopen por HTTP real | mismo test focalizado | before custom `200`; tras `PUT /api/policy` `403`; allowlist viva `200`; reopen conserva allowlist `200`, otra coincidencia custom `403` | ✅ |
| Packs y custom conviven sin pérdida ni duplicado | mismo test focalizado | `pack.keep` bloquea antes, después y tras reopen; `custom.badge` aparece exactamente una vez | ✅ |
| Suite completa del proxy | `cargo test -p cerberus-proxy` | `154 passed; 0 failed` | ✅ |
| Integración daemon/config/packs | `cargo test -p cerberus daemon::tests` | `13 passed; 0 failed` | ✅ |
| Workspace completo (corrida previa de esta unidad) | `cargo test --workspace` | `532 passed; 0 failed` (32 suites); preservada como historia, no como cifra final | ✅ |
| Workspace completo (estado final v6.1) | `cargo test --workspace` | `534 passed; 0 failed` (32 suites, 2026-08-21; revalidación del fix dashboard wire v2) | ✅ |
| Formato | `cargo fmt --all -- --check` | exit 0, sin diff | ✅ |
| Lints estrictos | `cargo clippy --workspace --all-targets -- -D warnings` | `No issues found` | ✅ |

## Casos adversariales probados

- Regla custom ausente antes del PUT: el marker pasa (`200`).
- La misma regla, con `flag/category/severity/action/patterns/contextKeywords/minLength/maxLength/allowedExamples/validators`, bloquea inmediatamente (`403`).
- Una entrada exacta de allowlist elimina el finding en el siguiente request sin reiniciar (`200`).
- Tras reabrir el YAML, la entrada permitida sigue pasando; otra coincidencia de la misma regla sigue bloqueada.
- La regla base de pack sigue bloqueando durante todo el ciclo y el flag custom no se duplica.
- Un patrón inválido y un fallo de persistencia conservan config y engine anteriores (tests unitarios de `api.rs`).
- Un rebase de pack mantiene el read-lock de config hasta publicar, serializado con el write-lock de `commit_policy`; evita combinaciones `base nueva/policy vieja` bajo concurrencia.

## NFR aplicables

- `cargo test --release --test load_test -- --nocapture`: 7 passed; p99 release máximo observado `3.929 ms` (`scan_and_redact`), dentro del presupuesto `< 3–5 ms`.
- Seguridad: el dataplane sigue tomando un snapshot atómico del engine por request; ni reglas ni payload secrets se imprimen en `Debug`.

## Riesgos residuales

- El cambio de `listen` continúa requiriendo reinicio para rebind del socket; la API ya lo declara con `requires_restart:true`.
- La persistencia YAML es transaccional respecto a la publicación en memoria, pero no constituye una transacción ACID frente a caída del proceso durante la escritura del archivo.
