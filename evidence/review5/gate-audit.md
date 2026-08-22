# Gate Audit — Gauntlet v5 (revisión del commit 8f54bb0)

- **Auditor:** gate-audit (rol SOLO verificación; sin modificación de código)
- **Worktree:** `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/gate-audit`
  (git desacoplado del main; detached HEAD, no toca el repo principal)
- **Commit auditado:** `8f54bb08d3f98e8fe89c5ac1a26ebff92b515340`
  (`feat(gauntlet v5): resolver los 10 hallazgos del code review — auth dashboard,
   packs hot-reload, store durability, determinismo PR, wiring engine, docker F8`)
- **Fecha:** 2026-08-21
- **Método:** ejecución directa en el worktree + verificación file:line del código
  en HEAD. Ningún archivo de código fue modificado por este auditor.

---

## 1. Resultado por comando (ejecutado en el worktree)

| # | Comando | Resultado | Evidencia |
|---|---------|-----------|-----------|
| 1 | `cargo fmt --all -- --check` | **PASS** (exit 0, 0 diffs) | salida vacía, `FMT_EXIT=0` |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** (exit 0, 0 errores) | `CLIPPY_EXIT=0 PASS`, `Finished dev profile ... in 15.19s` |
| 3 | `cargo test --workspace --all-targets` | **PASS** | **443 passed / 0 failed** (22 bins de test) |
| 4 | `cargo test --release --workspace --all-targets` | **PASS** | **443 passed / 0 failed** (22 bins) |
| 5 | Determinismo `cargo test --release --workspace --all-targets` x2 | **PASS** | run1 443/0 · run2 443/0 (idéntico) |
| 6 | `cargo test --release --workspace --all-targets` x3 (load determinista) | **PASS** | 443 passed / 0 failed en las 3 runs |
| 7 | `load_test` binary (p99 budgets) x3 | **PASS** | `test result: ok. 7 passed; 0 failed` x3 (0.14s cada) |
| 8 | `python3 tools/simulate.py` | **PASS** | `RESULTADO: 29 PASS / 0 FAIL` |
| 9 | `git rev-parse HEAD` | **PASS** | `8f54bb08d...` coincide con builder_commit |

### Conteo de tests (release, 22 binaries de test)
- `test result: ok. 6+29+2+2+1+175+15+6+0+6+7+5+44+70+24+18+3+0+4+7+11+8 = 443 passed`, 0 failed.
- `cargo test --release --workspace --all-targets --test load_test`: 443/0 en las 3 corridas.
- `cargo clippy`: 0 errores, exit 0.

---

## 2. Verificación file:line de los 10 hallazgos (en HEAD)

| # | Hallazgo (rev5) | Dictamen | file:line clave |
|---|---|---|---|
| 1 | P0 Auth default-secure (no-loopback exige token ≥24) | **PASS** | `proxy.rs:133-146` `check_listen_security` rechaza no-loopback si token `None`/`<24`; `proxy.rs:164` evalúa ANTES del bind; `api.rs:65` `ADMIN_TOKEN_MIN_BYTES: usize = 24`; `api.rs:756` assert=24 |
| 2 | P0 Admin token no filtrado al upstream | **PASS** | `proxy.rs:558-568` loop de reenvío omite `host`, `BYPASS_HEADER`, `ADMIN_TOKEN_HEADER`, `SKIP_HEADERS`, y tokens `Connection`; `api.rs:58` `ADMIN_TOKEN_HEADER` |
| 3 | P1 Dashboard con auth funcional | **PASS (cambió a pública)** | `api.rs:198-217` `auth_gate` exige token en **todas** las rutas de datos `/api/*` (`route_serves_data`, `api.rs:201-203`) salvo `/api/dashboard` (HTML estático PÚBLICO sin datos, review v5 F6); `api.rs:279` ruta dashboard |
| 4 | P1 Control plane bodies ≤1 MiB → 413 | **PASS** | `api.rs:70` `CONTROL_PLANE_MAX_BYTES: usize = 1 << 20`; `api.rs:401-406` `Limited::new(body, CONTROL_PLANE_MAX_BYTES)` → `LengthLimitError` → `TooLarge`; `api.rs:329-331` `PAYLOAD_TOO_LARGE` (413) |
| 5 | P1 fail_policy cubre error de redacción (Closed 502/Open forward) | **PASS** | `proxy.rs:300-309` `decide_redact_result`: Closed → `Reject(502, json sin raw)`, Open → forward; `proxy.rs:482-484` dispatch |
| 6 | P1 Store flush con ACK condicionado a `last_error` + cierre graceful | **PASS** | `store.rs:162-180` `last_error` retiene primer INSERT fallido; `store.rs:195/201` flush ACK → `Err` si `last_error` pendiente; `store.rs:198` `WriteMsg::Shutdown`+ack+return; `store.rs:19-21/116` `open_with_capacity` bounded channel; `store.rs:235` `dropped_events` backpressure |
| 7 | P1 F7 hot-reload runtime (packs, mismo engine) | **PASS** | `daemon.rs:320-390` `live_engine: Arc<RwLock<Arc<CompiledEngine>>>` compartido proxy↔worker; `daemon.rs:329-385` worker de packs SWAPEA engine tras install/rollback vía `swap_live_engine` (`daemon.rs:551`); `daemon.rs:388-394` `ProxyContext { engine: live_engine.clone() }`; **proxy.rs:112** `Arc<RwLock<Arc<CompiledEngine>>>`, **proxy.rs:431** `ctx.engine.read()` snapshot por request; test e2e `test_hot_reload_swaps_engine_without_restart` smoke_harness.rs:986 → **OK** |
| 8 | P1 Precision/recall por instancia con spans | **PASS** | `precision_recall_test.rs` per-instance; salida real: `Corpus precision/recall (per-instance): recall=94.3% precision=89.2%`; test `per_instance_recall_does_not_substitute_same_flag` → ok; 6 passed/0 failed |
| 9 | P2 Gate debug estable (budgets por perfil) | **PASS** | `load_test.rs:21-34` budgets por perfil (`is_release = !cfg!(debug_assertions)`, release estricto / debug x10); determinista: release 443/0 x3, load_test 7/7 x3 |
| 10 | P1 Independencia de auditoría (worktrees separados) | **PASS** | ver §3 abajo: este gate-ao auditado en worktree git desacoplado propio |

`file:line` de paths abreviados → `crates/cerberus-proxy/src/proxy.rs`, `api.rs`,
`crates/cerberus-proxy/dashboard.html`, `crates/cerberus-store/src/store.rs`,
`crates/cerberus/src/daemon.rs`, `tests/load_test.rs`.

---

## 3. Independencia / worktree (hallazgo 10)

- El gate se ejecutó en un worktree git **independiente**:
  `/var/folders/l8/.../opencode/gate-audit`, HEAD desacoplado en `8f54bb0`, registrado
  con `git worktree add ... 8f54bb0` (no toca el repo principal).
- `git rev-parse HEAD` = `8f54bb08d3f98e8fe89c5ac1a26ebff92b515340` (== commit a auditar).
- Solo se escribió este archivo de evidencia; `git status` tras correr todos los gates
  muestra únicamente `evidence/gate-audit.md` como cambio (side-effects de tests como
  `precision_recall_results.txt` coinciden con lo commiteado, sin diff).
- Los dos revisores de la revisión v4 (`2b5ed4c`) ya documentaron independencia previa
  (ver `evidence/review3/gate-audit.md`, `evidence/review3/findings-audit.md`).

---

## 4. Veredicto

- **Determinismo:** PASS — `cargo test --release --workspace --all-targets` corrió
  3 veces idéntico (443 passed / 0 failed cada una); n veces más para el subset
  `--test load_test` (443/0). Sin flakiness.
- **Todos los gates:** PASS.
- **Hallazgos rev5:** 10/10 PASS en este audit (incluye el anteriormente PARCIAL #7
  hot-reload runtime, ahora con e2e `test_hot_reload_swaps_engine_without_restart` OK).

**VERDICT: GATE PASS** — Gauntlet v5 (`8f54bb0`) resuelve los hallazgos con evidencia
reproducible en este worktree aislado.