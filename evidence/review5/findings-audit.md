# Evidence — Adversarial Adoption Audit (Code Review v5 Findings)

- **Fecha:** 2026-08-21
- **Revisor:** agente revisor independiente (prueba de adopción adversaria)
- **Commit auditado:** `8f54bb0` (HEAD de la rama `findings-audit`)
- **Worktree aislado:** `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/findings-audit`
  - Nota: la ruta del enunciado (`/var/folders/mw/...`) no existía en esta máquina; el worktree
    se creó con `git worktree add` en el dir temporal real del entorno. Único cambio en el
    worktree: este archivo. `git status --short` limpio antes/después de la auditoría.
- **Regla:** solo lectura/ejecución de verificación. NO se modificó código ni tests.

---

## Dictamen resumido

**10/10 PASS.** No se detectó ningún hallazgo sin resolver. El dictamen se sustenta en
verificación estática (file:line) + ejecución de los comandos de verificación indicados.

## Tabla de hallazgos

| Nº | Overte | file:line | Verificación | Dictamen |
|----|--------|-----------|--------------|----------|
| 1 | P1 F6 dashboard | `crates/cerberus-proxy/src/api.rs:201-217, 266-281`; `crates/cerberus-proxy/dashboard.html:50, 60-61, 84, 103, 108-116, 288` | auth_gate 401 sólo rutas con datos; dashboard exento; token por header X-Cerberus-Admin-Token + localStorage; filtro `?provider=` con filter_by_provider | **PASS** |
| 2 | P1 FAIL-1 (F7) update pak | `crates/cerberus-packs/src/updater.rs:284-349` | ownership por nombre de pack (solo se reemplaza `n == name`), manifest ordena order/active/versions, `pack_owned_rules` (:489), `engine_from_manifest` (:506) | **PASS** |
| 3 | P1 FAIL-2 rollback durable | `crates/cerberus-packs/src/updater.rs:360-397, 574-609, 619-660` | rollback persiste manifest; `load_installed_from_dir` no-op si manifest cargado; rebuild desde manifest | **PASS** |
| 4 | P1 F5 store durable | `crates/cerberus-store/src/store.rs:133, 157, 230-238, 256-268, 275-276, 287-303` | sync_channel bounded + try_send/dropped_events; flush propaga last_error; close → Disconnected = Err; flush_durable | **PASS** |
| 5 | P2 determinismo PR | `crates/cerberus-engine/tests/precision_recall_test.rs:37-53, 248-349, 490, 543` | ExpectedInstance + span_in_all; reporte sin "Scan time"/tiempos; `rows.sort_by_key(flag)`; sha256 idéntico en 2 corridas | **PASS** |
| 6 | F6 filtros provider | `crates/cerberus-proxy/dashboard.html:60-61, 149-155`; `crates/cerberus-proxy/src/api.rs:221-240` | `<select id=provider-filter>` + query_provider/filter_by_provider; test corre OK | **PASS** |
| 7 | P1 hot-reload | `crates/cerberus/src/daemon.rs:297-390, 551-566` | Arc<RwLock<Arc<CompiledEngine>>> live_engine + PackCommand + swap_live_engine; smoke_harness.rs:986 | **PASS** |
| 8 | P2 interface/CLI | `crates/cerberus/tests/pack_cli_e2e.rs:110-173` | install/list/rollback persisten; `cargo test --test pack_cli_e2e` → 2 passed (+33 total `--tests`) | **PASS** |
| 9 | P2 F8 docker | `docker-compose.yml:16`; `Dockerfile:6,10` | ${CERBERUS_ADMIN_TOKEN:?...} obligatorio; Dockerfile `cargo build -p cerberus` | **PASS** |
| 10 | Independencia | worktree removible + evidence propio | Verificación hecha en worktree aislado; único cambio commit-able es este archivo | **PASS** |

---

## Verificación por hallazgo (evidencia cruda)

### Hallazgo 1 — P1 F6 dashboard con auth inutilizable → **PASS**

El gate exime SOLO el HTML público `/api/dashboard`:

- `crates/cerberus-proxy/src/api.rs:201-203`:
  ```rust
  fn route_serves_data(path: &str) -> bool { path != "/api/dashboard" }
  ```
- `api.rs:210-216` — `auth_gate` sólo devuelve 401 cuando `route_serves_data(path) && !authorized(...)`.
- `api.rs:270-281` — enrutado: `/api/dashboard` → `handle_dashboard`, `/api/stats|events` pasan `provider`.
- `dashboard.html:50` `<input type="password" id="cerberus-token" ...>`; `:84` lectura `localStorage.getItem(TOKEN_KEY)`; `:114` `fetch(url, { headers: { 'X-Cerberus-Admin-Token': tok } })`; `:103` guardado en `localStorage`.

Pruebas (comando real):
```
$ cargo test -p cerberus-proxy --test smoke_harness test_dashboard_served_without_auth_when_token_set
→ cargo test: 1 passed, 23 filtered out
$ cargo test -p cerberus-proxy --test smoke_harness test_stats_filters_by_provider_query
→ cargo test: 1 passed, 23 filtered out
```
*sample: línea 863 y 909 de smoke_harness.rs contienen ambos tests; el primero valida `GET /api/dashboard` sin token (200), el segundo valida el filtro por provider.*

### Hallazgo 2 — P1 FAIL-1 (F7) update pak → **PASS**

`install_with_root` en `crates/cerberus-packs/src/updater.rs`:
- (a) Ownership por nombre: bucle de candidatos `:287-291` excluye packs no activos y a los packs del MISMO nombre (`n == &name` → `continue`), reemplazando la versión anterior.
- (b) Sustituye las reglas de la versión anterior del mismo pack: deactiva la versión previa con el mismo nombre en el manifest (`:309-320: manifest.active.insert(versioned_key(name, prev), false)`; activa la nueva; versiones se registran en `versions_by_pack` `:321-327`).
- (c) Engine determinista base+packs ordenado: `assemble_rules` (`:122-135` `packs.sort_by(...)`) + rebuild_order; `engine_from_manifest` en `:506-512`.
- Métodos comprobados: `pack_owned_rules` (`:489`), `engine_from_manifest` (`:506`).

Prueba de verificación:
```
$ cargo test -p cerberus-packs --all-targets
→ cargo test: 44 passed (1 suite, 0.01s)   [coincide con esperado]
```
Tests específicos de reopen/update (localizados): `update_replaces_same_pack_flags_in_engine` (`:918`), PASS.

### Hallazgo 3 — P1 FAIL-2 rollback durable → **PASS**

- `rollback()` (`updater.rs:360-397`): hace pop de `activation_sequence`, deactiva en manifest y `persist_manifest` (`:396`); reconstruye engine desde el manifest modificado (`rebuild_active_set`).
- Al reabrir `PackManager`: `load_manifest` lee `manifest.json` (`:207-231`); `load_installed_from_dir` hace no-op cuando el manifest ya se cargó (`:574-584` — "no reintalar los JSON (fix FAIL-2)").
- `rebuild_active_set` ordena determinista por (nombre, versión) (`:634`).

```bash
$ cargo test -p cerberus-packs --lib rollback_persists_and_survives_manager_reopen  → 1 passed
$ cargo test -p cerberus-packs --lib reopen_preserves_engine_composition_and_order  → 1 passed
```

### Hallazgo 4 — P1 F5 store durable → **PASS**

`crates/cerberus-store/src/store.rs`:
- Canal acotado: `mpsc::sync_channel(WriteMsg, capacity)` (`:133`).
- `write_event_async` usa `try_send` y cuenta dropped_events (`:230-236`).
- `flush()` propaga `last_error` (line `:194-195`, y `:256`).
- `close()`: transporte ack `Result`, `Disconnected` → **Err** explícito (`:287-303`).
- Daemon: `write_loop` (line :157+) y `flush_durable` (`:275-276`).

```bash
$ cargo test -p cerberus-store
→ cargo test: 18 passed (2 suites, 0.01s)   [>18]
```
Tests de regresión en `store.rs`: `flush_reports_prev_insert_failure`, `close_stops_writer_and_fails_subsequent_writes` (verifican Errores).

### Hallazgo 5 — P2 determinismo PR → **PASS**

- `ExpectedInstance { flag, value }` (`:37-42`), `span_in_all` para la k-ésima aparición (`:53`).
- Reporte: `write_results` SÓLO escribe fichero sin temporizaciones; "Scan time" NO está en el archivo (grep `scan time|duration|ms\b` → 0 coincidencias en `precision_recall_results.txt`). El tiempo está solo en stderr (`:543` eprintln/scan ms).
- Filas ordenadas por flag: `rows.sort_by_key(|r| r.flag.clone())` (`:490`).
- Líneas exigidas: `per-instance: true` (`:258`) y `ground-truth: spans(N)` (`:259`).

Corrida 2 veces `--test-threads=1`:
```
Corrida 1 → sha256 969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e  (6 passed)
Corrida 2 → sha256 969e84903ef58e72a7d706e2d50ab938c35d0c2c5851b5f40f64736355114d2e  (6 passed)
```
→ **mismo valor exacto en ambas corridas (mismo sha256)**, y sin tiempos en el archivo.

### Hallazgo 6 — F6 filtros por provider → **PASS**

- `dashboard.html:60-61` `<select id=provider-filter>`; `:149-155` se puebla y `:208` lee el valor.
- `api.rs:221-240` `query_provider` + `filter_by_provider`; enrutado `:267-274` lo aplica a stats|events.
- Test `test_stats_filters_by_provider_query` → PASS (ver hallazgo 1).

### Hallazgo 7 — P1 hot-reload de engine → **PASS**

`crates/cerberus/src/daemon.rs`:
- `:320` `let live_engine: Arc<RwLock<Arc<CompiledEngine>>> = ...`
- worker channel `PackCommand { Install/Rollback/List }` (`:326-390`); tras install/rollback llama `swap_live_engine` (`:551`, `:557`-`principal`).
- Proxy expone `engine: live_engine.clone()` (`:390`).

```bash
$ cargo test -p cerberus-proxy --test smoke_harness test_hot_reload_swaps_engine_without_restart -- --test-threads=1
→ cargo test: 1 passed, 23 filtered out
```
Test definido en `smoke_harness.rs:986`.

### Hallazgo 8 — P2 espera daemon/interface → **PASS**

```bash
$ cargo test -p cerberus --test pack_cli_e2e
→ cargo test: 2 passed (1 suite, 0.83s)     [install + gate-licencia]
$ cargo test -p cerberus --test pack_cli_e2e --tests
→ cargo test: 33 passed (3 suites, 3.20s)
```
El E2E cubre `cerberus pack install`, `pack list`, `pack rollback` y verifica el pack activo en un engine persistido (`pack_cli_e2e.rs:126-140`).

### Hallazgo 9 — P2 F8/Docker → **PASS**

```yaml
docker-compose.yml:16:  - CERBERUS_ADMIN_TOKEN=${CERBERUS_ADMIN_TOKEN:?set a strong admin token (>=24 chars)}
```
→ variable **obligatoria**, sin `change-me` fallback.

```docker
Dockerfile:6 RUN cargo build --release -p cerberus
Dockerfile:10 COPY --from=builder /app/target/release/cerberus /usr/local/bin/cerberus
```
→ imagen compilan y ejecutan el binario `cerberus`.

### Hallazgo 10 — Independencia → **PASS**

Auditoría ejecutada en worktree `git worktree` aislado en un directorio temporal fuera del repo de trabajo; se evaluó únicamente leyendo + ejecutando. `git status --short` del worktree tiene **0 cambios** excepto este archivo `evidence/findings-audit.md` (único cambio realizado por el revisor).

---

## Conclusión

Todos los verificables estáticos y dinámicos apuntan a la resolución correcta de los 10 hallazgos v5.
Sin FAIL respaldado. Reabrir solo requeriría nueva evidencia si el código cambiara después de
`8f54b0`.

*Documento generado por el revisor adversario independiente; evidencia cruda de comandos incluida arriba.*