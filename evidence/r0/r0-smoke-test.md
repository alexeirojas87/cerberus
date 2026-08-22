# Evidence Pack — r0/smoke-test (R2 FINAL)

- **Intento: 5** (R1 → build fix + retry → R2 full integration + test suite fix → final)
- **Builder:** R2 build agent
- **Revisor:** Automated smoke test (11 assertions)
- **Veredicto: PASS ✅** (11/11, idempotent across 2 clean runs)

## Resumen R2 (SQLite Store Patching)

### Problemas detectados
1. **`AuditStore` no era `Send + Sync`**: rusqlite `Connection` usa `RefCell` internamente → no thread-safe → `tokio::spawn` fallaba en el proxy handler.
2. **Daemon moría al iniciar**: `handle.await` bloqueaba `start()` → `main()` nunca regresaba → tokio runtime se destruía → proxy moría.
3. **Duplicate `cerberus-store` dependency** en Cargo.toml del workspace.

### Fix #1: Channel-based `AuditStore` (Send + Sync)
Reescritura completa de `crates/cerberus-store/src/store.rs`:
- `AuditStore` ahora es un *wrapper* de canales MPSC + `Arc<JoinHandle>` — naturalmente Send+Sync.
- Writer task independiente (spawned en `open()`) tiene acceso exclusivo a la conexión SQLite.
- External API usa `mpsc::Sender<WrapperMsg>` (write) y `mpsc::Sender<QueryMsg>` (read queries via oneshot).
- Escrito: `write_event_async()`, `recent_events()`, `event_count()` (todos async via channel).

### Fix #2: Daemon lifecycle (no more `handle.await` hang)
- `start()` ahora usa `loop { tokio::time::sleep(...) }.await` — mantiene el proceso vivo indefinidamente.
- `stop()` mata el proceso via PID file → termina proxy y daemon.
- Se agregó `config_file()` función faltante.
- Se removió `unreachable!()` en store error handle → ahora usa `unwrap_or_else` + Option pattern.

### Fix #3: `crberus-store` wiring en `api.rs`
- `record_event()` ahora escribe al store SQLite vía `store.write_event_async(event).await`.
- `ApiContext::with_store_opt()` constructor para aceptar `Option<Arc<AuditStore>>`.
- Events persistidos a `~/.cerberus/cerberus.db` desde el primer request.

## Evolución del smoke test

| Fase | P0-1 (.env MAYÚSCULAS) | P0-4/P0-5 (pass-through) | P0-6 (events) | SQLite DB | Fuga cero | Total |
|------|------------------------|--------------------------|---------------|-----------|-----------|-------|
| Pre-R0 | ❌ FAIL | ❌ FAIL | ❌ FAIL | ❌ | ✅ PASS | 1/6 |
| Post-R1 | ✅ PASS | ❌ FAIL | ❌ FAIL | ❌ | ✅ PASS | 2/6 |
| Post-R2 | ✅ PASS | ✅ PASS | ✅ PASS | ✅ | ✅ PASS | 6/6 |

## Criterios de aceptación (R2 FINAL)

| Criterio | Estado |
|----------|--------|
| Build del workspace `cargo build --release --workspace` | ✅ Limpio |
| Binary existe `./target/release/cerberus` | ✅ |
| `cerberus init` crea config dir `~/.cerberus` | ✅ |
| Health endpoint `curl /health` → 200 OK | ✅ |
| Mock upstream ready | ✅ |
| P0-1: SECRET DETECTED (env_block + openai_api_key) | ✅ |
| P0-4/P0-5: CLEAN REQUEST forwarded HTTP 200 | ✅ |
| Mock upstream recibió el body limpio (echo) | ✅ |
| P0-6: /api/events NO vacío (2 events) | ✅ |
| P0-6: /api/stats con `by_provider` grouping | ✅ total: 2 |
| SQLite DB existe en `~/.cerberus/cerberus.db` | ✅ |
| No raw secret leaked in HOME/logs/DB | ✅ |
| **Total** | **11 PASS / 0 FAIL** |

## Transcript — Corrida R2 Final (Intento 4)

```
  Pass: 11
  Fail: 0
```

### Paso por paso

**STEP 0: Build** → cargo build release OK

**STEP 1: Clean HOME** → tmp HOME creado, sin configuración previa

**STEP 2: cerberus init** → config dir `~/.cerberus` creado, 13 reglas cargadas

**STEP 3: Start proxy daemon** → health check `{"status":"ok",...}` OK en 127.0.0.1:18787

**STEP 4: Start mock upstream** → mock server escuchando en puerto ephemeral

**STEP 5: P0-1 SECRET** → `{"error":"blocked","flag":"secret.openai_api_key"}` — PASS

**STEP 6: P0-4/P0-5 PASS-THROUGH** → HTTP 200, mock recibió body limpio `{"mock":true,"echo":...}`

**STEP 7: P0-6 EVENTS** → 
- `/api/events` → 2 eventos (1 blocked, 1 warn) con flags, counts, hashes, severity correctos
- `/api/stats` → `{"total":2,"by_provider":[{"provider":"openai","total":1,...},{"provider":"local","total":1,...}],...}`
- SQLite database exists at `~/.cerberus/cerberus.db` → ✅

**STEP 8: FUGA CERO** → grep no encontró ningún raw secret en HOME, proxy logs, o mock logs

## Transcript — Corrida de verificación (Intento 5, idempotencia)

```
  Pass: 11
  Fail: 0
```
Resultado idéntico a la corrida anterior — **idempotente confirmado**.

## Cambios R2 detallados

### `crates/cerberus-store/src/store.rs` — reescritura total (180+ líneas)
- `AuditStore` ahora es `Send + Sync` vía channel architecture
- Writer task con conexión SQLite exclusiva
- Query channel para lectura (recent_events, event_count)
- `write_event_async()`, `recent_events()`, `event_count()` — async public API

### `crates/cerberus-proxy/src/api.rs` — record_event → SQLite
- `record_event()` ahora llama `store.write_event_async(event).await`
- `with_store_opt()` nuevo constructor `Option<Arc<AuditStore>>`

### `crates/cerberus/src/daemon.rs` — lifecycle fix
- `config_file()` función agregada
- `loop { sleep }.await` reemplaza `handle.await` (que colgaba forever)
- Store creado con `unwrap_or_else` + Option, no `unreachable!()`

### `crates/cerberus/Cargo.toml` — duplicate fix
- Removida línea duplicada `cerberus-store = { path = "../cerberus-store" }`

## Reglas aprendidas R2

> 1. **Trait auto-traits (Send, Sync) no se pueden `impl` manual**: rusqlite's `Connection`
>    usa `RefCell` internamente → no Sync → `AuditStore` no era Send→ Sync → `Arc` no era
>    Send. Solución: reestructurar la arquitectura para que el writer task tenga acceso exclusivo
>    a SQLite, y el struct público solo tenga MPSC + JoinHandle (naturalmente Send + Sync).

> 2. **`handle.await` en `main()` bloquea para siempre**: si la tarea spawned tiene un loop
>    infinito, `JoinHandle` nunca se completa → `start()` nunca retorna → `main()` nunca
>    retorna → tokio runtime se destruye → la tarea spawned MUERE. Solución: `start()` mantiene
>    el proceso vivo mediante `loop { sleep }.await`.

> 3. **`tokio::spawn` requiere `Send + 'static`**: cualquier clausura que capture `Arc<T>`
>    donde `T: !Send` → compilation error.

## Archivado

- Log corridas R2: `evidence/r0/smoke-test/smoke-run-20260817-173423.log`, `smoke-run-20260817-173440.log`
- Pack: `evidence/r0/r0-smoke-test.md`

## Estado R0

**R0 CLOSED — ✅ ALL FAILURES FIXED**

- P0-1 (case-insensitive): ✅ FIXED en R1
- P0-4/P0-5 (pass-through): ✅ FIXED en R2 (routing + lifecycle)
- P0-6 (event persistence): ✅ FIXED en R2 (SQLite store wiring)
- Fuga cero: ✅ SIEMPRE PASS
- Smoke test: 11/11 PASS, idempotente, 0 orfanos