# F4 — Revisión adversarial independiente (commit a04a84d)

Revisor externo, sin modificación de código. Verificación con file:line y reproducción real.
Worktree: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f4-reviewer`.

| # | Claim | Dictamen | Evidencia |
|---|-------|----------|-----------|
| 1 | Windows support real (platform.rs, stop graceful, process_alive, CI 3 OS) | **PASS** (con caveat: no cross-compile local) | Ver abajo §1 |
| 2 | Feedback dev conectado (feedback_ux.rs + notify-rust, watcher, rate-limit, sin raw) | **PASS** (función `show_feedback` sin caller de producción) | Ver abajo §2 |
| 3 | Cero-config (init escribe upstreams por defecto) | **PASS** | Ver abajo §3 |
| 4 | MITM forward proxy (CA, validate, listener, allowlist, fail-closed, wiring) | **PASS** | Ver abajo §4 |
| 5 | Preservar gates previos (clippy 0, fmt 0) | **PASS** | Ver abajo §5 |

## 1 — Windows support real — PASS (con caveat de cobertura local)

- `platform.rs:19-36` → `config_dir()` usa `%APPDATA%\Cerberus` en Windows (`crates/cerberus/src/platform.rs:24-31`), fallback `C:\Cerberus`.
- `platform.rs:46-55` → `daemon_binary_name()` = `cerberus.exe` en Windows.
- `platform.rs:63-92` → `process_alive()` rama Windows via `tasklist /FI "PID eq N" /NH` + escaneo de token de PID (evita falso positivo con línea `INFO: No tasks`).
- `platform.rs:104-150` → `stop_process_graceful()`: rama Windows envia `taskkill /PID <pid>` **SIN /F** primero → `wait_for_process_exit` (≤5 s, `platform.rs:154-159`) → `taskkill /PID <pid> /F` si sigue vivo (`platform.rs:133-140`).
- `daemon.rs:760-791` → `stop()` y `process_alive()` delegan en `platform`; `cerberus stop` ya no está restringido a unix.
- CI matrix 3 OS: `.github/workflows/ci.yml:18` (`os: [macos-latest, ubuntu-latest, windows-latest]`), tests en Windows serializados con `--test-threads=1` (`ci.yml:51-57`). `cargo build --workspace`, clippy y fmt por OS.
- **Caveat de reproducción**: `rustup target list --installed` reporta solo `aarch64-apple-darwin` → NO se pudo compilar `x86_64-pc-windows-msvc` localmente (se documenta: no instalado, CI cubre; no se instala por órden del review). Las ramas Windows se validan por inspección de código (cfg-gated) y por la matriz CI, no por ejecución local.
- Hallazgo menor (no-bloqueante): en Windows el fallo de `taskkill` graceful se descarta (`let _ = graceful;` `platform.rs:129`); la red de seguridad `/F` lo cubre, asimetría con unix (que propaga el error en `:109-111`).
- Prueba real en mac: `process_alive` usa `kill -0` y los tests `process_alive_false_for_garbage_pid`/`_true_for_current_process`, `daemon_binary_name_without_extension...` pasan (dentro de las 56 de `cargo test -p cerberus --all-targets`).

## 2 — Feedback al dev conectado — ✅ (nota: `show_feedback` solo tiene callers de test)

- **Ruta productiva real**: `daemon.rs:506-507` captura `ctx.api.events` (Arc del buffer del control plane) y crea `InterventionWatcher::new()`; `daemon.rs:570-578` en el loop del `tokio::select!` del daemon, cada tick (1 s) `feedback_ux::emit_interventions(&api_events, &mut interventions).await`. → el watcher del audit store está disparado desde el daemon, no solo tests.
- `feedback_ux.rs:50-65` → `drain_interventions` (watermark posicional, block/redact/warn via `is_dev_intervention` `:24-26`), con resync tras trim del buffer sin replay (`:52-57`).
- `feedback_ux.rs:74-87` → `send_dev_feedback`: notificación desktop o fallback a línea CLI en stderr (`eprintln!`, `:81, :85`).
- **Éxito del cuerpo sin valores crudos**: `dev_feedback_line` (`:92-105`) solo usa `event.flags.first()`, `event.hashed_values.first()` y metadatos tool/provider/severity; el hash viene del store (`sha256:...`). Test `dev_feedback_line_has_flag_and_hash_never_raw` y `dev_feedback_line_empty_event_safe` pasan.
- **notify-rust**: `crates/cerberus/Cargo.toml:36-40` — depende de notify-rust solo para macos y linux; en otras plataformas `notify_desktop` imprime a stderr con emoji (`feedback_ux.rs:133-139`).
- **Rate-limit** `1/s`: `feedback_ux.rs:142-166` (`NOTIFY_MIN_INTERVAL` + `acquire_feedback_slot`), testeado (`rate_limit_allows_first_and_blocks_immediately`).
- ⚠️ **Hallazgo / quiebre de sub-claim**: se pidió verificar que `show_feedback` tiene caller de producción. `grep` exhaustivo: los únicos callers de `show_feedback` son `feedback_ux.rs:440/447/455` = tests unitarios. `show_feedback` NO está conectado ni a `cli scan/test` (que usan `init::scan_text`, `init.rs:186-215`, sin llamarlo) ni al daemon (la ruta productiva es `emit_interventions → send_dev_feedback`). Es código muerto amparado por `#![allow(dead_code)]` del módulo. Reportado como nota de higiene: la feature F4 sí está entregada (watcher en `daemon.rs:577`), pero **ese símbolo concreto NO tiene caller de producción (solo tests)**.

## 3 — Cero-config — ✅

- `init.rs:96-98` → `init_config_yaml()` (const) genera YAML con `upstreams: {anthropic: {url: https://api.anthropic.com}, openai: {url: https://api.openai.com}}` + `listen/mode/fail_policy`.
- `run_init` escribe ese YAML en `config.yaml` (`init.rs:67-69`).
- El YAML parsea con tipo `UpstreamConfig` válido: test `init_writes_config_with_default_upstreams` (`init.rs:331-363`) lo parsea con `ProxyConfig::parse`, verifica keys/URL y que la escrita se preserva → pasa.
- `daemon.rs:187-264` → `resolve_config` merge: `file_cfg` (config.yaml) es la base; `config.upstreams.is_empty()` (que arrojaría error instructivo) solo si NO hay upstreams de `env` NI de config.yaml. Con el YAML de `init` → `cerberus start` arranca sin `CERBERUS_UPSTREAM_URL`. Test `resolve_config_preserves_yaml_fields` (`daemon.rs:955-992`) pasa.
- `cargo test -p cerberus --all-targets`: **56+2+4+3+4 OK** (0 fail).

## 4 — MITM forward proxy — ✅

- **generator**: `forward.rs:143-188` `generate_local_ca`: rechaza sobrescribir (`paths.cert.exists() || paths.key.exists()` → Err), dir 0700 (`create_secure_dir` `:196-205`), key 0600 vía `create_new_file(true)` (`:207-217`), CA self-signed con `BasicConstraints` (`:158`, `IsCa::Ca`), flush+sync (`write_and_sync`), y al final re-`validate_ca_files`.
- **validate / LocalCa::load**: `forward.rs:192-249, 277-306`: rechaza symlinks (`symlink_metadata` + `file_type().is_symlink()`, `:225-227`), >1MiB (`MAX_CA_FILE_BYTES` `:45, :227-231, :241-246`), unix perms key !=0600 (`:232-238`), cert-no-CA (`basic_constraints...ca` `:292-297`), key mismatch (`public_key` vs `subject_public_key_info` `:299-301`), PEM estricto (una sola cadena, sin trailing `:250-271`).
- **listener**: solo loopback (`ForwardProxyConfig::new` `:76-80`), puerto !=0; CONNECT solo (`:558-560` devuelve 405 a no-CONNECT); puerto 443 solo (`parse_connect_target` `:617-621`); allowlist exacta normalizada (sin `*`/IP/puerto/sufijo, `normalize_host` `:120-139`); máx 64 hosts (`MAX_ALLOWED_HOSTS` `:43, :106`); máx 128 conexiones (Semaphore `:471-486`, `MAX_CONNECTIONS=128`); handshake timeout 10s (`TLS_HANDSHAKE_TIMEOUT` `:46`, aplicado en `serve_intercepted` `:637-648`).
- **fail-closed antes del bind**: `spawn_forward_proxy` hace `LocalCa::load(&config.ca)?` y `server_config_for` de TODOS los hosts ANTES de `TcpListener::bind` (`:405-421`); error lo propaga el daemon y aborta `start` (`daemon.rs:513-523`). Wiring: `daemon.rs:296` `runtime_config() → mitm.rs` que valida CA + `ForwardConfigProxy::new` (loopback) `mitm.rs:71-82`; `daemon.rs:514`.
- **Prueba real**: `cargo test -p cerberus-proxy --lib forward` → **19/19 PASS** (cubre: create_new, key 0600, non-CA/mismatch, symlink, permisos, oversize, fail-before-bind con CA mismatch y con CA ausente, allowlist exacta + límites, 128 conexiones y recuperación, redact sin leak al upstream ni al audit, shadow pasa original, fail-policy closed/open, cierre de túnel en shutdown, host-no-listado 403 / puerto-wrong 400 / GET 405). `cargo test -p cerberus mitm_cli_daemon` → **4/4**. `cargo test -p cerberus mitm` → **9 unit + 4 integration PASS**.
- **ADVERSARIA allowlist (probe ad-hoc fuera del repo)**: compile un binario temp con path-dep en `cerberus_proxy::forward::normalize_allowed_hosts` (código real, sin tocar el repo) y probé 25 casos:
  - `host..com` → REJECT; `host-.com` → REJECT; `-host.com` → REJECT; `.example.com` / `..example.com` → REJECT; wildcard/IPv4/IPv6/scheme/port/localhost/underscore/espacio/253+ → REJECT; punycode `xn--xcn...` → ACCEPT (ascii válido, por diseño).
  - **Quirk no explotable**: `api.example.com..` / `...` colapsan por `trim_end_matches('.')` al término de la allowlist (ej. `api.example.com`). NO es un bypass: el `authority.host()` se normaliza ANTES de la búsqueda, la clave del mapa está normalizada igual, y `target`/cert leaf se construyen desde la entrada DE LA ALLOWLIST (`format!("https://{host}:443")`, `:417`), nunca de la string del cliente → ninguna ruta puede alcanzar un upstream fuera de la allowlist.

## 5 — No romper gates previos — ✅

- `cargo clippy --workspace --all-targets -- -D warnings` → salida limpia (`Finished dev profile`, sin warnings; exit 0).
- `cargo fmt --all -- --check` → salida vacía / exit 0.

## Dictamen F4 adversario

**PASS.** Las cinco afirmaciones verificadas con file:line y reproducción local (56 unit + 13 integration cerberus; 19 forward; 9 mitm unit + 4 integration; 0 clippy; 0 fmt). La allowlist y el fail-closed del MITM aguantan el intento adversarial (se probó con el código real fuera del repo: `host..com`, `host-.com`, etc., siempre rechazados, y el colapso de trailing dots no es explotable). Windows no se pudo compilar localmente (solo toolchain aarch64-darwin): cobertura por CI 3-OS, inspección por código. Dos anotaciones no-bloqueantes:
1. `show_feedback` en `feedback_ux.rs` no tiene caller de producción (dead-code solo tests); la feature live es el watcher `emit_interventions` (daemon.rs:577) — funcion cumplida pero declaración/documentado confuso para builders.
2. En Windows el error de `taskkill` graceful se descarta (`let _ = graceful`); la red `/F` cubre.

Ninguna acción correctiva requerida para F4.