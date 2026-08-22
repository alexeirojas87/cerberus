# Evidence Pack — F4/feedback-dev + cero-config + MITM wiring al daemon

- Fecha: 2026-08-21
- Unidad: F4 — feedback al dev conectado (desktop/CLI), cero-config (`cerberus init`),
  y `cerberus mitm enable|disable` hablando con el estado del daemon (wiring real).
- Builder/verificación: opencode (deepseek-v4-flash), flujo Gauntlet §8B.
- Veredicto: **PASS** (dentro del repo; bloqueo externo de `crates/cerberus-packs` reportado, ver §Límites).

## Entregables y evidencia

| # | Entregable | Cómo | Comando | Salida citada |
|---|---|---|---|---|
| 1 | Feedback al dev CONECTADO | En el loop del daemon (`daemon.rs`, arm `sleep(1s)` del `tokio::select!`) se drena `ApiContext.events`; cada evento `block`/`redact`/`warn` dispara `feedback_ux::send_dev_feedback`: macOS/Linux `notify-rust` (título “Cerberus bloqueó/redactó/advierte”, cuerpo flag+hash, NUNCA el secreto), tasa ≤1 notif/seg, fallback línea CLI a stderr; fuera de Unix la notificación es una línea a stderr con emoji | `rtk cargo test -p cerberus feedback_ux::tests` | `17 passed, 47 filtered out` (selección de acción, watermark sin replay/trim, línea sin valor crudo, tasa 1/seg) |
| 2 | Cero-config | `init.rs` escribe upstreams EXPLÍCITOS en `config.yaml` (`openai → https://api.openai.com`, `anthropic → https://api.anthropic.com`) → `cerberus start` arranca sin `CERBERUS_UPSTREAM_URL`; la guía ya no pide exportar env | `rtk cargo test -p cerberus init::tests` | `init_writes_config_with_default_upstreams` PASS |
| 3 | MITM conectado al daemon | `cerberus mitm enable/disable`: comprueba `daemon::is_running()`; daemon vivo → persiste config + imprime “edita `~/.cerberus/mitm.json` y reinicia (`cerberus stop && cerberus start`)” (no hay `/api/mitm` en caliente: api.rs es de otro agente); daemon parado → escribe config y anuncia que aplica al próximo arranque | `rtk cargo test -p cerberus --test mitm_cli_daemon` y `-p cerberus mitm::tests` | 4 integration PASS (exit codes + mensajes sin/con daemon), `enable_with_running_daemon_warns_restart_and_persists` PASS |
| 4 | Tests | Unit (feedback/rate-limit/watcher; mitm daemon-state) + integración real del binario con HOME aislado y pid file del proceso vivo | `rtk cargo test -p cerberus --all-targets` | `68 passed (5 suites)` |
| V | Build | — | `cargo build -p cerberus` | `Finished dev profile` (en copia aislada; ver §6) |
| V | Clippy | — | `rtk cargo clippy -p cerberus --all-targets -- -D warnings` | `No issues found` |
| V | Fmt | — | `cargo fmt --all -- --check` (mis 6 archivos) | 0 diffs; solo diffs ajenos en `platform.rs`/`telemetry.rs` |

## Cambios

- `crates/cerberus/src/feedback_ux.rs` — `send_dev_feedback`, `dev_feedback_line`, `is_dev_intervention`, `InterventionWatcher` (watermark posicional con resync por trim), rate limit 1/seg, `notify_desktop` cfg(unix)=notify-rust / cfg(other)=stderr emoji, `emit_interventions` (async) para el daemon. Línea y notificación usan SOLO flag + hash del `AuditEvent` (nunca el valor crudo).
- `crates/cerberus/src/daemon.rs` — `emit_interventions` en el arm `sleep(1s)` del loop graceful; `api_events` capturado antes de mover `ctx` a los proxies; `is_running` → `pub(crate)`. Startup ya lee `runtime_config()` (MITM al boot, sin cambios).
- `crates/cerberus/src/init.rs` — `init_config_yaml()` con upstreams explícitos; pasos corregidos (cero env).
- `crates/cerberus/src/mitm.rs` — `enable`/`disable` ahora anuncian la ruta persistida; `enable_with_daemon_state`/`disable_with_daemon_state` + `daemon_restart_note()`.
- `crates/cerberus/src/main.rs` — dispatch `mitm enable|disable` usa `daemon::is_running()` y los helpers con estado.
- `crates/cerberus/tests/mitm_cli_daemon.rs` — integración: status baseline, enable sin CA (exit≠0), init-ca → enable → disable (exit 0), enable con daemon falso (pid vivo) → nota de reinicio.
- `crates/cerberus/Cargo.toml` — sin cambios de deps: `notify-rust` ya existe en macos/linux; Windows sin notif usa el fallback `cfg`.

## Casos adversariales

- Linha de feedback construída con evento sin flags/hashes → `unknown`/`sha256:n/a`, sin panic.
- Watermark tras trim del buffer 10k (recorte del frente) → resync sin replay; repetir status con el mismo slice → 0 duplications.
- `mitm enable` con daemon falso vivo → la config se persiste igual (efectiva al reiniciar) Y avisa reinicio.
- `mitm enable` sin CA → falla en voz alta con `init-ca`, exit ≠ 0, sin tocar `mitm.json`.
- Tasa: 2ª notificación inmediata bloqueada; permitida tras ≥ 1 s.

## Límites y gaps declarados

- En el **working tree real** `cargo build --workspace` está ROTE por trabajo en curso de otro
  agente en `crates/cerberus-packs/` (`telemetry.rs` usa `reqwest`/`uuid` no declarados en ese
  `Cargo.toml` y una firma `is_root`/`OsString` mal tipada en `updater`). Todo lo de esta unidad se
  verificó en una **copiapejo del working tree** (rsync a `/var/folders/.../opencode/cerb-verify`)
  donde solo se añadieron esas deps, sin tocar los archivos reales de packs. Reportado como ajeno; no se revierte.
- `cerberus` (mi crate) está limpio ante `-D warnings` y fmt; los diffs de fmt ajenos quedan en
  `platform.rs` y `telemetry.rs` (no se tocan).
- No existe `/api/mitm` en caliente y NO se toca `cerberus-proxy/src/api.rs` (otro agente, F6/XSS):
  el wiring de MITM es por config + reinicio, no por control plane.
- Windows: `notify-rust` no está declarado (ya era así); el fallback imprime a stderr. No se ejecutó
  la matriz Windows (solo `aarch64-apple-darwin` instalado), igual que la unidad F4 `windows-support`.
- Ninguna notificación llamó a proveedores externos ni expuso secretos (solo hashes del evento).