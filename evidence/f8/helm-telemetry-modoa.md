# Evidence Pack — F8 / helm-telemetry (Modo A + telemetría opt-in)
- Unidad: `deploy/helm/cerberus/` + `crates/cerberus-packs/src/telemetry.rs`
- Revisor: Builder    Veredicto: PASS

## Alcance (solo estos archivos tocados)
- `deploy/helm/**` (chart completo, 12 archivos nuevos)
- `crates/cerberus-packs/src/telemetry.rs` (envío HTTP real opt-in)
- `crates/cerberus-packs/Cargo.toml` (`reqwest: blocking+default-tls`, `uuid: v4`)
- `Cargo.lock` (solo +reqwest +uuid en el entry cerberus-packs; ambos ya eran paquetes en el lock → sin descargas nuevas)
- `docs/f8-helm-telemetry.md` (notas F8)

## Part A — Helm (validado con helm 3.16.4 descargado a /tmp; no había helm en la máquina)

| Check | Resultado |
|---|---|
| `helm lint . --set 'config.admin.token=<30 chars>'` | 0 failed |
| `helm template cerberus .` | 5 docs (Secret/ConfigMap/Service/Deployment/Pod-test) |
| `config.yaml` resultante (pyyaml safe_load) | listen 0.0.0.0:8080, enforce, closed, 4 upstreams, telemetry off |
| `upstreams` anidado correctamente | `nindent 6` (gotcha: `indent 4` lo dejaba hermano → `upstreams: None`) |
| `helm template` sin `config.admin.token` | FALLA (required) — fail-closed |
| `helm template -f values-prod.yaml` | Ingress+TLS+annotations+resources OK |
| `helm lint` + `helm package` (tgz) | OK |
| pyyaml `safe_load_all` sobre render completo y sobre Chart/values/values-prod | OK |

Puntos de seguridad del chart:
- Deploy args `start --port 8080` + env `CERBERUS_LISTEN_HOST=0.0.0.0`; Service ClusterIP 8787→8080.
- Listener no-loopback exige admin token ≥24 bytes (crb-proxy `check_listen_security` proxy.rs:145): el chart obliga a `config.admin.token` vía `required` (patrón `{{- $tok := required ... }}`, que NO vuelca el valor al manifest).
- config.yaml montado en `/root/.cerberus/config.yaml` (configMap ro) + emptyDir runtime; `readOnlyRootFilesystem: true`.
- Hook test `cerberus-health` → `curl /health`.

## Part B — Telemetría

| Requisito | Estado |
|---|---|
| `enabled=false` (default) → cero red | `telemetry_disabled_no_http` (TcpListener sin conexión) |
| sin endpoint (config vacía / env vacío) → cero red | `telemetry_enabled_without_endpoint_skips_http` |
| `enabled=true` + endpoint → POST HTTP real | `telemetry_enabled_posts_to_endpoint` (mock TCP recibe el payload) |
| fallo silencioso (no bloquea) | `telemetry_enabled_http_failure_is_ok`, `send_simulated_fail_ok_when_disabled` |
| `install_id` uuid v4 persistente `~/.cerberus/install_id` | `id_default_persistent_in_tmp`, `install_id_is_persistent` |
| payload sin secretos (set exacto de claves + barrido) | `payload_has_no_secrets_fields` |
| `send_background` (hilo, no bloquea daemon) | implementado, guardado igual |

## Gauntlet §8B — verificación
| Comando | Salida | Resultado |
|---|---|---|
| `cargo test -p cerberus-packs --all-targets` | 65 passed; 0 failed | ✅ |
| `cargo test -p cerberus-packs --all-targets` x25 (race install_id) | 0/25 fallos tras fix | ✅ |
| `cargo clippy -p cerberus-packs --all-targets -- -D warnings` | No issues | ✅ |
| `cargo fmt --all -- --check` | No diffs | ✅ |
| `cargo build --workspace` | Finished (3 warnings preexistentes en cerberus bin) | ✅ |
| `cargo clippy --workspace --all-targets` | 7 errores PREEXISTENTES en `cerberus/src/{init,daemon,feedback_ux}.rs` (toolchain local 1.97 vs 1.85 pinneado) — ninguno mío ni en cerberus-packs | ⚠️ no mine |

## Nota issue
- Flakiness encontrada y corregida: `id_default_persistent_in_tmp` podía pisar el
  archivo install_id con tests concurrentes que creaban `Telemetry::new` sin el
  `ENV_LOCK` (race sobre `CERBERUS_INSTALL_ID_DIR`). Todos los tests que
  construyen `Telemetry` ahora serializan con `ENV_LOCK`.

## Deuda (net)
- Publicar imagen `ghcr.io/alexeirojas87/cerberus:0.1.0` (placeholder en values).
- Probar `helm install` real en cluster (viaje end-to-end + `helm test`).