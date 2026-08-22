# Evidence Pack — f7/license-daemon-wiring

- Unidad: Conexión de licensing (F7) al producto (daemon + CLI) — fix code review **item 12**
- Intento: 1    Revisor: builder (integr.)    Veredicto: PASS

## Qué conecta

`LicenseManager` y `PackManager` (cerberus-packs) quedan vivos en el arranque del daemon y en un
comando CLI, sin tocar `cerberus-proxy` (contrato respetado):

- `daemon::start()`: carga la licencia desde `CERBERUS_LICENSE_PATH` o `~/.cerberus/license.json`
  vía `LicenseManager::from_file`; ante fallo de verificación **logua WARN y sigue con
  `LicenseManager::free()`** (fail-open del producto: la licencia gate features Pro, nunca el
  motor / open-core §7). Expone `Arc<LicenseManager>`.
- `PackManager` creado en `~/.cerberus/packs` (dir auto-creado) con engine inicial = mismo ruleset;
  **no** autocarga packs (sin trust registry aún) y loguea su presencia y conteo.
- Comando `cerberus license` imprime `tier`, estado de expiración y features.
- `license_summary` emite `tier=pro|free` machine-readable (usado por tests y logs).

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida (citada) | Resultado |
|---|---|---|---|
| Build workspace OK | `cargo build --workspace` | `Finished dev profile [unoptimized + debuginfo] in 1.83s` | ✅ |
| Tests crate (unit + integración CLI) | `cargo test -p cerberus --all-targets` | `24 passed (1 suite...)` y `test result: ok. 2 passed; 0 failed` | ✅ (26 total) |
| fmt | `cargo fmt --all -- --check` | sin diff (exit 0) | ✅ |
| Clippy `-D warnings` | `cargo clippy --workspace --all-targets -- -D warnings` | `cargo clippy: No issues found` | ✅ |

## F7 conectado (evidencia de producto)

1. **Binario real, `cerberus license`, licencia firmada Pro** (firmada con Ed25519/openssl y root
   por env):

```
Licencia cargada desde: /tmp/cerberus_demo.YzTEJ8/signed.json
tier=pro state=valid
Licencia: Pro
Email: ev@cerberus.dev
ID: demo-1
Expira: perpetua
Features: dashboard, alerts, premium_packs, rule_editor, team_policies, multi_channel_alerts
```

2. **Same binario, firma/root ausente → fail-open, exit 0 (no cae)**:

```
 WARN license load failed (license verification impossible: ...); continuing with Free tier (fail-open) ...
tier=free state=valid
```

3. **Arranque real del daemon (`cerberus start`) con `CERBERUS_LICENSE_PATH` → `tier=pro` en los
   logs de arranque y PackManager listo:**

```
INFO license: loaded from /tmp/cerberus_demo.YzTEJ8/signed.json —
tier=pro state=valid
Licencia: Pro
...
INFO packs: manager ready at /Users/alexeirojas/.cerberus/packs (0 packs installed; auto-load deferred...)
Cerberus proxy corriendo en 127.0.0.1:18787
Cerberus iniciado en 127.0.0.1:18787
```

4. **Tests automatizados (lo que mantiene el gate):**
   - Unidad en `crates/cerberus/src/daemon.rs`: `license_wired_from_signed_file_at_boot`,
     `license_without_file_falls_back_to_free`, `packs_dir_is_under_config_dir`.
   - CLI en `crates/cerberus/tests/license_cli_integration.rs`: `cli_license_activates_pro_from_signed_file`,
     `cli_license_falls_back_to_free_without_trust_root` (ejecutan el binario real via
     `CARGO_BIN_EXE_cerberus`).

Salida: `cargo test -p cerberus --all-targets` →
`test result: ok. 24 passed; 0 failed` (unit) y `test result: ok. 2 passed; 0 failed` (integration).

## Casos adversariales (intento de romper)

- JSON plano (sin firma) → `LicenseManager::from_file` lo rechaza → `tier=free`, exit 0 (fail-open honesto, no product-crash).
- Firma válida pero trust root NO configurada → WARN + `tier=free`, exit 0.
- Archivo inexistente → `tier=free`, exit 0.
- Sin `CERBERUS_LICENSE_PATH`, default `~/.cerberus/license.json` (ausente) → `tier=free`.

## Archivos tocados (alcance item 12)

- `crates/cerberus/Cargo.toml` — dep `cerberus-packs` + dev-deps `ed25519-dalek`, `hex`
  (enabler mínimo: el daemon importa cerberus-packs).
- `crates/cerberus/src/daemon.rs` — `license_path`, `load_license` (fail-open), `license_summary`,
  `packs_dir`, wiring en `start()`, tests.
- `crates/cerberus/src/main.rs` — comando `cerberus license`.
- `crates/cerberus/tests/license_cli_integration.rs` — test CLI de integración.

**NO** se tocaron `crates/cerberus-proxy/*` ni `health.rs` (fuera de alcance). El gate por feature
queda como documentado: control-plane posterior; health sin cambios.