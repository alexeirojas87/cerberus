# Gauntlet v6.1 — Contrato packs: trust root explícito + install por bytes

Ámbito de este worker: `cerberus-packs` (`updater.rs`, nuevo `wire.rs`),
`cerberus/src/cli_pack.rs` y tests de pack/CLI. **No se tocó** `daemon.rs`,
`api.rs`, `dashboard.html` ni `store.rs`. Sin commits.

Estado de la **corrida original de este worker**: `cargo test --workspace` →
474 passed; `cargo clippy --workspace --all-targets` limpio (workspace deniega
pedantic + nursery); `cargo fmt --check` limpio. Se conserva como historia.

Addendum final v6.1 (2026-08-21): la integración posterior también migró el
dashboard a selección de archivo + contenido wire v2 y centralizó la cota del
envelope HTTP. Estado final verificado: `cargo test --workspace` → **534
passed, 0 failed**; evidencia en
`evidence/f6/dashboard-pack-wire-v2-v61-fix.md`.

---

## 1. P0 — Bypass de boot en tier Free: eliminado

### El bug

`PackManager::new` leía `CERBERUS_PACK_TRUST_ROOT` **dentro del constructor** y
con ese root rehidrataba el manifest (`rebuild_active_set`), activando en el
engine todos los packs marcados activos. El daemon llama al constructor
*antes* del gate de licencia (`daemon.rs:300` vs. `daemon.rs:306`), y el gate
solo protegía `load_installed_from_dir`, que además era **no-op cuando el
manifest ya estaba cargado**. Resultado: `Free + CERBERUS_PACK_TRUST_ROOT +
manifest con pack activo` ⇒ los packs Pro ya estaban dentro del engine, sin
licencia.

### El cambio (API pública de `cerberus_packs::updater`)

```rust
pub enum PackTrustRoot { Disabled, Key(String) }      // Default = Disabled

impl PackTrustRoot {
    pub fn from_key(k: impl AsRef<str>) -> Self;        // vacío/blanco ⇒ Disabled
    pub fn from_optional_key(k: Option<impl AsRef<str>>) -> Self;
    pub fn gated_by_pro(self, is_pro: bool) -> Self;    // ← el gate de licencia
    pub const fn key(&self) -> Option<&str>;
    pub const fn is_enabled(&self) -> bool;
}

impl PackManager {
    // NUEVO camino explícito: nunca lee variables de entorno.
    pub fn open(dir, engine, trust_root: &PackTrustRoot) -> Result<Self, String>;

    // Legado: == open(.., &PackTrustRoot::Disabled); ya NO lee el env en boot.
    pub fn new(dir, engine) -> Result<Self, String>;

    // Activación post-gate desde el manifest, idempotente.
    pub async fn hydrate_from_manifest_with_root(&self, root_key: &str) -> Result<usize, String>;

    pub fn effective_trust_root(&self) -> Option<String>;
}
```

Invariantes garantizadas por tests:

- `open(..., Disabled)` y `new(...)` **ignoran** `CERBERUS_PACK_TRUST_ROOT`:
  engine base, `list_packs()` vacío, `effective_trust_root() == None`.
- El boot fail-closed **no degrada el manifest en disco** (el pack sigue
  marcado activo; nada se reescribe), así que el gate Pro puede activarlo
  después sin pérdida de estado.
- `hydrate_from_manifest_with_root` es idempotente: no añade entradas a
  `order` ni a `activation_sequence` (no reinstala JSONs — se conserva el fix
  FAIL-2), y deja el root como *efectivo* para que `rollback`/`uninstall`
  reconstruyan con verificación real.
- `load_installed_from_dir(root)` ya no es no-op con manifest presente:
  delega en `hydrate_from_manifest_with_root`. **Esto conserva el
  comportamiento Pro actual del daemon sin tocar `daemon.rs`.**
- `install()` en un manager abierto con `open()` **nunca** cae al env: falla
  con `no trust root configured`. El fallback al env sobrevive **solo** en el
  constructor legado `new()` (modo local de un proceso: el CLI sin daemon,
  donde `require_pro_for_pack_ops` corre inmediatamente antes de `install`).

### Test focalizado exigido

`updater::tests::free_tier_boot_with_trust_root_and_active_manifest_loads_zero_packs`
— disco con pack firmado + manifest activo + root válido:
`gated_by_pro(false)` ⇒ 0 reglas, 0 packs, manifest intacto; el **mismo disco**
con `gated_by_pro(true)` ⇒ 1 regla, 1 pack (control positivo).

Otros: `boot_ignores_global_env_trust_root`,
`pro_gate_hydrates_manifest_idempotently_after_failclosed_boot`,
`install_on_explicit_manager_never_falls_back_to_env`,
`trust_root_gate_semantics`.

### Lo que `daemon.rs` debe integrar (2 cambios)

1. **Boot** — sustituir el par «constructor + gate posterior» por un gate
   *previo* al constructor:

   ```rust
   let trust_root = PackTrustRoot::from_optional_key(env_nonempty("CERBERUS_PACK_TRUST_ROOT"))
       .gated_by_pro(license.is_pro());
   let packs_manager = PackManager::open(packs_dir(), base_engine, &trust_root)
       .map_err(|e| format!("packs setup error: {e}"))?;
   if !trust_root.is_enabled() {
       tracing::warn!("packs: sin trust root efectivo (Free o root ausente) — engine base, cero packs");
   }
   ```

   Con esto el bloque `if !license.is_pro() { … } else if let Some(root) = … {
   load_installed_from_dir(root) }` de `daemon.rs:306-315` queda redundante;
   puede eliminarse. Si se deja, sigue siendo correcto e idempotente.

2. **`open_packs_manager()`** (`daemon.rs:141`, modo local del CLI) — mantener
   `PackManager::new` es seguro (fail-closed) porque `pack_install` /
   `pack_rollback` ya hacen `require_pro_for_pack_ops` y luego
   `load_installed_from_dir(&root)`, que ahora sí hidrata. Lo recomendable a
   futuro es pasar el root explícito también aquí:
   `PackManager::open(packs_dir(), engine, &PackTrustRoot::from_optional_key(root).gated_by_pro(license.is_pro()))`,
   y así retirar el último fallback al env dentro de `install()`.

---

## 2. CLI → API: install por **bytes**, no por path

### El problema

`POST /api/packs/install` recibía `{"path": "<ruta del cliente>"}` y el worker
del daemon hacía `PackManager::load_pack_from_file(path)`. Eso (a) exigía
filesystem y cwd compartidos entre CLI y daemon (falso en Docker, con `sudo`,
o con el daemon remoto), y (b) convertía el control plane en un lector de
archivos arbitrarios del host bajo el token de admin.

### Nuevo contrato — `cerberus_packs::wire` (módulo nuevo, compartido)

```rust
pub const PACK_LIST_PATH: &str      = "/api/packs";
pub const PACK_INSTALL_PATH: &str   = "/api/packs/install";
pub const PACK_ROLLBACK_PATH: &str  = "/api/packs/rollback";
pub const PACK_WIRE_VERSION: u32    = 2;          // 1 = legado por path (retirado)
pub const MAX_PACK_BODY_BYTES: usize = 1 << 20;             // 1 MiB compartido
pub const MAX_PACK_BYTES: usize      = (MAX_PACK_BODY_BYTES - 1024) / 2;

pub struct PackInstallRequest {
    pub wire_version: u32,             // serde default = 2
    pub pack: String,                  // JSON completo del SignedRulePack
    pub origin_name: Option<String>,   // basename saneado, SOLO informativo
}
```

Body real: `{"wire_version":2,"pack":"<json del SignedRulePack>","origin_name":"demo.json"}`.

Helpers (cliente y servidor comparten el mismo código):

| Función | Lado | Qué garantiza |
|---|---|---|
| `PackInstallRequest::from_pack_bytes(&[u8], Option<&str>)` | CLI | tamaño ≤ `MAX_PACK_BYTES`, UTF-8, parsea como `SignedRulePack` completo, `origin_name` saneado |
| `to_body()` | CLI | serialización del body |
| `PackInstallRequest::parse_body(&[u8])` | **daemon/api** | fail-safe (ver abajo) |
| `signed_pack()` | daemon | `SignedRulePack` listo para `install_with_root` |
| `origin_label()` | daemon | etiqueta para logs (`<inline>` si no vino) |
| `sanitize_origin_name(&str)` | ambos | reduce a basename; descarta `.`, `..`, separadores, control chars, >128 chars |

`parse_body` rechaza, con error tipado y accionable: body vacío
(`Empty`), > 2·`MAX_PACK_BYTES`+1 KiB o `pack` > `MAX_PACK_BYTES` (`TooLarge`),
no UTF-8 (`NotUtf8`), JSON no-objeto / sin `pack` / pack incompleto
(`Malformed`), `wire_version != 2` (`UnsupportedVersion`), `origin_name` con
semántica de ruta (`Malformed`) y — explícitamente — la forma legada
`{"path": …}` con `LegacyPathRequest`, cuyo mensaje indica al operador que
actualice el CLI.

### CLI (ya implementado, `cli_pack.rs`)

`install()` canonicaliza el path **localmente** (`std::fs::canonicalize`,
resuelve relativos/`..`/symlinks contra el cwd del CLI), valida que sea un
archivo, comprueba tamaño, lee bytes, construye la request y hace POST a
`PACK_INSTALL_PATH`. Ningún componente de la ruta del cliente viaja: solo el
basename informativo. Los fallos locales (ausente, directorio, no-pack, vacío,
oversize) abortan **antes** de tocar la red.

### Lo que `api.rs` / `daemon.rs` deben integrar

1. `api.rs` — `PackCommand::Install` cambia de `path: String` a los bytes:

   ```rust
   Install { pack: String, origin_name: Option<String>, reply: … }
   // o, si se prefiere tipado fuerte:
   Install { request: cerberus_packs::wire::PackInstallRequest, reply: … }
   ```

   `handle_pack_install` sustituye el `body.get("path")` por:

   ```rust
   let req = match PackInstallRequest::parse_body(&body) {
       Ok(r) => r,
       Err(e) => return Ok(json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":{}}}"#, serde_json::to_string(&e.to_string()).unwrap_or_default()))),
   };
   ```

   `LegacyPathRequest` es el caso a devolver como `400` con su mensaje literal
   (es el que orienta al operador con un CLI viejo). `cerberus-proxy` necesita
   por tanto la dependencia `cerberus-packs` (hoy no la tiene) — alternativa
   sin nueva dependencia: mover `wire.rs` a `cerberus-core`. Recomiendo
   `cerberus-packs` tal cual: `wire` solo depende de `serde`, `serde_json` y
   `pack::SignedRulePack`.

2. `daemon.rs` — el worker deja de leer disco:

   ```rust
   PackCommand::Install { pack, origin_name, reply } => {
       let license = load_license(Some(&license_path()));
       let res = match require_pro_for_pack_ops(&license) {
           Err(e) => Err(format!("pack install aborted via control plane: {e}")),
           Ok(()) => match serde_json::from_str::<SignedRulePack>(&pack) {   // o req.signed_pack()
               Err(e) => Err(format!("pack inválido: {e}")),
               Ok(signed) => { /* install_with_root(signed, &root) + snapshot + swap */ }
           },
       };
   }
   ```

   El root debe venir del `PackTrustRoot` ya gateado del boot (o de
   `packs_worker_manager.effective_trust_root()`), no del env.
   `origin_name` solo para el log (`tracing::info!(pack = %req.origin_label(), …)`).

3. Límite de body (addendum final): `MAX_PACK_BODY_BYTES` (1 MiB) es la única
cota compartida por `wire::parse_body` y el colector del control plane.
`MAX_PACK_BYTES = (MAX_PACK_BODY_BYTES - 1024) / 2` (511.5 KiB) reserva el
envelope y su escapado; un test cross-crate exige
`2·MAX_PACK_BYTES + 1024 <= CONTROL_PLANE_MAX_BYTES`, evitando que ambas cotas
puedan divergir en silencio.

---

## 3. Descubrimiento del endpoint efectivo

El CLI deducía el puerto de `CERBERUS_LISTEN` o del `listen` de
`config.yaml`; si el daemon liga otro puerto (efímero, `0.0.0.0` en Docker, o
config editada en caliente), el CLI hablaba al puerto equivocado.

Estructuras auxiliares nuevas (`cerberus_packs::wire`), listas para que el
daemon las use sin que este worker lo edite:

```rust
pub const ENDPOINT_FILE: &str = "endpoint.json";   // en config_dir(), junto al pid file

pub struct ControlPlaneEndpoint { pub listen: String, pub port: u16, pub pid: u32 }
impl ControlPlaneEndpoint {
    pub fn new(listen: &str, pid: u32) -> Result<Self, PackWireError>; // exige puerto válido
    pub fn to_json(&self) -> Result<String, PackWireError>;
    pub fn from_json(&str) -> Result<Self, PackWireError>;             // rechaza puerto 0
    pub fn loopback_base_url(&self) -> String;                         // SIEMPRE 127.0.0.1
}
pub fn port_from_listen(listen: &str) -> Option<u16>;                  // soporta [::1]:8787
```

Lado CLI (implementado): `resolve_endpoint() -> ResolvedEndpoint { port, source }`
con precedencia **env `CERBERUS_LISTEN` > `~/.cerberus/endpoint.json` >
`listen` de `config.yaml` > 8787**. Un descriptor ausente o corrupto degrada
al siguiente nivel con un aviso en stderr, nunca aborta. La URL siempre es
loopback aunque el descriptor publique `0.0.0.0`.

**Pendiente en `daemon.rs`** (una escritura y un borrado):

- tras ligar el listener, escribir atómicamente (temp + rename, junto al pid
  file) `ControlPlaneEndpoint::new(&listen_real, std::process::id())?.to_json()`
  en `config_dir().join(ENDPOINT_FILE)`;
- borrarlo en el shutdown graceful (el mismo sitio donde se borra el pid
  file). El campo `pid` permite al CLI detectar descriptores rancios si más
  adelante se quiere validar (`process_alive(ep.pid)`).

---

## 4. Archivos modificados y tests añadidos

| Archivo | Cambio |
|---|---|
| `crates/cerberus-packs/src/wire.rs` | **nuevo** — contrato de cable + endpoint descriptor + 8 tests |
| `crates/cerberus-packs/src/lib.rs` | `pub mod wire;` |
| `crates/cerberus-packs/src/updater.rs` | `PackTrustRoot`, `open`, `open_inner`, `effective_trust_root`, `hydrate_from_manifest_with_root`, `new`/`install` sin env en boot; 5 tests nuevos |
| `crates/cerberus/src/cli_pack.rs` | install por bytes, canonicalización local, `resolve_endpoint`; 4 tests nuevos |
| `crates/cerberus/tests/pack_cli_via_api.rs` | el test de modo API exige bytes y **prohíbe** que la ruta viaje; + 2 tests (fail-safe sin red, descubrimiento por descriptor) |

Tests nuevos: 19 (8 wire, 5 updater, 4 cli_pack unit, 2 integración CLI). 
