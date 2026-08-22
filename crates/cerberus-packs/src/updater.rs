//! Auto-update mechanism for rule packs.
//!
//! Soporta:
//! - Download de packs desde URLs
//! - Verificación de firma antes de cargar
//! - Hot-reload del engine con nuevo pack
//! - Rollback al pack anterior
//! - Ownership de reglas por pack + manifest durable (`manifest.json`)
//!   como fuente de verdad del estado instalado/activo (fix code review v5).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cerberus_engine::engine::{CompiledEngine, EngineBuilder};
use cerberus_engine::rule::Rule;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::pack::{PackMetadata, RulePack, SignedRulePack};

/// Nombre del archivo de manifest que persiste el estado instalado.
const MANIFEST_FILE: &str = "manifest.json";

/// Versiones por pack registradas en el manifest.
///
/// `installed` es la última versión conocida en disco; `active` es la versión
/// que aporta reglas al engine ("" si ninguna está activa).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackVersions {
    /// Última versión instalada-en-disco para este pack.
    pub installed: String,
    /// Versión activa (reglas en el engine), "" si no hay activa.
    pub active: String,
}

/// Manifest durable del estado instalado (fix code review v5).
///
/// Es la fuente de verdad del `PackManager`: se lee al abrir (`new`) y se
/// reescribe en cada `install` / `rollback` / `uninstall`. Registra, por pack
/// y versión, el ownership de reglas y cuáles están activas en el engine.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackManifest {
    /// Versiones conocidas `"<pack>@<version>"`, ordenadas por (nombre, versión).
    pub order: Vec<String>,
    /// ¿Está activa cada `"<pack>@<version>"`? Solo las activas aportan reglas.
    pub active: HashMap<String, bool>,
    /// Por pack: última versión en disco y versión activa.
    pub versions_by_pack: HashMap<String, PackVersions>,
    /// Secuencia de activaciones, en orden, para resolver el rollback (campo
    /// aditivo; ausente en manifests escritos por versiones previas).
    #[serde(default)]
    pub activation_sequence: Vec<String>,
}

/// Estado de un pack instalado.
#[derive(Debug, Clone)]
pub struct InstalledPack {
    /// Metadatos del pack.
    pub metadata: PackMetadata,
    /// JSON del pack (para rollback).
    pub pack_json: String,
    /// Firma Ed25519 en hex (persistida junto al pack, revisión 2 P1 #4).
    pub signature_hex: Option<String>,
    /// Clave pública del firmante (procedencia persistida).
    pub signer_public_key_hex: Option<String>,
    /// ¿Está activo actualmente?
    pub active: bool,
}

/// Estado interno (bajo `state`) del gestor.
#[derive(Debug, Clone)]
struct ManagerState {
    manifest: PackManifest,
    installed: HashMap<String, InstalledPack>,
}

/// Trust root de rule packs, provisto **explícitamente** por el caller.
///
/// [P0 v6.1] El `PackManager` ya NO lee `CERBERUS_PACK_TRUST_ROOT` en el boot:
/// hacerlo dejaba un bypass del gate de licencia. El daemon abría el manager
/// (que rehidrataba del manifest usando el root global) y solo DESPUÉS
/// comprobaba la licencia; en tier Free con un manifest activo los packs ya
/// estaban dentro del engine. Ahora el root entra por parámetro y el caller lo
/// condiciona a la licencia con [`PackTrustRoot::gated_by_pro`]: sin Pro el
/// valor es [`PackTrustRoot::Disabled`] y NINGÚN pack se activa.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PackTrustRoot {
    /// Sin trust root: fail-closed, cero packs (engine base).
    #[default]
    Disabled,
    /// Clave pública raíz (Ed25519, hex) contra la que se verifica cada pack.
    Key(String),
}

impl PackTrustRoot {
    /// Trust root desde una clave; vacía o en blanco ⇒ [`Self::Disabled`].
    #[must_use]
    pub fn from_key(key: impl AsRef<str>) -> Self {
        let key = key.as_ref().trim();
        if key.is_empty() {
            Self::Disabled
        } else {
            Self::Key(key.to_string())
        }
    }

    /// Trust root desde un valor opcional de configuración.
    #[must_use]
    pub fn from_optional_key(key: Option<impl AsRef<str>>) -> Self {
        key.map_or(Self::Disabled, Self::from_key)
    }

    /// Gate de licencia: solo tier Pro puede activar rule packs (open-core).
    ///
    /// Aplicar SIEMPRE antes de pasar el root al `PackManager`; en Free el
    /// resultado es [`Self::Disabled`] y el manager arranca con el engine base.
    #[must_use]
    pub fn gated_by_pro(self, is_pro: bool) -> Self {
        if is_pro {
            self
        } else {
            Self::Disabled
        }
    }

    /// La clave, si el trust root está habilitado.
    #[must_use]
    pub const fn key(&self) -> Option<&str> {
        match self {
            Self::Disabled => None,
            Self::Key(k) => Some(k.as_str()),
        }
    }

    /// ¿Hay trust root (y por tanto los packs pueden verificarse)?
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Key(_))
    }
}

/// Gestor de packs con soporte de rollback persistente.
pub struct PackManager {
    /// Directorio donde se almacenan los packs.
    pack_dir: PathBuf,
    /// Reglas base (propias del engine, antes de packs) — orden determinista.
    base_rules: Vec<Rule>,
    /// Estado mutable: manifest durable + packs activos.
    state: Arc<Mutex<ManagerState>>,
    /// Engine activo actual.
    active_engine: Arc<Mutex<CompiledEngine>>,
    /// Trust root EFECTIVO para operaciones post-gate (rollback, uninstall,
    /// reconstrucciones). Se fija con el root explícito de [`PackManager::open`]
    /// y se actualiza con el root que aporte cada operación ya autorizada
    /// (`install_with_root`, `hydrate_from_manifest_with_root`). Nunca sale de
    /// una variable de entorno.
    trust_root: std::sync::RwLock<Option<String>>,
    /// ¿Puede [`PackManager::install`] caer al env `CERBERUS_PACK_TRUST_ROOT`?
    ///
    /// Solo `true` en el constructor legado [`PackManager::new`], que usa el
    /// modo local de un solo proceso (el CLI sin daemon) donde el gate de
    /// licencia ya corrió antes de llamar a `install`. El camino explícito
    /// ([`PackManager::open`]) nunca consulta el entorno.
    allow_env_install_root: bool,
}

/// Devolver la clave `"<name>@<version>"` de un `(pack, version)`.
fn versioned_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

/// Separar una clave `"<name>@<version>"` en sus partes.
fn parse_versioned_key(key: &str) -> (String, String) {
    key.find('@').map_or_else(
        || (key.to_string(), String::new()),
        |at| (key[..at].to_string(), key[at + 1..].to_string()),
    )
}

/// Nombre de archivo versionado para un pack (historial por versión).
fn versioned_file_name(name: &str, version: &str) -> String {
    format!("pack_{name}-v{version}.json")
}

/// Parsear las reglas de un pack desde su JSON interno.
///
/// # Errors
///
/// Devuelve error si el JSON del pack no es un `RulePack` válido.
fn rules_from_pack_json(json: &str) -> Result<Vec<Rule>, String> {
    match RulePack::from_json(json) {
        Ok(pack) => Ok(pack.rules),
        Err(e) => Err(format!("cannot parse owned pack rules: {e}")),
    }
}

/// Orden determinista de las reglas: base primero, luego cada pack activo
/// ordenado por (nombre, versión).
fn assemble_rules(base_rules: &[Rule], packs: &[(String, String, Vec<Rule>)]) -> Vec<Rule> {
    let mut packs: Vec<&(String, String, Vec<Rule>)> = packs.iter().collect();
    packs.sort_by(|a, b| {
        let by_name = a.0.cmp(&b.0);
        by_name.then_with(|| a.1.cmp(&b.1))
    });
    let mut out = base_rules.to_vec();
    for (_, _, rules) in packs {
        for rule in rules {
            out.push(rule.clone());
        }
    }
    out
}

/// Cargar el pack firmado activo para `(name, version)` desde disco, con
/// fallback al nombre plano legado (`<name>.json`).
fn load_signed_from_dir(dir: &Path, name: &str, version: &str) -> Option<SignedRulePack> {
    let versioned = dir.join(format!("pack_{name}-v{version}.json"));
    let legacy = dir.join(format!("{name}.json"));
    let path = if versioned.exists() { versioned } else { legacy };
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str::<SignedRulePack>(&content).ok()
}

impl PackManager {
    /// Crear un `PackManager` **sin** trust root (fail-closed).
    ///
    /// Equivale a `open(pack_dir, engine, &PackTrustRoot::Disabled)`: lee el
    /// manifest para preservar el historial, pero NO activa ningún pack (el
    /// engine queda en las reglas base). [P0 v6.1] Este constructor ya NO
    /// consulta `CERBERUS_PACK_TRUST_ROOT`; para hidratar packs hay que pasar
    /// un root explícito ya condicionado por licencia (véase
    /// [`PackTrustRoot::gated_by_pro`]).
    ///
    /// Conserva el fallback al env SOLO en [`Self::install`], para el modo
    /// local de un proceso (CLI sin daemon), donde el gate de licencia corre
    /// en el caller inmediatamente antes.
    ///
    /// # Errors
    ///
    /// Devuelve error si no se puede crear el directorio de packs.
    pub fn new(pack_dir: impl AsRef<Path>, initial_engine: CompiledEngine) -> Result<Self, String> {
        Self::open_inner(pack_dir, initial_engine, &PackTrustRoot::Disabled, true)
    }

    /// Abrir un `PackManager` con un trust root EXPLÍCITO.
    ///
    /// Si el trust root está habilitado y existe `manifest.json`, reconstruye
    /// el engine activo en el orden guardado (base + packs activos ordenados
    /// por nombre/versión), verificando cada pack contra `trust_root`, y
    /// rehidrata `installed`. Con [`PackTrustRoot::Disabled`] el manifest se
    /// carga como historial pero el engine arranca en base y `installed` queda
    /// vacío: es el camino Free (cero packs).
    ///
    /// Este constructor NUNCA lee variables de entorno: el caller resuelve el
    /// root desde su configuración confiable y lo condiciona a la licencia.
    ///
    /// # Errors
    ///
    /// Devuelve error si no se puede crear el directorio de packs.
    pub fn open(
        pack_dir: impl AsRef<Path>,
        initial_engine: CompiledEngine,
        trust_root: &PackTrustRoot,
    ) -> Result<Self, String> {
        Self::open_inner(pack_dir, initial_engine, trust_root, false)
    }

    /// Implementación compartida de [`Self::new`] y [`Self::open`].
    fn open_inner(
        pack_dir: impl AsRef<Path>,
        initial_engine: CompiledEngine,
        trust_root: &PackTrustRoot,
        allow_env_install_root: bool,
    ) -> Result<Self, String> {
        let dir = pack_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create pack dir: {e}"))?;

        let base_rules = initial_engine.rules().to_vec();
        let manifest_path = dir.join(MANIFEST_FILE);

        let mut manifest = PackManifest::default();
        let mut start_engine = initial_engine;
        let mut installed: HashMap<String, InstalledPack> = HashMap::new();

        let root = trust_root.key().map(ToString::to_string);

        if manifest_path.exists() {
            match Self::load_manifest(&dir) {
                Ok(mut m) => match rebuild_active_set(&mut m, &dir, &base_rules, root.as_deref()) {
                    Ok((engine, replay_installed)) => {
                        tracing::info!(
                            "packs: manifest loaded from {} ({} active packs)",
                            manifest_path.display(),
                            replay_installed.len()
                        );
                        manifest = m;
                        start_engine = engine;
                        installed = replay_installed;
                    }
                    Err(e) => {
                        tracing::warn!("packs: manifest rebuild failed ({e}); starting from base engine");
                    }
                },
                Err(e) => {
                    tracing::warn!("packs: invalid manifest ({e}); starting from base engine");
                }
            }
        }

        Ok(Self {
            pack_dir: dir,
            base_rules,
            trust_root: std::sync::RwLock::new(root),
            allow_env_install_root,
            state: Arc::new(Mutex::new(ManagerState { manifest, installed })),
            active_engine: Arc::new(Mutex::new(start_engine)),
        })
    }

    /// Trust root efectivo actual (copia), si hay alguno.
    #[must_use]
    pub fn effective_trust_root(&self) -> Option<String> {
        self.trust_root
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Fijar el trust root efectivo tras una operación ya autorizada.
    fn remember_trust_root(&self, root: &str) {
        let mut guard = self
            .trust_root
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(root.to_string());
    }

    /// Cargar el manifest desde `pack_dir` si existe, o un manifest vacío.
    ///
    /// # Errors
    ///
    /// Devuelve error si `manifest.json` existe pero no es un JSON válido.
    fn load_manifest(dir: &Path) -> Result<PackManifest, String> {
        let path = dir.join(MANIFEST_FILE);
        if !path.exists() {
            return Ok(PackManifest::default());
        }
        let content = std::fs::read_to_string(&path).map_err(|e| format!("cannot read manifest: {e}"))?;
        serde_json::from_str::<PackManifest>(&content).map_err(|e| format!("invalid manifest: {e}"))
    }

    /// Persistir el manifest en `pack_dir` (escritura temp + rename).
    ///
    /// # Errors
    ///
    /// Devuelve error si no se puede escribir o renombrar el archivo.
    fn persist_manifest(dir: &Path, manifest: &PackManifest) -> Result<(), String> {
        let json = serde_json::to_string(manifest).map_err(|e| format!("cannot serialize manifest: {e}"))?;
        let path = dir.join(MANIFEST_FILE);
        let tmp = dir.join(format!("{MANIFEST_FILE}.tmp"));
        std::fs::write(&tmp, json).map_err(|e| format!("cannot write manifest: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("cannot commit manifest: {e}"))
    }

    /// Instalar un pack desde un `SignedRulePack`.
    ///
    /// Verifica la firma contra el trust root EFECTIVO del manager (el de
    /// [`Self::open`], o el de la última operación autorizada). Solo el
    /// constructor legado [`Self::new`] admite, como último recurso, el env
    /// `CERBERUS_PACK_TRUST_ROOT` (modo local de un proceso, ya gateado por el
    /// caller). Fail-closed: sin root, error. Compila las reglas y
    /// actualiza el engine activo. Para un root explícito resolverlo y usar
    /// [`Self::install_with_root`].
    ///
    /// # Errors
    ///
    /// Devuelve error si no hay trust root, la firma es inválida o las reglas
    /// no compilan.
    pub async fn install(&self, signed: SignedRulePack) -> Result<(), String> {
        let root = self.effective_trust_root().or_else(|| {
            if self.allow_env_install_root {
                std::env::var("CERBERUS_PACK_TRUST_ROOT").ok().filter(|r| !r.is_empty())
            } else {
                None
            }
        });
        let Some(root) = root else {
            return Err(
                "pack install aborted: no trust root configured (set CERBERUS_PACK_TRUST_ROOT or use install_with_root)"
                    .to_string(),
            );
        };
        self.install_with_root(signed, &root).await
    }

    /// Instalar un pack verificando contra una clave raíz de confianza
    /// EXPLÍCITA (provista por el caller desde su config confiable).
    ///
    /// Las reglas del pack reemplazan las propietarias de la versión anterior
    /// del MISMO pack (`pack_name`); el engine se reconstruye de forma
    /// determinista (base + packs activos ordenados por nombre/versión). El
    /// resto de rule packs NO pierde reglas. El resultado se persiste en el
    /// manifest y en un archivo versionado `pack_<name>-v<ver>.json` (la
    /// versión antigua queda como historial con `active: false`).
    ///
    /// Un fallo de compilación o de escritura deja el engine y el manifest
    /// intactos (atomicidad).
    ///
    /// # Errors
    ///
    /// Devuelve error si la firma es inválida, no coincide con `root_key`, las
    /// reglas no compilan, o falla la persistencia.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn install_with_root(&self, signed: SignedRulePack, root_key: &str) -> Result<(), String> {
        let pack = signed.extract_with_root(root_key)?;
        // Root ya autorizado por el caller: queda como root efectivo para las
        // reconstrucciones posteriores (rollback/uninstall) de este manager.
        self.remember_trust_root(root_key);
        let name = pack.metadata.name.clone();
        let version = pack.metadata.version.clone();
        let rules = pack.rules.clone();

        let mut state = self.state.lock().await;
        let mut manifest = state.manifest.clone();
        let prev_active = manifest
            .versions_by_pack
            .get(&name)
            .map(|v| v.active.clone())
            .unwrap_or_default();
        let is_new_version = prev_active != version;

        // Candidato del engine con reemplazo de ownership (guard atómico):
        // si compilar falla no se toca nada (engine + manifest + disco).
        let mut entries: Vec<(String, String, Vec<Rule>)> = Vec::new();
        for (n, p) in &state.installed {
            if !p.active || n == &name {
                continue;
            }
            let nrules = match rules_from_pack_json(&p.pack_json) {
                Ok(r) => r,
                Err(e) => return Err(format!("pack {n} corrupt: {e}")),
            };
            entries.push((n.clone(), p.metadata.version.clone(), nrules));
        }
        entries.push((name.clone(), version.clone(), rules));
        let new_engine = EngineBuilder::new(&assemble_rules(&self.base_rules, &entries))
            .build()
            .map_err(|e| format!("engine build error for {name} v{version}: {e}"))?;

        // Escritura del JSON versionado (solo tras compilar OK).
        let signed_json = serde_json::to_string(&signed).map_err(|e| format!("cannot serialize signed pack: {e}"))?;
        let pack_path = self.pack_dir.join(versioned_file_name(&name, &version));
        std::fs::write(&pack_path, signed_json).map_err(|e| format!("cannot write pack: {e}"))?;

        // Manifest: deactivar la versión activa previa del MISMO pack y activar la nueva.
        let key = versioned_key(&name, &version);
        if !prev_active.is_empty() && prev_active != version {
            manifest.active.insert(versioned_key(&name, &prev_active), false);
        }
        if !manifest.order.contains(&key) {
            manifest.order.push(key.clone());
        }
        manifest.order.sort_by(|a, b| {
            let (na, va) = parse_versioned_key(a.as_str());
            let (nb, vb) = parse_versioned_key(b.as_str());
            na.cmp(&nb).then_with(|| va.cmp(&vb))
        });
        manifest.active.insert(key.clone(), true);
        manifest.versions_by_pack.insert(
            name.clone(),
            PackVersions {
                installed: version.clone(),
                active: version.clone(),
            },
        );
        if is_new_version {
            manifest.activation_sequence.push(key.clone());
        }
        Self::persist_manifest(&self.pack_dir, &manifest)?;

        // Swap in-memory + engine vivo.
        state.installed.insert(
            name.clone(),
            InstalledPack {
                metadata: pack.metadata,
                pack_json: signed.pack_json.clone(),
                signature_hex: Some(signed.signature_hex.clone()),
                signer_public_key_hex: Some(signed.signer_public_key_hex.clone()),
                active: true,
            },
        );
        state.manifest = manifest;
        *self.active_engine.lock().await = new_engine;

        tracing::info!("pack installed: {name} v{version}");
        Ok(())
    }

    /// Hacer rollback al engine anterior, PERSISTENTE y repetible tras
    /// reinicio: deactiva la última activación grabada en el manifest, la
    /// persiste y reconstruye el engine vivo desde el manifest resultante.
    ///
    /// # Errors
    ///
    /// Devuelve error si no hay historial de activaciones que revertir o si la
    /// reconstrucción/persistencia falla.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn rollback(&self) -> Result<(), String> {
        let mut state = self.state.lock().await;
        let mut manifest = state.manifest.clone();
        let last = manifest
            .activation_sequence
            .pop()
            .ok_or_else(|| "no history to rollback".to_string())?;
        let (name, ver) = parse_versioned_key(&last);
        if ver.is_empty() {
            return Err(format!("corrupt activation entry in manifest: {last}"));
        }

        // Versión previa activa del MISMO pack (si la hay) para restaurar.
        let prev_key = manifest
            .activation_sequence
            .iter()
            .rev()
            .find(|k| parse_versioned_key(k.as_str()).0 == name)
            .cloned();

        manifest.active.insert(versioned_key(&name, &ver), false);
        let new_active = if let Some(pk) = prev_key {
            let (pn, pv) = parse_versioned_key(pk.as_str());
            manifest.active.insert(versioned_key(&pn, &pv), true);
            pv
        } else {
            String::new()
        };
        if let Some(vm) = manifest.versions_by_pack.get_mut(&name) {
            vm.active = new_active;
        }

        let (engine, installed) = match rebuild_active_set(
            &mut manifest,
            &self.pack_dir,
            &self.base_rules,
            self.effective_trust_root().as_deref(),
        ) {
            Ok(x) => x,
            Err(e) => return Err(format!("rollback rebuild failed: {e}")),
        };
        Self::persist_manifest(&self.pack_dir, &manifest)?;

        state.installed = installed;
        state.manifest = manifest;
        *self.active_engine.lock().await = engine;

        tracing::info!("pack rollback executed: deactivated {last}");
        Ok(())
    }

    /// Desinstalar un pack por nombre: lo deactiva en el manifest (persistiendo
    /// el cambio) y reconstruye el engine vivo sin sus reglas. Su JSON se
    /// conserva como historial con `active: false`.
    ///
    /// # Errors
    ///
    /// Devuelve error si el pack no tiene versión activa o si la reconstrucción/
    /// persistencia falla.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn uninstall(&self, pack_name: &str) -> Result<(), String> {
        let mut state = self.state.lock().await;
        let mut manifest = state.manifest.clone();
        let active_ver = manifest
            .versions_by_pack
            .get(pack_name)
            .map(|v| v.active.clone())
            .unwrap_or_default();
        if active_ver.is_empty() {
            return Err(format!("no active version of pack '{pack_name}' to uninstall"));
        }

        let key = versioned_key(pack_name, &active_ver);
        manifest.active.insert(key.clone(), false);
        if let Some(vm) = manifest.versions_by_pack.get_mut(pack_name) {
            vm.active = String::new();
        }
        manifest
            .activation_sequence
            .retain(|k| !k.as_str().eq_ignore_ascii_case(&key));

        let (engine, installed) = match rebuild_active_set(
            &mut manifest,
            &self.pack_dir,
            &self.base_rules,
            self.effective_trust_root().as_deref(),
        ) {
            Ok(x) => x,
            Err(e) => return Err(format!("uninstall rebuild failed: {e}")),
        };
        Self::persist_manifest(&self.pack_dir, &manifest)?;

        state.installed = installed;
        state.manifest = manifest;
        *self.active_engine.lock().await = engine;
        tracing::info!("pack uninstalled: {pack_name}");
        Ok(())
    }

    /// Obtener el engine activo.
    #[must_use]
    pub fn engine(&self) -> Arc<Mutex<CompiledEngine>> {
        Arc::clone(&self.active_engine)
    }

    /// Snapshot del engine activo como `CompiledEngine` de propiedad (fix
    /// review v4, hallazgo 7): `CompiledEngine` no es `Clone`, así que quien
    /// necesita una copia por valor (p.ej. el `ProxyContext` del daemon, que
    /// usa `Arc<CompiledEngine>`) la obtiene recompilando desde las reglas
    /// activas. Como la compilación es una función pura de las reglas, el
    /// snapshot es equivalente al activo.
    ///
    /// `payload_secret` se re-aplica al snapshot si el caller lo usa en su
    /// engine base (HMAC-SHA256, P1-12).
    ///
    /// # Errors
    ///
    /// Devuelve error si la recompilación de las reglas activas falla.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn snapshot_engine(&self, payload_secret: Option<&[u8]>) -> Result<CompiledEngine, String> {
        let active = self.active_engine.lock().await;
        let mut builder = EngineBuilder::new(active.rules());
        if let Some(secret) = payload_secret {
            builder = builder.with_payload_secret(secret.to_vec());
        }
        builder.build().map_err(|e| format!("snapshot engine build error: {e}"))
    }

    /// Listar packs instalados (solo los activos).
    #[must_use]
    pub async fn list_packs(&self) -> Vec<InstalledPack> {
        let state = self.state.lock().await;
        state.installed.values().cloned().collect()
    }

    /// Reglas que aporta el pack `pack_name` (versión activa) al engine.
    ///
    /// Devuelve un slice vacío si el pack no está activo.
    #[must_use]
    pub async fn pack_owned_rules(&self, pack_name: &str) -> Vec<Rule> {
        let state = self.state.lock().await;
        state
            .installed
            .get(pack_name)
            .filter(|p| p.active)
            .and_then(|p| rules_from_pack_json(&p.pack_json).ok())
            .unwrap_or_default()
    }

    /// Reconstruir el «engine del manifest»: base + packs activos del manifest,
    /// en orden determinista (por nombre/versión), sin tocar el estado.
    ///
    /// # Errors
    ///
    /// Devuelve error si algún pack activo referenciado no se puede leer o
    /// compilar.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn engine_from_manifest(&self) -> Result<CompiledEngine, String> {
        let state = self.state.lock().await;
        let mut manifest = state.manifest.clone();
        match rebuild_active_set(
            &mut manifest,
            &self.pack_dir,
            &self.base_rules,
            self.effective_trust_root().as_deref(),
        ) {
            Ok((engine, _installed)) => Ok(engine),
            Err(e) => Err(e),
        }
    }

    /// Leer el manifest persistido actual (copia) — para inspección/compat.
    #[must_use]
    pub async fn manifest_snapshot(&self) -> PackManifest {
        let state = self.state.lock().await;
        state.manifest.clone()
    }

    /// Cargar un pack desde un archivo JSON.
    ///
    /// # Errors
    ///
    /// Devuelve error si el archivo no existe o no es válido.
    pub fn load_pack_from_file(path: impl AsRef<Path>) -> Result<SignedRulePack, String> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| format!("cannot read pack file: {e}"))?;
        serde_json::from_str::<SignedRulePack>(&content).map_err(|e| format!("invalid signed pack: {e}"))
    }

    /// Cargar múltiples packs desde un directorio (ignora `manifest.json`).
    ///
    /// # Errors
    ///
    /// Devuelve error si algún pack no se puede cargar (los no parseables se
    /// loguean y se saltan).
    pub fn load_packs_from_dir(dir: impl AsRef<Path>) -> Result<Vec<SignedRulePack>, String> {
        let mut packs = Vec::new();
        let dir = dir.as_ref();

        if !dir.is_dir() {
            return Ok(packs);
        }

        for entry in std::fs::read_dir(dir).map_err(|e| format!("cannot read dir: {e}"))? {
            let entry = entry.map_err(|e| format!("dir entry error: {e}"))?;
            let path = entry.path();
            let is_manifest = path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == MANIFEST_FILE);
            if !is_manifest && path.extension().is_some_and(|ext| ext == "json") {
                match Self::load_pack_from_file(&path) {
                    Ok(pack) => packs.push(pack),
                    Err(e) => tracing::warn!("skipping pack {}: {e}", path.display()),
                }
            }
        }

        Ok(packs)
    }

    /// Activar, con un `root_key` EXPLÍCITO y ya autorizado por licencia, los
    /// packs que el manifest marca como activos.
    ///
    /// Es la contraparte del boot fail-closed: [`Self::open`] con
    /// [`PackTrustRoot::Disabled`] deja el engine en base; cuando el caller
    /// comprueba que la licencia es Pro llama aquí con su root de confianza y
    /// el engine pasa a incluir los packs activos verificados. Idempotente:
    /// reconstruye desde el manifest, no reinstala JSONs (no duplica
    /// activaciones ni historial).
    ///
    /// Devuelve el número de packs activos resultantes.
    ///
    /// # Errors
    ///
    /// Devuelve error si algún pack activo referenciado falta o no compila.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn hydrate_from_manifest_with_root(&self, root_key: &str) -> Result<usize, String> {
        let root = PackTrustRoot::from_key(root_key);
        let Some(root) = root.key() else {
            return Err("hydrate aborted: empty trust root".to_string());
        };
        let mut state = self.state.lock().await;
        if state.manifest.order.is_empty() {
            return Ok(0);
        }
        let mut manifest = state.manifest.clone();
        let (engine, installed) = rebuild_active_set(&mut manifest, &self.pack_dir, &self.base_rules, Some(root))
            .map_err(|e| format!("manifest hydrate failed: {e}"))?;
        let active = installed.len();
        self.remember_trust_root(root);
        state.installed = installed;
        state.manifest = manifest;
        *self.active_engine.lock().await = engine;
        tracing::info!("packs: manifest hydrated with explicit trust root ({active} active packs)");
        Ok(active)
    }

    /// Rehidratar el estado instalado desde el directorio de packs.
    ///
    /// Si existe `manifest.json`, el manifest es la fuente de verdad: se
    /// reconstruye el engine desde él con `root_key`
    /// ([`Self::hydrate_from_manifest_with_root`]) SIN reinstalar los JSON
    /// (fix FAIL-2). Si NO existe manifest (directorio legacy pre-manifest),
    /// instala en orden cada JSON firmado verificado contra `root_key`
    /// (bootstrap).
    ///
    /// # Errors
    ///
    /// Devuelve error solo si el directorio no se puede leer; los packs que
    /// fallan la verificación no abortan la carga.
    pub async fn load_installed_from_dir(&self, root_key: &str) -> Result<(), String> {
        let dir = &self.pack_dir;
        let manifest_loaded = {
            let state = self.state.lock().await;
            !state.manifest.order.is_empty()
        };
        if manifest_loaded {
            self.hydrate_from_manifest_with_root(root_key).await?;
            return Ok(());
        }

        let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot read pack dir {}: {e}", dir.display()))?
            .filter_map(Result::ok)
            .filter(|e| {
                let is_manifest = e.file_name().to_string_lossy() == MANIFEST_FILE;
                !is_manifest && e.path().extension().is_some_and(|ext| ext == "json")
            })
            .map(|e| e.path())
            .collect();
        paths.sort();

        for path in paths {
            let signed = match Self::load_pack_from_file(&path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("pack skipped {}: {e}", path.display());
                    continue;
                }
            };
            if let Err(e) = self.install_with_root(signed, root_key).await {
                tracing::warn!("pack skipped {}: {e}", path.display());
            }
        }
        Ok(())
    }
}

/// Deactivar un pack en el manifest (tras fallar verificación en boot) y
/// removerlo de la secuencia de activaciones para que el rollback no lo
/// re-active.
fn deactivate_pack(manifest: &mut PackManifest, name: &str, ver: &str) {
    let key = versioned_key(name, ver);
    manifest.active.insert(key.clone(), false);
    if let Some(vm) = manifest.versions_by_pack.get_mut(name) {
        if vm.active == ver {
            vm.active = String::new();
        }
    }
    manifest
        .activation_sequence
        .retain(|k| !k.as_str().eq_ignore_ascii_case(&key));
}

/// Reconstruir el engine y el mapa de packs instalados SOLO desde el manifest
/// (fuente de verdad) — determinista: base + packs activos por (nombre,versión).
///
/// Cada pack activo se VERIFICA contra `trust_root` (fix P0). Si la firma no
/// es válida (tamper), el pack se deactiva en el manifest persistido y NO entra
/// al engine. Sin `trust_root` (fail-closed) NO se carga NINGÚN pack.
///
/// # Errors
///
/// Devuelve error si un pack activo referenciado no se puede leer o si compilar
/// el engine falla. Los packs con firma inválida NO abortan (se deactivan).
fn rebuild_active_set(
    manifest: &mut PackManifest,
    dir: &Path,
    base_rules: &[Rule],
    trust_root: Option<&str>,
) -> Result<(CompiledEngine, HashMap<String, InstalledPack>), String> {
    let mut installed: HashMap<String, InstalledPack> = HashMap::new();

    let Some(root) = trust_root else {
        tracing::warn!("packs: boot without trust root; loading NO packs (fail-closed)");
        let engine = EngineBuilder::new(base_rules)
            .build()
            .map_err(|e| format!("base engine build error: {e}"))?;
        return Ok((engine, installed));
    };

    let mut actives: Vec<(String, String)> = Vec::new();
    for (name, vers) in &manifest.versions_by_pack {
        if vers.active.is_empty() {
            continue;
        }
        let key = versioned_key(name.as_str(), vers.active.as_str());
        if manifest.active.get(&key).is_some_and(|b| *b) {
            actives.push((name.clone(), vers.active.clone()));
        }
    }
    actives.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut changed = false;
    let mut entries: Vec<(String, String, Vec<Rule>)> = Vec::new();
    for (name, ver) in actives {
        let Some(signed) = load_signed_from_dir(dir, &name, &ver) else {
            return Err(format!("active pack file missing: {name}@{ver}"));
        };
        let pack = match signed.extract_with_root(root) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "packs: active pack {name}@{ver} FAILED signature verification on boot; deactivating: {e}"
                );
                deactivate_pack(manifest, &name, &ver);
                changed = true;
                continue;
            }
        };
        entries.push((name.clone(), ver.clone(), pack.rules));
        installed.insert(
            name.clone(),
            InstalledPack {
                metadata: pack.metadata,
                pack_json: signed.pack_json.clone(),
                signature_hex: Some(signed.signature_hex.clone()),
                signer_public_key_hex: Some(signed.signer_public_key_hex.clone()),
                active: true,
            },
        );
    }

    if changed {
        PackManager::persist_manifest(dir, manifest).map_err(|e| format!("persist boot deactivation: {e}"))?;
    }

    let engine = EngineBuilder::new(&assemble_rules(base_rules, &entries))
        .build()
        .map_err(|e| format!("manifest engine build error: {e}"))?;
    Ok((engine, installed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{PackMetadata, RulePack, SignedRulePack};
    use cerberus_engine::rule::{Action, Category, Severity};
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Guard para serializar los (pocos) tests que tocan `CERBERUS_PACK_TRUST_ROOT`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Abrir un `PackManager` en un proceso con `CERBERUS_PACK_TRUST_ROOT`
    /// seteada a `root` (para tests de boot/reopen con verificación). Restaura
    /// el valor previo al terminar.
    fn open_with_trust_root(dir: &Path, root: &str) -> PackManager {
        // v6.1: el trust root entra por parámetro (nunca por env).
        PackManager::open(
            dir,
            EngineBuilder::new(&[]).build().unwrap(),
            &PackTrustRoot::from_key(root),
        )
        .unwrap()
    }

    fn sample_rule() -> Rule {
        Rule {
            flag: "test.flag".to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Block,
            hash_normalization: None,
            context_keywords: Vec::new(),
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec!["test".to_string()],
            validators: Vec::new(),
        }
    }

    fn sample_pack() -> RulePack {
        RulePack {
            metadata: PackMetadata {
                name: "test-pack".to_string(),
                version: "1.0.0".to_string(),
                description: "Test".to_string(),
                author: "Cerberus".to_string(),
                published: "2026-01-01T00:00:00Z".to_string(),
                min_engine_version: "0.1.0".to_string(),
            },
            rules: vec![sample_rule()],
        }
    }

    /// Construir un pack con nombre/versión/flag/patrón dados.
    fn pack_named(name: &str, version: &str, flag: &str, pattern: &str) -> RulePack {
        let rule = Rule {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Block,
            hash_normalization: None,
            context_keywords: Vec::new(),
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec![pattern.to_string()],
            validators: Vec::new(),
        };
        RulePack {
            metadata: PackMetadata {
                name: name.to_string(),
                version: version.to_string(),
                description: "Test".to_string(),
                author: "Cerberus".to_string(),
                published: "2026-01-01T00:00:00Z".to_string(),
                min_engine_version: "0.1.0".to_string(),
            },
            rules: vec![rule],
        }
    }

    fn test_keypair() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    /// Firma el pack con la clave fixture y devuelve la root asociada.
    fn sign_pack(pack: &RulePack) -> (SignedRulePack, String) {
        let keypair = test_keypair();
        let root = hex::encode(keypair.verifying_key().as_bytes());
        (SignedRulePack::sign(pack, &keypair).unwrap(), root)
    }

    /// Leer el manifest persistido (fuente de verdad en disco).
    fn read_manifest(dir: &Path) -> PackManifest {
        let content = std::fs::read_to_string(dir.join(MANIFEST_FILE)).unwrap();
        serde_json::from_str::<PackManifest>(&content).unwrap()
    }

    /// Flags del engine vivo, en orden.
    async fn engine_flags(mgr: &PackManager) -> Vec<String> {
        let arc = mgr.engine();
        let guard = arc.lock().await;
        guard.rules().iter().map(|r| r.flag.clone()).collect::<Vec<_>>()
    }

    #[tokio::test]
    async fn pack_manager_install_and_list() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();

        let packs = mgr.list_packs().await;
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].metadata.name, "test-pack");
        assert!(packs[0].active);
    }

    #[tokio::test]
    async fn pack_manager_rollback() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();
        assert!(mgr.rollback().await.is_ok());
    }

    #[tokio::test]
    async fn pack_manager_rollback_empty_history_fails() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();
        assert!(mgr.rollback().await.is_err());
    }

    #[tokio::test]
    async fn pack_manager_tampered_pack_fails_install() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();

        let (mut signed, root) = sign_pack(&sample_pack());
        signed.pack_json.push(' ');
        assert!(mgr.install_with_root(signed, &root).await.is_err());
    }

    #[test]
    fn load_pack_from_file_roundtrip() {
        let pack = sample_pack();
        let (signed, root) = sign_pack(&pack);

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.json");
        std::fs::write(&path, serde_json::to_string(&signed).unwrap()).unwrap();

        let loaded = PackManager::load_pack_from_file(&path).unwrap();
        assert!(loaded.verify_with_trusted_root(&root).is_ok());
    }

    #[test]
    fn load_packs_from_dir() {
        let tmp = TempDir::new().unwrap();
        let pack = sample_pack();
        let (signed, _) = sign_pack(&pack);

        let path1 = tmp.path().join("pack-a.json");
        std::fs::write(&path1, serde_json::to_string(&signed).unwrap()).unwrap();

        let path2 = tmp.path().join("pack-b.json");
        std::fs::write(&path2, serde_json::to_string(&signed).unwrap()).unwrap();

        let packs = PackManager::load_packs_from_dir(tmp.path()).unwrap();
        assert_eq!(packs.len(), 2);
    }

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn pack_manager_engine_accessible() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();

        let engine = mgr.engine();
        let guard = engine.lock().await;
        assert_eq!(guard.num_rules(), 0);
    }

    /// Fix review v4 (hallazgo 7): los packs se FUSIONAN, no reemplazan ──────────

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn pack_install_merges_rules_with_base() {
        let tmp = TempDir::new().unwrap();
        let base_rule = Rule {
            flag: "base.rule".to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Block,
            hash_normalization: None,
            context_keywords: Vec::new(),
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec!["base-pattern".to_string()],
            validators: Vec::new(),
        };
        let initial = EngineBuilder::new(std::slice::from_ref(&base_rule)).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();

        // base + pack = 2 reglas (la del pack se AÑADE, no reemplaza).
        let engine = mgr.engine();
        let guard = engine.lock().await;
        let flags: Vec<&str> = guard.rules().iter().map(|r| r.flag.as_str()).collect();
        assert_eq!(flags.len(), 2, "flags: {flags:?}");
        assert!(flags.contains(&"base.rule"));
        assert!(flags.contains(&"test.flag"));
        assert_eq!(guard.num_rules(), 2);
    }

    #[tokio::test]
    async fn pack_merge_deduplicates_by_flag() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();

        // El mismo pack firmado dos veces: la 2ª NO duplica la regla.
        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();
        let (signed2, root2) = sign_pack(&sample_pack());
        assert_eq!(root, root2);
        mgr.install_with_root(signed2, &root).await.unwrap();

        assert_eq!(mgr.engine().lock().await.num_rules(), 1);
    }

    #[tokio::test]
    async fn snapshot_engine_rebuilds_active_engine() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();

        let snap = mgr.snapshot_engine(None).await.unwrap();
        assert_eq!(snap.num_rules(), 0);

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();
        let snap2 = mgr.snapshot_engine(None).await.unwrap();
        assert_eq!(snap2.num_rules(), 1);
        assert!(
            !snap2.scan("a test value here").findings.is_empty(),
            "el snapshot debe escanear con las reglas instaladas"
        );
    }

    // ─────────────────── Regresión v5 (ownership + manifest durable) ─────────

    /// [FAIL-1] Actualizar un pack sustituye SOLO las reglas de la versión
    /// anterior del MISMO pack (`pack_name`) y el manifest registra ownership
    /// activo de v2.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn update_replaces_same_pack_flags_in_engine() {
        let tmp = TempDir::new().unwrap();
        let initial = EngineBuilder::new(&[]).build().unwrap();
        let mgr = PackManager::new(tmp.path(), initial).unwrap();

        let v1 = pack_named("test-pack", "1.0.0", "a.v1", "v1-pattern");
        let (s1, root) = sign_pack(&v1);
        mgr.install_with_root(s1, &root).await.unwrap();

        let v2 = pack_named("test-pack", "2.0.0", "a.v2", "v2-pattern");
        let (s2, _) = sign_pack(&v2);
        mgr.install_with_root(s2, &root).await.unwrap();

        let flags = engine_flags(&mgr).await;
        assert_eq!(flags.len(), 1, "engine must contain only v2 rules, got {flags:?}");
        assert!(flags.contains(&"a.v2".to_string()), "engine must contain v2's rule");
        assert!(
            !flags.contains(&"a.v1".to_string()),
            "engine must NOT contain v1's rule (ownership replaced)"
        );

        // manifest: ownership activo de v2, v1 en historial inactivo.
        let mf = read_manifest(tmp.path());
        assert_eq!(mf.active.get("test-pack@2.0.0"), Some(&true));
        assert_eq!(mf.active.get("test-pack@1.0.0"), Some(&false));
        assert_eq!(mf.versions_by_pack["test-pack"].active, "2.0.0");

        let owned = mgr.pack_owned_rules("test-pack").await;
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].flag, "a.v2");
    }

    /// [FAIL-2] El rollback persiste: tras abrir un NUEVO manager en la MISMA
    /// dir, el engine base no incluye el pack.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn rollback_persists_and_survives_manager_reopen() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let v1 = pack_named("test-pack", "1.0.0", "a.rollback", "reverse-pattern");
        let (signed, root) = sign_pack(&v1);
        mgr.install_with_root(signed, &root).await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        mgr.rollback().await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 0, "rollback deja el engine base");

        // rollback PERSISTIÓ: nuevo manager en la misma dir.
        let reopened = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
        assert_eq!(
            reopened.engine().lock().await.num_rules(),
            0,
            "el rollback pasa a sobrevivir al reopen del manager"
        );
        assert!(reopened.list_packs().await.is_empty());

        let mf = read_manifest(tmp.path());
        assert!(
            mf.active.get("test-pack@1.0.0") == Some(&false),
            "pack queda inactivo en el manifest"
        );
    }

    /// [3] Una regla inválida al instalar v2 deja engine y manifest intactos
    /// (atomicidad).
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn update_invalid_leaves_engine_and_disk_unchanged() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let v1 = pack_named("test-pack", "1.0.0", "a.v1", "stable-pattern");
        let (s1, root) = sign_pack(&v1);
        mgr.install_with_root(s1, &root).await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        // v2 con regex inválida → compila falla → install Err.
        let v2 = pack_named("test-pack", "2.0.0", "a.v2", "[");
        let (s2, _) = sign_pack(&v2);
        assert!(mgr.install_with_root(s2, &root).await.is_err());

        // engine sigue con v1.
        let flags = engine_flags(&mgr).await;
        assert_eq!(flags.len(), 1, "engine unchanged: {flags:?}");
        assert!(flags.contains(&"a.v1".to_string()));

        // manifest sin cambios: no hay entrada de v2.
        let mf = read_manifest(tmp.path());
        assert!(
            !mf.active.contains_key("test-pack@2.0.0"),
            "v2 no debe quedar activa en el manifest"
        );
        assert_eq!(mf.active.get("test-pack@1.0.0"), Some(&true));

        // disco: no se escribió el archivo versionado de v2.
        assert!(
            !tmp.path().join("pack_test-pack-v2.0.0.json").exists(),
            "no debe quedar el JSON de v2 en disco"
        );
    }

    /// Reopen con múltiples packs conserva la composición y el orden determinista.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn reopen_preserves_engine_composition_and_order() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let a1 = pack_named("alpha-pack", "1.0.0", "alpha.rule", "alp-one");
        let b2 = pack_named("beta-pack", "2.0.0", "beta.rule", "bet-two");
        let (sa, root) = sign_pack(&a1);
        mgr.install_with_root(sa, &root).await.unwrap();
        let (sb, _) = sign_pack(&b2);
        mgr.install_with_root(sb, &root).await.unwrap();

        let before = engine_flags(&mgr).await;
        assert_eq!(before, vec!["alpha.rule".to_string(), "beta.rule".to_string()]);

        let reopened = open_with_trust_root(tmp.path(), &root);
        assert_eq!(
            engine_flags(&reopened).await,
            before,
            "la composición/orden persiste tras reopen"
        );
        assert_eq!(reopened.list_packs().await.len(), 2);
    }

    /// [P0] Un pack tamperado en disco (`pack_json` modificado SIN re-firmar) se
    /// RECHAZA al reabrir con trust root: no entra al engine y el manifest lo
    /// marca inactivo.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn tampered_pack_rejected_on_reopen() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        // Tamper: modificar pack_json en disco sin re-firmar.
        let pack_path = tmp.path().join("pack_test-pack-v1.0.0.json");
        let mut on_disk = PackManager::load_pack_from_file(&pack_path).unwrap();
        on_disk.pack_json = on_disk.pack_json.replace("\"test\"", "\"EVIL\"");
        std::fs::write(&pack_path, serde_json::to_string(&on_disk).unwrap()).unwrap();

        let reopened = open_with_trust_root(tmp.path(), &root);
        assert_eq!(
            reopened.engine().lock().await.num_rules(),
            0,
            "el pack tamperado NO debe aportar reglas al engine tras reboot"
        );
        assert!(
            reopened.list_packs().await.is_empty(),
            "el pack tamperado no debe estar activo"
        );

        let mf = read_manifest(tmp.path());
        assert_eq!(
            mf.active.get("test-pack@1.0.0"),
            Some(&false),
            "el manifest debe marcar el pack tamperado como inactivo"
        );
        assert_eq!(
            mf.versions_by_pack["test-pack"].active, "",
            "no debe quedar versión activa para el pack tamperado"
        );
    }

    /// [P0] Sin trust root configurado (fail-closed), NO se carga ningún pack
    /// al abrir, aunque existan en disco con manifest.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn boot_without_trust_root_loads_no_packs() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        // Reabrir SIN trust root → ningún pack carga (fail-closed).
        let reopened = {
            let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = std::env::var("CERBERUS_PACK_TRUST_ROOT").ok();
            std::env::remove_var("CERBERUS_PACK_TRUST_ROOT");
            let m = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
            if let Some(p) = prev {
                std::env::set_var("CERBERUS_PACK_TRUST_ROOT", p);
            }
            m
        };
        assert_eq!(
            reopened.engine().lock().await.num_rules(),
            0,
            "sin trust root el engine debe quedar sin packs"
        );
        assert!(reopened.list_packs().await.is_empty());
    }

    /// [P0 v6.1] Free + trust root válido + manifest con pack ACTIVO ⇒ engine
    /// base, cero packs.
    ///
    /// Es el bypass de boot que existía: el manager leía el root global y
    /// rehidrataba el manifest ANTES de que el caller comprobara la licencia,
    /// así que en Free los packs ya estaban dentro del engine. Con el root
    /// explícito condicionado por licencia (`gated_by_pro(false)`) el boot es
    /// fail-closed, y el MISMO estado en disco con `gated_by_pro(true)` sí
    /// carga (control positivo: el test no pasa por falta de datos).
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn free_tier_boot_with_trust_root_and_active_manifest_loads_zero_packs() {
        let tmp = TempDir::new().unwrap();
        let seed = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
        let (signed, root) = sign_pack(&sample_pack());
        seed.install_with_root(signed, &root).await.unwrap();
        assert_eq!(seed.engine().lock().await.num_rules(), 1);
        assert_eq!(read_manifest(tmp.path()).active.get("test-pack@1.0.0"), Some(&true));

        // Tier Free: el root se anula en el gate ⇒ ni un pack.
        let free_root = PackTrustRoot::from_key(&root).gated_by_pro(false);
        assert_eq!(free_root, PackTrustRoot::Disabled);
        let free = PackManager::open(tmp.path(), EngineBuilder::new(&[]).build().unwrap(), &free_root).unwrap();
        assert_eq!(
            free.engine().lock().await.num_rules(),
            0,
            "Free NO debe recibir reglas de packs en boot"
        );
        assert!(free.list_packs().await.is_empty(), "Free no reporta packs activos");
        assert!(free.effective_trust_root().is_none(), "Free no retiene trust root");
        // El manifest en disco NO se degrada: sigue marcando el pack activo.
        assert_eq!(
            read_manifest(tmp.path()).active.get("test-pack@1.0.0"),
            Some(&true),
            "el boot Free no debe reescribir el manifest"
        );

        // Control positivo: MISMO disco, tier Pro ⇒ el pack sí entra.
        let pro_root = PackTrustRoot::from_key(&root).gated_by_pro(true);
        let pro = PackManager::open(tmp.path(), EngineBuilder::new(&[]).build().unwrap(), &pro_root).unwrap();
        assert_eq!(pro.engine().lock().await.num_rules(), 1, "Pro sí hidrata los packs");
        assert_eq!(pro.list_packs().await.len(), 1);
    }

    /// [P0 v6.1] `open` IGNORA `CERBERUS_PACK_TRUST_ROOT`: un root global en el
    /// entorno no puede reactivar packs a espaldas del gate.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn boot_ignores_global_env_trust_root() {
        let tmp = TempDir::new().unwrap();
        let seed = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
        let (signed, root) = sign_pack(&sample_pack());
        seed.install_with_root(signed, &root).await.unwrap();

        let (free, legacy) = {
            let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = std::env::var("CERBERUS_PACK_TRUST_ROOT").ok();
            std::env::set_var("CERBERUS_PACK_TRUST_ROOT", &root);
            let free = PackManager::open(
                tmp.path(),
                EngineBuilder::new(&[]).build().unwrap(),
                &PackTrustRoot::Disabled,
            )
            .unwrap();
            let legacy = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
            match prev {
                Some(p) => std::env::set_var("CERBERUS_PACK_TRUST_ROOT", p),
                None => std::env::remove_var("CERBERUS_PACK_TRUST_ROOT"),
            }
            (free, legacy)
        };
        assert_eq!(
            free.engine().lock().await.num_rules(),
            0,
            "open no debe leer el root del entorno"
        );
        assert_eq!(
            legacy.engine().lock().await.num_rules(),
            0,
            "new tampoco lee el root del entorno en boot"
        );
    }

    /// [v6.1] Tras un boot fail-closed, el caller que ya validó la licencia Pro
    /// hidrata con root explícito: los packs activos entran SIN duplicar
    /// activaciones ni historial, y el rollback posterior sigue funcionando.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn pro_gate_hydrates_manifest_idempotently_after_failclosed_boot() {
        let tmp = TempDir::new().unwrap();
        let seed = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
        let (v1, root) = sign_pack(&pack_named("alpha", "1.0.0", "alpha.rule", "AAA"));
        let (v2, root2) = sign_pack(&pack_named("alpha", "2.0.0", "alpha.rule2", "BBB"));
        assert_eq!(root2, root, "misma clave fixture");
        seed.install_with_root(v1, &root).await.unwrap();
        seed.install_with_root(v2, &root).await.unwrap();
        let before = read_manifest(tmp.path());

        let mgr = PackManager::open(
            tmp.path(),
            EngineBuilder::new(&[]).build().unwrap(),
            &PackTrustRoot::Disabled,
        )
        .unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 0, "boot Free: cero packs");

        // Gate Pro superado ⇒ hidratación explícita (dos veces: idempotente).
        assert_eq!(mgr.hydrate_from_manifest_with_root(&root).await.unwrap(), 1);
        assert_eq!(mgr.hydrate_from_manifest_with_root(&root).await.unwrap(), 1);
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);
        let after = read_manifest(tmp.path());
        assert_eq!(
            after.activation_sequence, before.activation_sequence,
            "la hidratación no debe añadir activaciones"
        );
        assert_eq!(after.order, before.order, "la hidratación no debe añadir versiones");
        assert_eq!(mgr.effective_trust_root().as_deref(), Some(root.as_str()));

        // El rollback post-hidratación usa el root efectivo (no el entorno).
        mgr.rollback().await.unwrap();
        assert_eq!(
            mgr.engine().lock().await.num_rules(),
            1,
            "rollback restaura la versión previa del pack, no un engine vacío"
        );
        assert_eq!(read_manifest(tmp.path()).versions_by_pack["alpha"].active, "1.0.0");

        // Hidratar con root vacío es un error explícito (fail-closed).
        assert!(mgr.hydrate_from_manifest_with_root("").await.is_err());
    }

    /// [v6.1] Sin trust root explícito, `install` por el camino EXPLÍCITO
    /// (`open`) falla aunque el entorno tenga un root global.
    #[tokio::test]
    // El guard serializa la mutación de env (proceso global) y debe cubrir el
    // `install` completo: single-threaded runtime, sin riesgo de deadlock.
    #[allow(clippy::await_holding_lock)]
    async fn install_on_explicit_manager_never_falls_back_to_env() {
        let tmp = TempDir::new().unwrap();
        let (signed, root) = sign_pack(&sample_pack());
        let mgr = PackManager::open(
            tmp.path(),
            EngineBuilder::new(&[]).build().unwrap(),
            &PackTrustRoot::Disabled,
        )
        .unwrap();

        let err = {
            let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = std::env::var("CERBERUS_PACK_TRUST_ROOT").ok();
            std::env::set_var("CERBERUS_PACK_TRUST_ROOT", &root);
            let err = mgr.install(signed).await.expect_err("debe fallar sin root explícito");
            match prev {
                Some(p) => std::env::set_var("CERBERUS_PACK_TRUST_ROOT", p),
                None => std::env::remove_var("CERBERUS_PACK_TRUST_ROOT"),
            }
            err
        };
        assert!(err.contains("no trust root configured"), "{err}");
    }

    /// [v6.1] `PackTrustRoot`: normalización y gate de licencia.
    #[test]
    fn trust_root_gate_semantics() {
        assert_eq!(PackTrustRoot::from_key("  "), PackTrustRoot::Disabled);
        assert_eq!(PackTrustRoot::from_key(" ab "), PackTrustRoot::Key("ab".to_string()));
        assert_eq!(
            PackTrustRoot::from_optional_key(None::<String>),
            PackTrustRoot::Disabled
        );
        assert_eq!(
            PackTrustRoot::from_optional_key(Some("ab")),
            PackTrustRoot::Key("ab".to_string())
        );
        assert!(PackTrustRoot::from_key("ab").is_enabled());
        assert!(!PackTrustRoot::Disabled.is_enabled());
        assert_eq!(PackTrustRoot::default(), PackTrustRoot::Disabled);
        assert_eq!(
            PackTrustRoot::from_key("ab").gated_by_pro(false),
            PackTrustRoot::Disabled
        );
        assert_eq!(PackTrustRoot::from_key("ab").gated_by_pro(true).key(), Some("ab"));
        assert_eq!(PackTrustRoot::Disabled.gated_by_pro(true), PackTrustRoot::Disabled);
    }
}
