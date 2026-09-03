//! Auto-update mechanism for rule packs.
//!
//! Supports:
//! - Downloading packs from URLs
//! - Signature verification before loading
//! - Hot-reload of the engine with a new pack
//! - Rollback to the previous pack
//! - Per-pack rule ownership + a durable manifest (`manifest.json`)
//!   as the source of truth of the installed/active state (fix code review v5).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cerberus_engine::engine::{CompiledEngine, EngineBuilder};
use cerberus_engine::rule::Rule;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::pack::{PackMetadata, RulePack, SignedRulePack};

/// Name of the manifest file that persists the installed state.
const MANIFEST_FILE: &str = "manifest.json";

/// Versions per pack recorded in the manifest.
///
/// `installed` is the latest version known on disk; `active` is the version
/// that contributes rules to the engine ("" if none is active).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackVersions {
    /// Latest version installed-on-disk for this pack.
    pub installed: String,
    /// Active version (rules in the engine), "" if none is active.
    pub active: String,
}

/// Durable manifest of the installed state (fix code review v5).
///
/// It is the source of truth for the `PackManager`: it is read on open
/// (`new`) and rewritten on every `install` / `rollback` / `uninstall`. It
/// records, per pack and version, rule ownership and which ones are active
/// in the engine.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackManifest {
    /// Known versions `"<pack>@<version>"`, ordered by (name, version).
    pub order: Vec<String>,
    /// Is each `"<pack>@<version>"` active? Only active ones contribute rules.
    pub active: HashMap<String, bool>,
    /// Per pack: latest version on disk and active version.
    pub versions_by_pack: HashMap<String, PackVersions>,
    /// Sequence of activations, in order, to resolve rollback (additive field;
    /// absent in manifests written by previous versions).
    #[serde(default)]
    pub activation_sequence: Vec<String>,
}

/// State of an installed pack.
#[derive(Debug, Clone)]
pub struct InstalledPack {
    /// Pack metadata.
    pub metadata: PackMetadata,
    /// Pack JSON (for rollback).
    pub pack_json: String,
    /// Ed25519 signature in hex (persisted alongside the pack, review 2 P1 #4).
    pub signature_hex: Option<String>,
    /// Signer public key (persisted provenance).
    pub signer_public_key_hex: Option<String>,
    /// Is it currently active?
    pub active: bool,
}

/// Internal state (under `state`) of the manager.
#[derive(Debug, Clone)]
struct ManagerState {
    manifest: PackManifest,
    installed: HashMap<String, InstalledPack>,
}

/// Rule pack trust root, provided **explicitly** by the caller.
///
/// [P0 v6.1] The `PackManager` no longer reads `CERBERUS_PACK_TRUST_ROOT` at
/// boot: doing so left a license-gate bypass. The daemon opened the manager
/// (which rehydrated from the manifest using the global root) and only
/// AFTERWARDS checked the license; in Free tier with an active manifest the
/// packs were already inside the engine. Now the root comes in as a parameter
/// and the caller conditions it on the license via
/// [`PackTrustRoot::gated_by_pro`]: without Pro the value is
/// [`PackTrustRoot::Disabled`] and NO pack is activated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PackTrustRoot {
    /// No trust root: fail-closed, zero packs (base engine).
    #[default]
    Disabled,
    /// Root public key (Ed25519, hex) against which every pack is verified.
    Key(String),
}

impl PackTrustRoot {
    /// Trust root from a key; empty or blank ⇒ [`Self::Disabled`].
    #[must_use]
    pub fn from_key(key: impl AsRef<str>) -> Self {
        let key = key.as_ref().trim();
        if key.is_empty() {
            Self::Disabled
        } else {
            Self::Key(key.to_string())
        }
    }

    /// Trust root from an optional config value.
    #[must_use]
    pub fn from_optional_key(key: Option<impl AsRef<str>>) -> Self {
        key.map_or(Self::Disabled, Self::from_key)
    }

    /// License gate: only Pro tier can activate rule packs (open-core).
    ///
    /// ALWAYS apply before passing the root to the `PackManager`; in Free the
    /// result is [`Self::Disabled`] and the manager boots with the base engine.
    #[must_use]
    pub fn gated_by_pro(self, is_pro: bool) -> Self {
        if is_pro {
            self
        } else {
            Self::Disabled
        }
    }

    /// The key, if the trust root is enabled.
    #[must_use]
    pub const fn key(&self) -> Option<&str> {
        match self {
            Self::Disabled => None,
            Self::Key(k) => Some(k.as_str()),
        }
    }

    /// Is there a trust root (and therefore packs can be verified)?
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Key(_))
    }
}

/// Pack manager with persistent rollback support.
pub struct PackManager {
    /// Directory where packs are stored.
    pack_dir: PathBuf,
    /// Base rules (engine's own, before packs) — deterministic order.
    base_rules: Vec<Rule>,
    /// Mutable state: durable manifest + active packs.
    state: Arc<Mutex<ManagerState>>,
    /// Current active engine.
    active_engine: Arc<Mutex<CompiledEngine>>,
    /// EFFECTIVE trust root for post-gate operations (rollback, uninstall,
    /// rebuilds). It is set with the explicit root of [`PackManager::open`]
    /// and updated with the root contributed by each already-authorized
    /// operation (`install_with_root`, `hydrate_from_manifest_with_root`). It
    /// never comes from an environment variable.
    trust_root: std::sync::RwLock<Option<String>>,
    /// Can [`PackManager::install`] fall back to the env `CERBERUS_PACK_TRUST_ROOT`?
    ///
    /// Only `true` in the legacy constructor [`PackManager::new`], which uses
    /// the local single-process mode (the CLI without a daemon) where the
    /// license gate already ran before calling `install`. The explicit path
    /// ([`PackManager::open`]) never consults the environment.
    allow_env_install_root: bool,
}

/// Return the `"<name>@<version>"` key for a `(pack, version)`.
fn versioned_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

/// Split a `"<name>@<version>"` key into its parts.
fn parse_versioned_key(key: &str) -> (String, String) {
    key.find('@').map_or_else(
        || (key.to_string(), String::new()),
        |at| (key[..at].to_string(), key[at + 1..].to_string()),
    )
}

/// Versioned file name for a pack (history per version).
fn versioned_file_name(name: &str, version: &str) -> String {
    format!("pack_{name}-v{version}.json")
}

/// Parse a pack's rules from its internal JSON.
///
/// # Errors
///
/// Returns an error if the pack JSON is not a valid `RulePack`.
fn rules_from_pack_json(json: &str) -> Result<Vec<Rule>, String> {
    match RulePack::from_json(json) {
        Ok(pack) => Ok(pack.rules),
        Err(e) => Err(format!("cannot parse owned pack rules: {e}")),
    }
}

/// Deterministic order of rules: base first, then each active pack ordered by
/// (name, version).
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

/// Load the active signed pack for `(name, version)` from disk, with a
/// fallback to the legacy plain name (`<name>.json`).
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
    /// Create a `PackManager` **without** a trust root (fail-closed).
    ///
    /// Equivalent to `open(pack_dir, engine, &PackTrustRoot::Disabled)`: reads
    /// the manifest to preserve history, but does NOT activate any pack (the
    /// engine stays on the base rules). [P0 v6.1] This constructor no longer
    /// consults `CERBERUS_PACK_TRUST_ROOT`; to hydrate packs you must pass an
    /// explicit root already conditioned by license (see
    /// [`PackTrustRoot::gated_by_pro`]).
    ///
    /// It keeps the env fallback ONLY in [`Self::install`], for the local
    /// single-process mode (CLI without a daemon), where the license gate runs
    /// in the caller immediately before.
    ///
    /// # Errors
    ///
    /// Returns an error if the pack directory cannot be created.
    pub fn new(pack_dir: impl AsRef<Path>, initial_engine: CompiledEngine) -> Result<Self, String> {
        Self::open_inner(pack_dir, initial_engine, &PackTrustRoot::Disabled, true)
    }

    /// Open a `PackManager` with an EXPLICIT trust root.
    ///
    /// If the trust root is enabled and `manifest.json` exists, it rebuilds
    /// the active engine in the saved order (base + active packs ordered by
    /// name/version), verifying each pack against `trust_root`, and rehydrates
    /// `installed`. With [`PackTrustRoot::Disabled`] the manifest is loaded as
    /// history but the engine boots on base and `installed` stays empty: this
    /// is the Free path (zero packs).
    ///
    /// This constructor NEVER reads environment variables: the caller resolves
    /// the root from its trusted config and conditions it on the license.
    ///
    /// # Errors
    ///
    /// Returns an error if the pack directory cannot be created.
    pub fn open(
        pack_dir: impl AsRef<Path>,
        initial_engine: CompiledEngine,
        trust_root: &PackTrustRoot,
    ) -> Result<Self, String> {
        Self::open_inner(pack_dir, initial_engine, trust_root, false)
    }

    /// Shared implementation of [`Self::new`] and [`Self::open`].
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

    /// Current effective trust root (copy), if any.
    #[must_use]
    pub fn effective_trust_root(&self) -> Option<String> {
        self.trust_root
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Set the effective trust root after an already-authorized operation.
    fn remember_trust_root(&self, root: &str) {
        let mut guard = self
            .trust_root
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(root.to_string());
    }

    /// Load the manifest from `pack_dir` if it exists, or an empty manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if `manifest.json` exists but is not valid JSON.
    fn load_manifest(dir: &Path) -> Result<PackManifest, String> {
        let path = dir.join(MANIFEST_FILE);
        if !path.exists() {
            return Ok(PackManifest::default());
        }
        let content = std::fs::read_to_string(&path).map_err(|e| format!("cannot read manifest: {e}"))?;
        serde_json::from_str::<PackManifest>(&content).map_err(|e| format!("invalid manifest: {e}"))
    }

    /// Persist the manifest to `pack_dir` (temp write + rename).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or renamed.
    fn persist_manifest(dir: &Path, manifest: &PackManifest) -> Result<(), String> {
        let json = serde_json::to_string(manifest).map_err(|e| format!("cannot serialize manifest: {e}"))?;
        let path = dir.join(MANIFEST_FILE);
        let tmp = dir.join(format!("{MANIFEST_FILE}.tmp"));
        std::fs::write(&tmp, json).map_err(|e| format!("cannot write manifest: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("cannot commit manifest: {e}"))
    }

    /// Install a pack from a `SignedRulePack`.
    ///
    /// Verifies the signature against the manager's EFFECTIVE trust root (the
    /// one from [`Self::open`], or the one from the last authorized
    /// operation). Only the legacy constructor [`Self::new`] admits, as a last
    /// resort, the env `CERBERUS_PACK_TRUST_ROOT` (local single-process mode,
    /// already gated by the caller). Fail-closed: without a root, error.
    /// Compiles the rules and updates the active engine. For an explicit root,
    /// resolve it and use [`Self::install_with_root`].
    ///
    /// # Errors
    ///
    /// Returns an error if there is no trust root, the signature is invalid,
    /// or the rules fail to compile.
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

    /// Install a pack verifying against an EXPLICIT trust root key (provided
    /// by the caller from its trusted config).
    ///
    /// The pack's rules replace the owned rules of the previous version of the
    /// SAME pack (`pack_name`); the engine is rebuilt deterministically (base
    /// and active packs ordered by name/version). Other rule packs do NOT lose
    /// rules. The result is persisted to the manifest and to a versioned file
    /// `pack_<name>-v<ver>.json` (the old version remains as history with
    /// `active: false`).
    ///
    /// A compile or write failure leaves the engine and manifest untouched
    /// (atomicity).
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, does not match
    /// `root_key`, the rules fail to compile, or persistence fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn install_with_root(&self, signed: SignedRulePack, root_key: &str) -> Result<(), String> {
        let pack = signed.extract_with_root(root_key)?;
        // Root already authorized by the caller: it remains the effective root
        // for later rebuilds (rollback/uninstall) of this manager.
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

        // Engine candidate with ownership replacement (atomic guard):
        // if compile fails nothing is touched (engine + manifest + disk).
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

        // Write the versioned JSON (only after compile OK).
        let signed_json = serde_json::to_string(&signed).map_err(|e| format!("cannot serialize signed pack: {e}"))?;
        let pack_path = self.pack_dir.join(versioned_file_name(&name, &version));
        std::fs::write(&pack_path, signed_json).map_err(|e| format!("cannot write pack: {e}"))?;

        // Manifest: deactivate the previous active version of the SAME pack and activate the new one.
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

        // Swap in-memory + live engine.
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

    /// Roll back to the previous engine, PERSISTENT and repeatable across
    /// restarts: deactivates the last activation recorded in the manifest,
    /// persists it and rebuilds the live engine from the resulting manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no activation history to revert or if the
    /// rebuild/persistence fails.
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

        // Previous active version of the SAME pack (if any) to restore.
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

    /// Uninstall a pack by name: deactivates it in the manifest (persisting
    /// the change) and rebuilds the live engine without its rules. Its JSON is
    /// kept as history with `active: false`.
    ///
    /// # Errors
    ///
    /// Returns an error if the pack has no active version or if the
    /// rebuild/persistence fails.
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

    /// Enable or disable a pack by name (Appendix B B.3: `packs
    /// enable/disable <pack>`): flips the `active` flag of the pack's latest
    /// installed version in the manifest, persists the manifest, and rebuilds
    /// the live engine. Disabling is additive-safe: the pack JSON stays on
    /// disk (history, `active: false`), so a later `enable` re-activates it
    /// without re-installing.
    ///
    /// This is NOT the uninstall path: no JSON is deleted and the activation
    /// sequence is left intact for `rollback`.
    ///
    /// # Errors
    ///
    /// Returns an error if the pack is not installed, or the rebuild or
    /// manifest persistence fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn set_active(&self, pack_name: &str, active: bool) -> Result<(), String> {
        let mut state = self.state.lock().await;
        let mut manifest = state.manifest.clone();
        let Some(versions) = manifest.versions_by_pack.get(pack_name) else {
            return Err(format!("pack '{pack_name}' is not installed"));
        };
        // Target key: enabling activates the latest on-disk version;
        // disabling deactivates the currently active one. Already in the
        // requested state → idempotent no-op success.
        let key = if active {
            let latest = versions.installed.clone();
            if latest.is_empty() || manifest.active.get(&versioned_key(pack_name, &latest)).copied() == Some(true) {
                return Ok(());
            }
            versioned_key(pack_name, &latest)
        } else {
            let current = versions.active.clone();
            if current.is_empty() {
                return Ok(());
            }
            versioned_key(pack_name, &current)
        };
        if active && self.effective_trust_root().is_none() {
            // Enabling (re)activates rules — same Pro trust-root policy as
            // install/rollback. Disabling only reduces detection and stays
            // available in every tier.
            return Err("pack enable requires a trust root (Pro tier or CERBERUS_PACK_TRUST_ROOT)".to_string());
        }
        manifest.active.insert(key.clone(), active);
        if let Some(vm) = manifest.versions_by_pack.get_mut(pack_name) {
            vm.active = if active {
                parse_versioned_key(&key).1
            } else {
                String::new()
            };
        }

        let (engine, installed) = match rebuild_active_set(
            &mut manifest,
            &self.pack_dir,
            &self.base_rules,
            self.effective_trust_root().as_deref(),
        ) {
            Ok(x) => x,
            Err(e) => {
                return Err(format!(
                    "pack {} rebuild failed: {e}",
                    if active { "enable" } else { "disable" }
                ))
            }
        };
        Self::persist_manifest(&self.pack_dir, &manifest)?;
        state.installed = installed;
        state.manifest = manifest;
        *self.active_engine.lock().await = engine;
        tracing::info!("pack {}: {pack_name}", if active { "enabled" } else { "disabled" });
        Ok(())
    }

    /// Re-verify every installed pack's signature against the effective
    /// trust root and rebuild the live engine from the verified manifest
    /// (Appendix B B.3: `packs update` — F6 contract is verify + hot-reload;
    /// fetching newer versions from a registry is the F7 auto-update unit).
    ///
    /// Returns one `(pack@version, ok)` entry per installed version; a
    /// failed verification deactivates that version in the manifest (the
    /// same policy as boot-time tamper handling) before the rebuild.
    ///
    /// # Errors
    ///
    /// Returns an error only if the post-verification rebuild fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn verify_installed(&self) -> Result<Vec<(String, bool)>, String> {
        let mut state = self.state.lock().await;
        let mut manifest = state.manifest.clone();
        let root = self.effective_trust_root();
        let mut results: Vec<(String, bool)> = Vec::new();
        for (key, installed) in &state.installed {
            let (name, ver) = parse_versioned_key(key);
            let ok = match (&root, &installed.signature_hex, &installed.signer_public_key_hex) {
                (Some(expected), Some(_sig), Some(_signer)) => {
                    // F7 re-verification P2: verify the DISK bytes — the same
                    // source `rebuild_active_set` uses — so the operator
                    // report matches the rebuild outcome. Verifying the
                    // in-memory copy masked out-of-band disk tampering (the
                    // report said "verified" while the rebuild deactivated).
                    // Disk file missing: nothing to verify — unverified.
                    load_signed_from_dir(&self.pack_dir, &name, &ver)
                        .is_some_and(|signed| signed.verify_with_trusted_root(expected).is_ok())
                }
                // No trust root / unsigned pack: without a root there is
                // nothing to verify AGAINST — the pack is inactive anyway
                // (boot gate), report it as unverified rather than "ok".
                _ => false,
            };
            if !ok {
                deactivate_pack(&mut manifest, &name, &ver);
            }
            results.push((key.clone(), ok));
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));

        let (engine, installed) =
            match rebuild_active_set(&mut manifest, &self.pack_dir, &self.base_rules, root.as_deref()) {
                Ok(x) => x,
                Err(e) => return Err(format!("packs update rebuild failed: {e}")),
            };
        Self::persist_manifest(&self.pack_dir, &manifest)?;
        state.installed = installed;
        state.manifest = manifest;
        *self.active_engine.lock().await = engine;
        Ok(results)
    }

    /// Get the active engine.
    #[must_use]
    pub fn engine(&self) -> Arc<Mutex<CompiledEngine>> {
        Arc::clone(&self.active_engine)
    }

    /// Snapshot of the active engine as an owned `CompiledEngine` (fix
    /// review v4, finding 7): `CompiledEngine` is not `Clone`, so whoever
    /// needs an owned copy (e.g. the daemon's `ProxyContext`, which uses
    /// `Arc<CompiledEngine>`) gets it by recompiling from the active rules.
    /// Since compilation is a pure function of the rules, the snapshot is
    /// equivalent to the active one.
    ///
    /// `payload_secret` is re-applied to the snapshot if the caller uses it in
    /// its base engine (HMAC-SHA256, P1-12).
    ///
    /// # Errors
    ///
    /// Returns an error if recompiling the active rules fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn snapshot_engine(&self, payload_secret: Option<&[u8]>) -> Result<CompiledEngine, String> {
        let active = self.active_engine.lock().await;
        let mut builder = EngineBuilder::new(active.rules());
        if let Some(secret) = payload_secret {
            builder = builder.with_payload_secret(secret.to_vec());
        }
        builder.build().map_err(|e| format!("snapshot engine build error: {e}"))
    }

    /// List installed packs (active ones only).
    #[must_use]
    pub async fn list_packs(&self) -> Vec<InstalledPack> {
        let state = self.state.lock().await;
        state.installed.values().cloned().collect()
    }

    /// Rules contributed by pack `pack_name` (active version) to the engine.
    ///
    /// Returns an empty slice if the pack is not active.
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

    /// Rebuild the "engine from the manifest": base + active packs from the
    /// manifest, in deterministic order (by name/version), without touching
    /// the state.
    ///
    /// # Errors
    ///
    /// Returns an error if any referenced active pack cannot be read or
    /// compiled.
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

    /// Read the current persisted manifest (copy) — for inspection/compat.
    #[must_use]
    pub async fn manifest_snapshot(&self) -> PackManifest {
        let state = self.state.lock().await;
        state.manifest.clone()
    }

    /// Load a pack from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist or is invalid.
    pub fn load_pack_from_file(path: impl AsRef<Path>) -> Result<SignedRulePack, String> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| format!("cannot read pack file: {e}"))?;
        serde_json::from_str::<SignedRulePack>(&content).map_err(|e| format!("invalid signed pack: {e}"))
    }

    /// Load multiple packs from a directory (ignores `manifest.json`).
    ///
    /// # Errors
    ///
    /// Returns an error if any pack cannot be loaded (non-parseable ones are
    /// logged and skipped).
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

    /// Activate, with an EXPLICIT `root_key` already authorized by license,
    /// the packs that the manifest marks as active.
    ///
    /// This is the counterpart to fail-closed boot: [`Self::open`] with
    /// [`PackTrustRoot::Disabled`] leaves the engine on base; when the caller
    /// verifies the license is Pro it calls here with its trusted root and the
    /// engine comes to include the verified active packs. Idempotent: it
    /// rebuilds from the manifest, it does not reinstall JSONs (it does not
    /// duplicate activations or history).
    ///
    /// Returns the resulting number of active packs.
    ///
    /// # Errors
    ///
    /// Returns an error if any referenced active pack is missing or fails to
    /// compile.
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

    /// Rehydrate the installed state from the pack directory.
    ///
    /// If `manifest.json` exists, the manifest is the source of truth: the
    /// engine is rebuilt from it with `root_key`
    /// ([`Self::hydrate_from_manifest_with_root`]) WITHOUT reinstalling the
    /// JSONs (fix FAIL-2). If no manifest exists (legacy pre-manifest
    /// directory), it installs each verified signed JSON against `root_key`
    /// in order (bootstrap).
    ///
    /// # Errors
    ///
    /// Returns an error only if the directory cannot be read; packs that fail
    /// verification do not abort the load.
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

/// Deactivate a pack in the manifest (after it fails verification at boot) and
/// remove it from the activation sequence so rollback does not re-activate it.
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

/// Rebuild the engine and the installed-pack map SOLELY from the manifest
/// (source of truth) — deterministic: base + active packs by (name, version).
///
/// Each active pack is VERIFIED against `trust_root` (fix P0). If the
/// signature is invalid (tamper), the pack is deactivated in the persisted
/// manifest and does NOT enter the engine. Without `trust_root`
/// (fail-closed) NO pack is loaded.
///
/// # Errors
///
/// Returns an error if a referenced active pack cannot be read or if
/// compiling the engine fails. Packs with invalid signatures do NOT abort
/// (they are deactivated).
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
                tracing::warn!("packs: active pack {name}@{ver} FAILED signature verification; deactivating: {e}");
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

    /// Guard to serialize the (few) tests that touch `CERBERUS_PACK_TRUST_ROOT`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Open a `PackManager` in a process with `CERBERUS_PACK_TRUST_ROOT` set
    /// to `root` (for boot/reopen tests with verification). Restores the
    /// previous value on exit.
    fn open_with_trust_root(dir: &Path, root: &str) -> PackManager {
        // v6.1: the trust root comes in as a parameter (never from env).
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

    /// Build a pack with the given name/version/flag/pattern.
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

    /// Sign the pack with the fixture key and return the associated root.
    fn sign_pack(pack: &RulePack) -> (SignedRulePack, String) {
        let keypair = test_keypair();
        let root = hex::encode(keypair.verifying_key().as_bytes());
        (SignedRulePack::sign(pack, &keypair).unwrap(), root)
    }

    /// Read the persisted manifest (on-disk source of truth).
    fn read_manifest(dir: &Path) -> PackManifest {
        let content = std::fs::read_to_string(dir.join(MANIFEST_FILE)).unwrap();
        serde_json::from_str::<PackManifest>(&content).unwrap()
    }

    /// Flags of the live engine, in order.
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

    /// Fix review v4 (finding 7): packs are MERGED, not replaced ──────────

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

        // base + pack = 2 rules (the pack rule is ADDED, not replaced).
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

        // The same signed pack twice: the 2nd does NOT duplicate the rule.
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
            "the snapshot must scan with the installed rules"
        );
    }

    // ─────────────────── Regression v5 (ownership + durable manifest) ─────────

    /// [FAIL-1] Updating a pack replaces ONLY the rules of the previous
    /// version of the SAME pack (`pack_name`) and the manifest records the
    /// active ownership of v2.
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

        // manifest: active ownership of v2, v1 in inactive history.
        let mf = read_manifest(tmp.path());
        assert_eq!(mf.active.get("test-pack@2.0.0"), Some(&true));
        assert_eq!(mf.active.get("test-pack@1.0.0"), Some(&false));
        assert_eq!(mf.versions_by_pack["test-pack"].active, "2.0.0");

        let owned = mgr.pack_owned_rules("test-pack").await;
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].flag, "a.v2");
    }

    /// [FAIL-2] Rollback persists: after opening a NEW manager in the SAME
    /// dir, the base engine does not include the pack.
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
        assert_eq!(
            mgr.engine().lock().await.num_rules(),
            0,
            "rollback leaves the base engine"
        );

        // rollback PERSISTED: new manager in the same dir.
        let reopened = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
        assert_eq!(
            reopened.engine().lock().await.num_rules(),
            0,
            "rollback now survives manager reopen"
        );
        assert!(reopened.list_packs().await.is_empty());

        let mf = read_manifest(tmp.path());
        assert!(
            mf.active.get("test-pack@1.0.0") == Some(&false),
            "pack remains inactive in the manifest"
        );
    }

    /// [3] An invalid rule when installing v2 leaves engine and manifest
    /// intact (atomicity).
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn update_invalid_leaves_engine_and_disk_unchanged() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let v1 = pack_named("test-pack", "1.0.0", "a.v1", "stable-pattern");
        let (s1, root) = sign_pack(&v1);
        mgr.install_with_root(s1, &root).await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        // v2 with invalid regex → compile fails → install Err.
        let v2 = pack_named("test-pack", "2.0.0", "a.v2", "[");
        let (s2, _) = sign_pack(&v2);
        assert!(mgr.install_with_root(s2, &root).await.is_err());

        // engine still on v1.
        let flags = engine_flags(&mgr).await;
        assert_eq!(flags.len(), 1, "engine unchanged: {flags:?}");
        assert!(flags.contains(&"a.v1".to_string()));

        // manifest unchanged: no v2 entry.
        let mf = read_manifest(tmp.path());
        assert!(
            !mf.active.contains_key("test-pack@2.0.0"),
            "v2 must not remain active in the manifest"
        );
        assert_eq!(mf.active.get("test-pack@1.0.0"), Some(&true));

        // disk: the versioned v2 file was not written.
        assert!(
            !tmp.path().join("pack_test-pack-v2.0.0.json").exists(),
            "the v2 JSON must not remain on disk"
        );
    }

    /// Reopen with multiple packs preserves the composition and the deterministic order.
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
            "composition/order persists after reopen"
        );
        assert_eq!(reopened.list_packs().await.len(), 2);
    }

    /// [P0] A tampered pack on disk (`pack_json` modified WITHOUT re-signing)
    /// is REJECTED on reopen with a trust root: it does not enter the engine
    /// and the manifest marks it inactive.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn tampered_pack_rejected_on_reopen() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        // Tamper: modify pack_json on disk without re-signing.
        let pack_path = tmp.path().join("pack_test-pack-v1.0.0.json");
        let mut on_disk = PackManager::load_pack_from_file(&pack_path).unwrap();
        on_disk.pack_json = on_disk.pack_json.replace("\"test\"", "\"EVIL\"");
        std::fs::write(&pack_path, serde_json::to_string(&on_disk).unwrap()).unwrap();

        let reopened = open_with_trust_root(tmp.path(), &root);
        assert_eq!(
            reopened.engine().lock().await.num_rules(),
            0,
            "the tampered pack must NOT contribute rules to the engine after reboot"
        );
        assert!(
            reopened.list_packs().await.is_empty(),
            "the tampered pack must not be active"
        );

        let mf = read_manifest(tmp.path());
        assert_eq!(
            mf.active.get("test-pack@1.0.0"),
            Some(&false),
            "the manifest must mark the tampered pack as inactive"
        );
        assert_eq!(
            mf.versions_by_pack["test-pack"].active, "",
            "no active version must remain for the tampered pack"
        );
    }

    /// [P0] Without a configured trust root (fail-closed), NO pack is loaded
    /// on open, even if they exist on disk with a manifest.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn boot_without_trust_root_loads_no_packs() {
        let tmp = TempDir::new().unwrap();
        let mgr = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();

        let (signed, root) = sign_pack(&sample_pack());
        mgr.install_with_root(signed, &root).await.unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);

        // Reopen WITHOUT trust root → no pack loads (fail-closed).
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
            "without a trust root the engine must stay without packs"
        );
        assert!(reopened.list_packs().await.is_empty());
    }

    /// [P0 v6.1] Free + valid trust root + manifest with an ACTIVE pack ⇒ base
    /// engine, zero packs.
    ///
    /// This is the boot bypass that existed: the manager read the global root
    /// and rehydrated the manifest BEFORE the caller checked the license, so
    /// in Free the packs were already inside the engine. With the explicit
    /// root conditioned by license (`gated_by_pro(false)`) the boot is
    /// fail-closed, and the SAME on-disk state with `gated_by_pro(true)` does
    /// load (positive control: the test does not pass for lack of data).
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn free_tier_boot_with_trust_root_and_active_manifest_loads_zero_packs() {
        let tmp = TempDir::new().unwrap();
        let seed = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
        let (signed, root) = sign_pack(&sample_pack());
        seed.install_with_root(signed, &root).await.unwrap();
        assert_eq!(seed.engine().lock().await.num_rules(), 1);
        assert_eq!(read_manifest(tmp.path()).active.get("test-pack@1.0.0"), Some(&true));

        // Free tier: the root is voided at the gate ⇒ no packs.
        let free_root = PackTrustRoot::from_key(&root).gated_by_pro(false);
        assert_eq!(free_root, PackTrustRoot::Disabled);
        let free = PackManager::open(tmp.path(), EngineBuilder::new(&[]).build().unwrap(), &free_root).unwrap();
        assert_eq!(
            free.engine().lock().await.num_rules(),
            0,
            "Free must NOT receive pack rules at boot"
        );
        assert!(free.list_packs().await.is_empty(), "Free does not report active packs");
        assert!(
            free.effective_trust_root().is_none(),
            "Free does not retain a trust root"
        );
        // The on-disk manifest is NOT degraded: it still marks the pack active.
        assert_eq!(
            read_manifest(tmp.path()).active.get("test-pack@1.0.0"),
            Some(&true),
            "the Free boot must not rewrite the manifest"
        );

        // Positive control: SAME disk, Pro tier ⇒ the pack does enter.
        let pro_root = PackTrustRoot::from_key(&root).gated_by_pro(true);
        let pro = PackManager::open(tmp.path(), EngineBuilder::new(&[]).build().unwrap(), &pro_root).unwrap();
        assert_eq!(pro.engine().lock().await.num_rules(), 1, "Pro does hydrate the packs");
        assert_eq!(pro.list_packs().await.len(), 1);
    }

    /// [P0 v6.1] `open` IGNORES `CERBERUS_PACK_TRUST_ROOT`: a global root in
    /// the environment cannot reactivate packs behind the gate's back.
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
            "open must not read the root from the environment"
        );
        assert_eq!(
            legacy.engine().lock().await.num_rules(),
            0,
            "new also does not read the root from the environment at boot"
        );
    }

    /// [v6.1] After a fail-closed boot, the caller that already validated the
    /// Pro license hydrates with an explicit root: active packs enter WITHOUT
    /// duplicating activations or history, and the subsequent rollback still
    /// works.
    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn pro_gate_hydrates_manifest_idempotently_after_failclosed_boot() {
        let tmp = TempDir::new().unwrap();
        let seed = PackManager::new(tmp.path(), EngineBuilder::new(&[]).build().unwrap()).unwrap();
        let (v1, root) = sign_pack(&pack_named("alpha", "1.0.0", "alpha.rule", "AAA"));
        let (v2, root2) = sign_pack(&pack_named("alpha", "2.0.0", "alpha.rule2", "BBB"));
        assert_eq!(root2, root, "same fixture key");
        seed.install_with_root(v1, &root).await.unwrap();
        seed.install_with_root(v2, &root).await.unwrap();
        let before = read_manifest(tmp.path());

        let mgr = PackManager::open(
            tmp.path(),
            EngineBuilder::new(&[]).build().unwrap(),
            &PackTrustRoot::Disabled,
        )
        .unwrap();
        assert_eq!(mgr.engine().lock().await.num_rules(), 0, "Free boot: zero packs");

        // Pro gate passed ⇒ explicit hydration (twice: idempotent).
        assert_eq!(mgr.hydrate_from_manifest_with_root(&root).await.unwrap(), 1);
        assert_eq!(mgr.hydrate_from_manifest_with_root(&root).await.unwrap(), 1);
        assert_eq!(mgr.engine().lock().await.num_rules(), 1);
        let after = read_manifest(tmp.path());
        assert_eq!(
            after.activation_sequence, before.activation_sequence,
            "hydration must not add activations"
        );
        assert_eq!(after.order, before.order, "hydration must not add versions");
        assert_eq!(mgr.effective_trust_root().as_deref(), Some(root.as_str()));

        // Post-hydration rollback uses the effective root (not the environment).
        mgr.rollback().await.unwrap();
        assert_eq!(
            mgr.engine().lock().await.num_rules(),
            1,
            "rollback restores the previous version of the pack, not an empty engine"
        );
        assert_eq!(read_manifest(tmp.path()).versions_by_pack["alpha"].active, "1.0.0");

        // Hydrating with an empty root is an explicit error (fail-closed).
        assert!(mgr.hydrate_from_manifest_with_root("").await.is_err());
    }

    /// [v6.1] Without an explicit trust root, `install` on the EXPLICIT path
    /// (`open`) fails even if the environment has a global root.
    #[tokio::test]
    // The guard serializes env mutation (global process) and must cover the
    // complete `install`: single-threaded runtime, no deadlock risk.
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
            let err = mgr
                .install(signed)
                .await
                .expect_err("must fail without an explicit root");
            match prev {
                Some(p) => std::env::set_var("CERBERUS_PACK_TRUST_ROOT", p),
                None => std::env::remove_var("CERBERUS_PACK_TRUST_ROOT"),
            }
            err
        };
        assert!(err.contains("no trust root configured"), "{err}");
    }

    /// [v6.1] `PackTrustRoot`: normalization and license gate.
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
