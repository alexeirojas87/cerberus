//! Cerberus Local — cortafuegos de datos sensibles para agentes LLM.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use cerberus_engine::engine::{CompiledEngine, EngineBuilder};
use cerberus_engine::loader::load_rules_from_str;
use cerberus_packs::license::LicenseManager;
use cerberus_packs::updater::{PackManager, PackTrustRoot};
use cerberus_packs::wire::{ControlPlaneEndpoint, ENDPOINT_FILE};
use cerberus_proxy::api::ApiContext;
use cerberus_proxy::config::{OperationMode, ProxyConfig, UpstreamConfig};
use cerberus_proxy::forward::spawn_forward_proxy;
use cerberus_proxy::proxy::{spawn_managed_proxy, ProxyContext};
use cerberus_store::store::AuditStore;

use crate::packs::default_rules_json;
use crate::platform;

/// Ruta al archivo PID.
pub(crate) fn pid_path() -> PathBuf {
    config_dir().join("cerberus.pid")
}

fn endpoint_path() -> PathBuf {
    config_dir().join(ENDPOINT_FILE)
}

fn persist_endpoint(actual: std::net::SocketAddr, pid: u32) -> Result<(), String> {
    let endpoint = ControlPlaneEndpoint::new(&actual.to_string(), pid).map_err(|e| e.to_string())?;
    let target = endpoint_path();
    let tmp = target.with_extension(format!("json.tmp-{pid}"));
    fs::write(&tmp, endpoint.to_json().map_err(|e| e.to_string())?)
        .map_err(|e| format!("cannot write endpoint metadata: {e}"))?;
    if let Err(first) = fs::rename(&tmp, &target) {
        // Windows no reemplaza un destino existente con rename. Un descriptor
        // viejo no es autoridad (el PID file lo es), así que se elimina y se
        // reintenta con el temp completamente escrito.
        if target.exists() {
            fs::remove_file(&target).map_err(|e| format!("cannot replace stale endpoint metadata: {e}"))?;
            fs::rename(&tmp, &target).map_err(|e| format!("cannot publish endpoint metadata: {e}"))?;
        } else {
            let _ = fs::remove_file(&tmp);
            return Err(format!("cannot publish endpoint metadata: {first}"));
        }
    }
    Ok(())
}

fn remove_runtime_files() {
    let _ = fs::remove_file(pid_path());
    let _ = fs::remove_file(endpoint_path());
}

/// Ruta al directorio de configuración (delegado a `platform` para que en
/// Windows sea `%APPDATA%\Cerberus` en lugar de `~\.cerberus`).
pub(crate) fn config_dir() -> std::path::PathBuf {
    platform::config_dir()
}

/// Ruta al archivo de config YAML generado por `cerberus init`.
fn config_file() -> PathBuf {
    config_dir().join("config.yaml")
}

/// Ruta al directorio de rule packs instalados (`~/.cerberus/packs`).
pub(crate) fn packs_dir() -> PathBuf {
    config_dir().join("packs")
}

/// Ruta al archivo de licencia activa: env `CERBERUS_LICENSE_PATH` o, por
/// defecto, `~/.cerberus/license.json`.
pub(crate) fn license_path() -> PathBuf {
    std::env::var("CERBERUS_LICENSE_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .map_or_else(|| config_dir().join("license.json"), PathBuf::from)
}

/// Cargar la licencia activa para el daemon (conexión F7 en el producto,
/// fix del code review item 12).
///
/// Política **fail-open del producto**: si el archivo no existe o la
/// verificación falla (sin trust root o firma inválida), se continúa con tier
/// Free y se loguea una advertencia clara. La licencia solo gate features Pro
/// (open-core: el motor y el modo local básico quedan libres, §7 del plan).
pub(crate) fn load_license(path: Option<&std::path::Path>) -> LicenseManager {
    let Some(path) = path else {
        return LicenseManager::free();
    };
    if !path.exists() {
        return LicenseManager::free();
    }
    match LicenseManager::from_file(path) {
        Ok(mgr) => mgr,
        Err(e) => {
            tracing::warn!(
                "license load failed ({e}); continuing with Free tier (fail-open) — set \
                 CERBERUS_LICENSE_PUBLIC_KEY and a valid license at CERBERUS_LICENSE_PATH"
            );
            LicenseManager::free()
        }
    }
}

/// Resumen de la licencia para el log del arranque, con el campo
/// machine-readable `tier=pro|free` (clave del test de integración).
#[must_use]
pub(crate) fn license_summary(mgr: &LicenseManager) -> String {
    let tier = if mgr.is_pro() { "pro" } else { "free" };
    let state = if mgr.is_expired() { "expired" } else { "valid" };
    format!("tier={tier} state={state}\n{}", mgr.report())
}

/// Intentar cargar config YAML de `cerberus init`.
/// Retorna `None` si no existe el fichero o es inválida.
fn load_proxy_config() -> Option<ProxyConfig> {
    load_proxy_config_from(&config_file())
}

/// Cargar config desde una ruta explícita para aislar el filesystem en tests.
fn load_proxy_config_from(path: &std::path::Path) -> Option<ProxyConfig> {
    if !path.exists() {
        return None;
    }
    ProxyConfig::from_file(path).ok()
}

/// Secreto de payload-hash (HMAC-SHA256, P1-12) desde `CERBERUS_HMAC_SECRET`.
fn payload_secret_from_env() -> Option<Vec<u8>> {
    std::env::var("CERBERUS_HMAC_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .map(String::into_bytes)
}

/// Valor de env no vacío como `Option<String>`.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Días de retención de la auditoría: env `CERBERUS_RETENTION_DAYS`
/// (default 90). `0` = retención mínima (ver `store::purge_old`).
fn retention_days_from_env() -> u64 {
    std::env::var("CERBERUS_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(90)
}

/// Compilar el engine base (default rules + payload secret opcional).
/// Es la ÚNICA fuente de reglas del daemon y del CLI: de aquí deriva tanto el
/// `PackManager` (que lo fusiona con los packs, hallazgo 7) como el snapshot
/// que recibe el proxy — sin una segunda compilación independiente.
///
/// # Errors
///
/// Devuelve el error de cargar/compiilar las reglas.
fn build_base_engine() -> Result<cerberus_engine::engine::CompiledEngine, String> {
    let rules_json = default_rules_json();
    let rules = load_rules_from_str(&rules_json).map_err(|e| format!("error loading rules: {e}"))?;
    let mut builder = EngineBuilder::new(&rules);
    if let Some(secret) = payload_secret_from_env() {
        builder = builder.with_payload_secret(secret);
    }
    builder.build().map_err(|e| format!("engine build error: {e}"))
}

/// Abrir un `PackManager` sobre `packs_dir()` con el engine base — el MISMO
/// para el daemon y el CLI (hallazgo 7: no hay un segundo engine).
///
/// # Errors
///
/// Devuelve error si no se puede crear el directorio de packs o compilar.
fn open_packs_manager() -> Result<PackManager, String> {
    let engine = build_base_engine()?;
    let license = load_license(Some(&license_path()));
    let trust_root =
        PackTrustRoot::from_optional_key(env_nonempty("CERBERUS_PACK_TRUST_ROOT")).gated_by_pro(license.is_pro());
    PackManager::open(packs_dir(), engine, &trust_root).map_err(|e| format!("packs setup error: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// A) MERGE real de la config: base = config.yaml (fail_policy, max_body_bytes,
//    health_path, log_level, etc. TODOS preservados — ver fix del code review
//    v4 hallazgo 5, parte daemon: antes se reconstruía con `..default()` y se
//    perdían esos campos del YAML).
//
// Precedencia:
//   listen      env `CERBERUS_LISTEN_HOST` (o host de file_cfg) + port CLI.
//   upstreams   env `CERBERUS_UPSTREAMS` (JSON) > env `CERBERUS_UPSTREAM_URL`
//               (openai/anthropic/default) > config.yaml > error instructivo.
//   admin_token env `CERBERUS_ADMIN_TOKEN` > config.yaml.
//   mode        env `CERBERUS_MODE` > config.yaml.
// ─────────────────────────────────────────────────────────────────────────────
fn resolve_config(port: u16, file_cfg: Option<ProxyConfig>) -> Result<ProxyConfig, String> {
    let mut config = file_cfg.unwrap_or_default();

    // Mode: env > archivo.
    if let Some(mode_raw) = env_nonempty("CERBERUS_MODE") {
        config.mode = serde_yaml::from_str::<OperationMode>(&mode_raw)
            .or_else(|_| serde_json::from_str::<OperationMode>(&mode_raw))
            .map_err(|e| format!("invalid CERBERUS_MODE ('{mode_raw}'): {e}"))?;
    }

    // Listen: host desde env (0.0.0.0 en Docker) o el host del archivo; el
    // port SIEMPRE es el del CLI (default 8787).
    let listen_host = std::env::var("CERBERUS_LISTEN_HOST")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| {
            config
                .listen
                .split(':')
                .next()
                .map(str::to_string)
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "127.0.0.1".to_string())
        });
    config.listen = format!("{listen_host}:{port}");

    // Upstreams: env (JSON) > env URL (openai/anthropic/default) > archivo.
    // Sin ningún upstream → error con instrucciones claras.
    let upstream_auth = "authorization".to_string();
    if let Some(upstreams_json) = env_nonempty("CERBERUS_UPSTREAMS") {
        config.upstreams = serde_json::from_str::<HashMap<String, UpstreamConfig>>(&upstreams_json)
            .map_err(|e| format!("invalid CERBERUS_UPSTREAMS JSON: {e}"))?;
    } else if let Some(url) = env_nonempty("CERBERUS_UPSTREAM_URL") {
        // Compatibilidad P1 #7: la URL base crea MULTIPLES upstreams para que
        // el routing por prefijo funcione (openai/anthropic/default).
        let mut m = HashMap::new();
        m.insert(
            "openai".to_string(),
            UpstreamConfig {
                url: url.clone(),
                path_prefix: Some("/openai/".to_string()),
                auth_header: upstream_auth.clone(),
            },
        );
        m.insert(
            "anthropic".to_string(),
            UpstreamConfig {
                url: url.clone(),
                path_prefix: Some("/anthropic/".to_string()),
                auth_header: upstream_auth.clone(),
            },
        );
        m.insert(
            "default".to_string(),
            UpstreamConfig {
                url,
                path_prefix: None,
                auth_header: upstream_auth,
            },
        );
        config.upstreams = m;
    }

    if config.upstreams.is_empty() {
        return Err("no upstreams configured: ejecuta 'cerberus init' o exporta CERBERUS_UPSTREAM_URL".to_string());
    }

    // Admin token: env con prioridad, luego config.yaml (control plane P0).
    if let Some(token) = env_nonempty("CERBERUS_ADMIN_TOKEN") {
        config.admin_token = Some(token);
    }

    Ok(config)
}

#[allow(
    clippy::too_many_lines,
    clippy::option_if_let_else,
    clippy::map_unwrap_or,
    clippy::if_not_else
)]
pub(crate) async fn start(port: u16) -> Result<String, String> {
    // Verificar si ya está corriendo
    if is_running() {
        return Err("Cerberus ya está corriendo. Usa 'cerberus stop' primero.".to_string());
    }

    // Engine base ÚNICO (hallazgo 7): lo usan PackManager y, tras la carga
    // inicial de packs, el snapshot que recibe el proxy.
    let base_engine = build_base_engine()?;

    // A) Config real: base = config.yaml (sin perder fields) + overrides.
    let file_cfg = load_proxy_config();
    let config = resolve_config(port, file_cfg)?;
    // El archivo `mitm.json` ausente/deshabilitado produce `None`: el reverse
    // proxy sigue siendo siempre el default. Si el usuario optó explícitamente
    // por MITM, validamos CA/hosts/listener antes de inicializar el daemon.
    let mitm_config = crate::mitm::runtime_config()?;

    // C/F) Auditoría con retención configurable (env, default 90 días).
    let retention_days = retention_days_from_env();
    let db_path = pid_path()
        .parent()
        .map_or_else(|| PathBuf::from("/tmp/cerberus/cerberus.db"), |p| p.join("cerberus.db"));
    fs::create_dir_all(config_dir()).map_err(|e| format!("cannot create config dir: {e}"))?;

    let store_opt = AuditStore::open_with(&db_path, retention_days).map(Arc::new).ok();
    if store_opt.is_some() {
        println!(
            "Audit store opened at {} (retention {retention_days} days)",
            db_path.display()
        );
    } else {
        eprintln!("warning: audit store unavailable — events will be in-memory only");
    }

    println!(
        "config efectiva: mode={} fail_policy={} max_body_bytes={} health_path={}",
        format!("{:?}", config.mode).to_lowercase(),
        format!("{:?}", config.fail_policy).to_lowercase(),
        config.max_body_bytes.unwrap_or(0),
        config.health_path
    );

    // Config compartida proxy ↔ Config API (hot-reload real, P0-5).
    let shared_config = Arc::new(std::sync::RwLock::new(config.clone()));

    // F7: licencia activa (fail-open → Free si no verificable).
    let boot_license_path = license_path();
    let license: Arc<LicenseManager> = Arc::new(load_license(Some(boot_license_path.as_path())));
    tracing::info!(
        "license: loaded from {} —\n{}",
        boot_license_path.display(),
        license_summary(&license)
    );

    // F7: PackManager sobre el MISMO engine base; cargamos packs firmados ya
    // presentes en `~/.cerberus/packs` (si hay trust root) ANTES de levantar
    // el proxy → el snapshot que recibe el proxy ya incluye esos packs.
    // F7: PackManager con el MISMO engine base. Los packs del dir se hidratan
    // ANTES de levantar el proxy (trust root); el snapshot inicial alimenta el
    // engine del proxy. El hot-reload en runtime se gestiona por un WORKER de
    // packs (fix review v5): un `Arc<RwLock<Arc<CompiledEngine>>>` compartido
    // con el proxy se intercambia atómicamente en cada install/rollback vía
    // las rutas `/api/packs/*`.
    // El trust root se resuelve DESPUÉS de la licencia y se desactiva en tier
    // Free antes de construir el manager. Así ningún manifest activo puede
    // hidratar packs Pro durante el constructor y evadir el gate de boot.
    let trust_root =
        PackTrustRoot::from_optional_key(env_nonempty("CERBERUS_PACK_TRUST_ROOT")).gated_by_pro(license.is_pro());
    let packs_manager =
        PackManager::open(packs_dir(), base_engine, &trust_root).map_err(|e| format!("packs setup error: {e}"))?;
    if !trust_root.is_enabled() {
        tracing::warn!("packs: sin trust root efectivo (tier Free o root ausente) — engine base, cero packs");
    }
    let engine_for_proxy = packs_manager
        .snapshot_engine(payload_secret_from_env().as_deref())
        .await?;
    let installed = packs_manager.list_packs().await.len();
    println!(
        "packs: manager ready at {} ({} packs instalados; snapshot pasa al proxy)",
        packs_dir().display(),
        installed
    );

    // Fix review v6.1: las reglas BASE del dataplane son el snapshot de packs
    // (defaults + packs firmados). La política persistida en config.yaml
    // (categorías, overrides y reglas custom) se aplica ENCIMA al arrancar →
    // lo que el operador guardó desde el dashboard se restaura sin tener que
    // reinstalar nada. Si el YAML trae una política que no compila, el
    // arranque falla en voz alta: preferimos no arrancar a arrancar con menos
    // detección de la que el operador cree tener.
    let base_rules: Vec<cerberus_engine::rule::Rule> = engine_for_proxy.rules().to_vec();
    config
        .policy
        .validate()
        .map_err(|e| format!("policy inválida en {}: {e}", config_file().display()))?;
    let boot_engine = cerberus_proxy::detection_policy::build_engine(
        &base_rules,
        &config.policy,
        payload_secret_from_env().as_deref(),
    )
    .map_err(|e| format!("policy engine build error: {e}"))?;
    println!(
        "policy: {} categorías, {} overrides, {} reglas custom, {} entradas de allowlist → engine con {} reglas ({} base)",
        config.policy.categories.len(),
        config.policy.rule_actions.len(),
        config.policy.custom_rules.len(),
        config.policy.allowlist.len(),
        boot_engine.num_rules(),
        base_rules.len(),
    );

    // Engine intercambiable (hot-reload): el proxy lee de aquí; el worker de
    // packs escribe el snapshot tras install/rollback y el control plane
    // republica tras cada cambio de política.
    let live_engine: Arc<RwLock<Arc<CompiledEngine>>> = Arc::new(std::sync::RwLock::new(Arc::new(boot_engine)));
    let engine_control = cerberus_proxy::detection_policy::EngineControl::new(
        live_engine.clone(),
        base_rules,
        payload_secret_from_env(),
    );

    // Worker de rule packs (asíncrono) — ejecuta install/rollback/list contra
    // el PackManager y, tras cada mutación, sustituye las reglas BASE y
    // republica la política encima → el proxy en marcha cambia de reglas SIN
    // reiniciar y sin perder las reglas custom del operador.
    let pack_worker_manager: Arc<PackManager> = Arc::new(packs_manager);
    let (pack_tx, mut pack_rx) = tokio::sync::mpsc::channel::<cerberus_proxy::api::PackCommand>(8);
    let packs_worker_manager = pack_worker_manager.clone();
    let engine_control_worker = engine_control.clone();
    let policy_source = shared_config.clone();
    tokio::spawn(async move {
        use cerberus_proxy::api::PackCommand;
        let payload_secret = payload_secret_from_env();
        while let Some(cmd) = pack_rx.recv().await {
            // Cada arm produce (reply, Result) y el send se hace una vez.
            let outcome: (
                tokio::sync::oneshot::Sender<Result<String, String>>,
                Result<String, String>,
            ) = match cmd {
                PackCommand::Install { request, reply } => {
                    // Gate Pro (coherencia con CLI): los packs requieren tier Pro.
                    let license = load_license(Some(&license_path()));
                    let res = if let Err(e) = require_pro_for_pack_ops(&license) {
                        Err(format!("pack install aborted via control plane: {e}"))
                    } else {
                        let origin = request.origin_label().to_string();
                        match request.signed_pack() {
                            Ok(signed) => match packs_worker_manager.install(signed).await {
                                Ok(()) => match packs_worker_manager.snapshot_engine(payload_secret.as_deref()).await {
                                    Ok(new_engine) => {
                                        // Rebase atómico (helper síncrono, sin await →
                                        // el guard std nunca cruza el `await` Send): las
                                        // reglas del pack pasan a ser la BASE y la
                                        // política del operador se re-aplica encima, así
                                        // que un install no borra las reglas custom ni
                                        // los overrides (fix review v6.1).
                                        match rebase_live_engine(&engine_control_worker, &policy_source, &new_engine) {
                                            Ok(rules) => {
                                                tracing::info!(pack_origin = %origin, rules, "pack instalado por control plane");
                                                Ok(format!(
                                                    "pack instalado (hot-reload): engine ahora tiene {rules} reglas"
                                                ))
                                            }
                                            Err(e) => Err(format!("policy rebase falló tras instalar: {e}")),
                                        }
                                    }
                                    Err(e) => Err(format!("snapshot engine falló: {e}")),
                                },
                                Err(e) => Err(e),
                            },
                            Err(e) => Err(e.to_string()),
                        }
                    };
                    (reply, res)
                }
                PackCommand::Rollback { reply } => {
                    // Gate Pro (hallazgo v6): rollback reactiva una versión de
                    // pack — beneficio Pro, igual que install. En Free se deniega.
                    let license = load_license(Some(&license_path()));
                    let res = match require_pro_for_pack_ops(&license) {
                        Err(e) => Err(format!("pack rollback aborted via control plane: {e}")),
                        Ok(()) => match packs_worker_manager.rollback().await {
                            Ok(()) => match packs_worker_manager.snapshot_engine(payload_secret.as_deref()).await {
                                Ok(new_engine) => {
                                    // Igual que el install: la política del operador se
                                    // re-aplica sobre las reglas revertidas.
                                    match rebase_live_engine(&engine_control_worker, &policy_source, &new_engine) {
                                        Ok(rules) => Ok(format!(
                                            "rollback ejecutado (hot-reload): engine ahora tiene {rules} reglas"
                                        )),
                                        Err(e) => Err(format!("policy rebase falló tras el rollback: {e}")),
                                    }
                                }
                                Err(e) => Err(format!("snapshot engine falló: {e}")),
                            },
                            Err(e) => Err(e),
                        },
                    };
                    (reply, res)
                }
                PackCommand::List { reply } => {
                    let packs = packs_worker_manager.list_packs().await;
                    let res = Ok(format!("{} packs instalados", packs.len()));
                    (reply, res)
                }
            };
            let _ = outcome.0.send(outcome.1);
        }
    });

    let ctx = Arc::new(ProxyContext {
        config: shared_config.clone(),
        engine: live_engine.clone(),
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::with_store_opt(shared_config, store_opt.clone())
            .with_config_path(config_file())
            .with_pack_worker(pack_tx)
            .with_engine(engine_control),
        last_upstream: Arc::new(std::sync::Mutex::new(None)),
    });

    // F4 (feedback al dev): el daemon vigea el buffer en memoria de eventos
    // del control plane (`ApiContext.events`) y emite feedback uno-a-uno por
    // cada intervención (block/redact/warn) que se registra. El Arc del
    // buffer se captura AQUÍ, antes de mover `ctx` a los proxies.
    let api_events = ctx.api.events.clone();
    let mut interventions = crate::feedback_ux::InterventionWatcher::new();

    let addr: std::net::SocketAddr = config.listen.parse().map_err(|e| format!("invalid address: {e}"))?;
    let (actual, proxy_handle) = spawn_managed_proxy(addr, ctx.clone())
        .await
        .map_err(|e| format!("proxy error: {e}"))?;
    let mut forward_handle = if let Some(mitm_config) = mitm_config {
        match spawn_forward_proxy(mitm_config, ctx.clone()).await {
            Ok((forward_addr, handle)) => {
                println!("Cerberus MITM opt-in corriendo en {forward_addr} (CONNECT allowlist exacta)");
                Some(handle)
            }
            Err(error) => {
                let _ = proxy_handle.shutdown(Duration::from_secs(1)).await;
                return Err(format!("MITM opt-in proxy error: {error}"));
            }
        }
    } else {
        println!("MITM: disabled (default); reverse proxy only");
        None
    };

    // Escribir PID
    let pid = std::process::id();
    fs::write(pid_path(), pid.to_string()).map_err(|e| format!("cannot write PID: {e}"))?;
    if let Err(e) = persist_endpoint(actual, pid) {
        remove_runtime_files();
        if let Some(handle) = forward_handle.take() {
            let _ = handle.shutdown(Duration::from_secs(1)).await;
        }
        let _ = proxy_handle.shutdown(Duration::from_secs(1)).await;
        return Err(e);
    }

    println!("Cerberus proxy corriendo en {actual}");
    println!("Cerberus iniciado en {actual} (esperando señales de parada)");

    // ─── G) Loop graceful: Ctrl+C / SIGTERM / pid file removido → flush+close.
    // El future de señal se resuelve FUERA del `tokio::select!` (la macro no
    // acepta `#[cfg]` en arms; en no-unix el arm SIGTERM es `pending()`).
    #[cfg(unix)]
    let mut term_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("cannot install SIGTERM handler: {e}"))?;
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let sigterm = term_signal.recv();
    #[cfg(not(unix))]
    let sigterm = tokio::future::pending::<Option<()>>();
    tokio::pin!(ctrl_c);
    tokio::pin!(sigterm);

    // F4 (feedback al dev): cada tick (1 s), drenar intervenciones nuevas →
    // notificación de escritorio (tasa 1/seg) + línea CLI como fallback.
    let shutdown: bool = loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("señal de parada (SIGINT) recibida");
                break true;
            }
            _ = &mut sigterm => {
                println!("señal de parada (SIGTERM) recibida");
                break true;
            }
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                if !is_running() {
                    println!("pid file removido — detención externa solicitada");
                    break true;
                }
                // Cada tick (1 s), drenar intervenciones nuevas → notificación
                // de escritorio (tasa 1/seg) + línea CLI como fallback.
                crate::feedback_ux::emit_interventions(&api_events, &mut interventions).await;
            }
        }
    };
    let _ = shutdown;

    // Primero cerramos admisión y drenamos requests: ningún handler puede
    // encolar auditoría después de la barrera del store.
    if let Some(handle) = forward_handle {
        if let Err(e) = handle.shutdown(Duration::from_secs(5)).await {
            eprintln!("MITM forward proxy: cierre forzado durante shutdown: {e}");
        } else {
            println!("MITM forward proxy: admisión cerrada y túneles drenados");
        }
    }
    if let Err(e) = proxy_handle.shutdown(Duration::from_secs(5)).await {
        eprintln!("proxy: cierre forzado durante shutdown: {e}");
    } else {
        println!("proxy: admisión cerrada y requests drenados");
    }

    // Posterior a la seña: flush durable del audit store (B) antes de morir.

    // Posterior a la señal de parada: flush durable del audit store (B).
    // Si un flush falla, el daemon NO anuncia éxito (fix review v5 #4): la
    // pérdida de auditoría se reporta como error, no como cierre limpio.
    if let Some(store) = store_opt {
        store.begin_closing();
        match store.flush_durable().await {
            Ok(()) => println!("audit store: flush durable completado"),
            Err(e) => {
                eprintln!("audit store: flush error en shutdown: {e}");
                remove_runtime_files();
                return Err(format!("Cerberus detenido con error de auditoría: {e}"));
            }
        }
        match store.close().await {
            Ok(()) => println!("audit store: writer cerrado"),
            Err(e) => {
                eprintln!("audit store: close error: {e}");
                remove_runtime_files();
                return Err(format!("Cerberus detenido con error de cierre de auditoría: {e}"));
            }
        }
    }
    remove_runtime_files();
    println!("Cerberus detenido (graceful)");
    Ok("Cerberus detenido (graceful, mutación flusheada)".to_string())
}

// ─── Comandos `cerberus pack` (F7: install/list/rollback) ───────────────────

/// `cerberus pack install <signed.json>` — verifica firma contra
/// `CERBERUS_PACK_TRUST_ROOT` y fusiona las reglas en el engine activo.
/// Gated por licencia: los packs requieren tier Pro (open-core).
///
/// # Errors
///
/// Error si la licencia no es Pro, el pack es inválido, no hay trust root o
/// las reglas no compilan.
pub(crate) async fn pack_install(pack_file: &str) -> Result<String, String> {
    let license = load_license(Some(&license_path()));
    require_pro_for_pack_ops(&license).map_err(|e| format!("pack install aborted: {e}"))?;
    let packs = open_packs_manager()?;
    if let Some(root) = env_nonempty("CERBERUS_PACK_TRUST_ROOT") {
        // Rehidratar lo instalado (historial de engines) antes de sumar el nuevo.
        packs.load_installed_from_dir(&root).await?;
    }
    let before = packs.engine().lock().await.num_rules();
    let signed = PackManager::load_pack_from_file(pack_file)?;
    // `install` exige CERBERUS_PACK_TRUST_ROOT (fail-closed si falta).
    packs.install(signed).await?;
    let after = packs.engine().lock().await.num_rules();
    Ok(format!("pack instalado: reglas del engine {before} → {after}"))
}

/// `cerberus pack list` — lista los packs firmados presentes en
/// `~/.cerberus/packs` y su estado de verificación frente al trust root.
///
/// # Errors
///
/// Devuelve error solo si el directorio no se puede leer.
pub(crate) fn pack_list() -> Result<String, String> {
    let _ = open_packs_manager()?; // garantiza el layout de packs (o falla rápido).
    let dir = packs_dir();
    let mut entries = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| format!("cannot read packs dir {}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "json") {
            entries.push(path);
        }
    }
    if entries.is_empty() {
        return Ok("no se encontraron rule packs en ~/.cerberus/packs.".to_string());
    }
    entries.sort();
    let root = env_nonempty("CERBERUS_PACK_TRUST_ROOT");
    let mut out = String::from("Rule packs:\n");
    for path in entries {
        let name = match PackManager::load_pack_from_file(&path) {
            Ok(signed) => {
                let verified = root
                    .as_deref()
                    .is_some_and(|r| signed.verify_with_trusted_root(r).is_ok());
                let pack = root.as_deref().and_then(|r| signed.extract_with_root(r).ok());
                let label = pack.map_or_else(
                    || name_from_path(&path),
                    |p| format!("{} v{}", p.metadata.name, p.metadata.version),
                );
                match (root.is_some(), verified) {
                    (true, true) => format!("  {label} ✓ firma válida"),
                    (true, false) => format!("  {label} ✗ firma inválida (rechazado en boot)"),
                    (false, _) => format!("  {label} sin validar (falta CERBERUS_PACK_TRUST_ROOT)"),
                }
            }
            Err(e) => format!("  {} (inválido: {e})", name_from_path(&path)),
        };
        out.push_str(&name);
        out.push('\n');
    }
    Ok(out)
}

/// Gate Pro para operaciones de rule packs (hallazgo v6): install y rollback
/// mutan el engine activo (beneficio Pro). list es solo-lectura y queda libre.
fn require_pro_for_pack_ops(license: &LicenseManager) -> Result<(), String> {
    if license.is_pro() {
        Ok(())
    } else {
        Err("los rule packs requieren una licencia Pro (open-core). Visita 'cerberus license'.".to_string())
    }
}

/// Rebasar el engine activo del proxy en caliente (hot-reload, fix review v5 +
/// v6.1): las reglas del `new_engine` (defaults + packs) pasan a ser la BASE y
/// la política persistida del operador (categorías, overrides y reglas custom)
/// se re-aplica encima.
///
/// Helper **síncrono** a propósito: el guard del `RwLock` de std nunca cruza un
/// `await` (el futuro del worker debe seguir siendo `Send`).
///
/// Devuelve el número de reglas del engine recién activado.
fn rebase_live_engine(
    control: &cerberus_proxy::detection_policy::EngineControl,
    policy_source: &RwLock<ProxyConfig>,
    new_engine: &CompiledEngine,
) -> Result<usize, String> {
    // Mantener el read-lock hasta terminar el rebase serializa esta
    // publicación con `commit_policy`, que conserva el write-lock durante
    // compile → persist → publish. Si clonásemos la policy y soltásemos el
    // lock antes, un PUT concurrente podría publicar base-vieja/policy-nueva
    // y acto seguido este worker sobrescribirla con base-nueva/policy-vieja.
    let cfg = policy_source.read().unwrap_or_else(std::sync::PoisonError::into_inner);
    control.rebase(new_engine.rules().to_vec(), &cfg.policy)
}

/// Nombre (sin extensión) de un archivo de pack para el `pack list`.
fn name_from_path(path: &std::path::Path) -> String {
    path.file_name().and_then(|s| s.to_str()).map_or_else(
        || path.display().to_string(),
        |s| s.trim_end_matches(".json").to_string(),
    )
}

/// `cerberus pack rollback` — revierte al engine anterior (último install).
///
/// # Errors
///
/// Devuelve error si no hay historial de engines que revertir.
pub(crate) async fn pack_rollback() -> Result<String, String> {
    // Gate Pro (hallazgo v6): rollback reactiva una versión de pack, beneficio
    // Pro también en el modo local sin daemon (open-core).
    let license = load_license(Some(&license_path()));
    require_pro_for_pack_ops(&license).map_err(|e| format!("pack rollback aborted: {e}"))?;
    let packs = open_packs_manager()?;
    if let Some(root) = env_nonempty("CERBERUS_PACK_TRUST_ROOT") {
        packs.load_installed_from_dir(&root).await?;
    }
    packs.rollback().await?;
    let rules = packs.engine().lock().await.num_rules();
    Ok(format!("pack rollback ejecutado: reglas del engine {rules}"))
}

/// Detener el daemon (F4 multiplataforma): delega en
/// `platform::stop_process_graceful` — en unix envía **SIGTERM** (no SIGKILL)
/// para que el daemon haga el flush+close graceful y fuerza kill solo si el
/// proceso no sale en ~5s; en windows `taskkill` sin `/F` primero y `/F` como
/// fallback. En las 3 plataformas limpia el pid file y el endpoint file.
///
/// # Errors
///
/// Devuelve error si no hay PID file o no se puede matar el proceso.
pub(crate) fn stop() -> Result<String, String> {
    let pid_path = pid_path();
    if !pid_path.exists() {
        return Err("Cerberus no está corriendo (no hay PID file).".to_string());
    }

    let pid_str = fs::read_to_string(&pid_path).map_err(|e| format!("cannot read PID: {e}"))?;
    let pid: u32 = pid_str.trim().parse().map_err(|e| format!("invalid PID: {e}"))?;

    // Centralizado en `platform` (un solo binario multiplataforma): en unix
    // SIGTERM → espera ≤5s → SIGKILL; en windows taskkill sin /F → espera
    // ≤5s → taskkill /F. Loop de apagado compartido, no duplicado.
    platform::stop_process_graceful(pid)?;

    remove_runtime_files();
    Ok(format!("Cerberus detenido (PID {pid})."))
}

/// ¿El proceso con `pid` sigue vivo? (delegado a `platform::process_alive`:
/// `kill -0` en unix, `tasklist /FI "PID eq N"` en Windows).
fn process_alive(pid: u32) -> bool {
    platform::process_alive(pid)
}

/// Mostrar el estado del daemon.
#[must_use]
pub(crate) fn status() -> String {
    if !pid_path().exists() {
        return format!("Cerberus: {}", console_style("STOPPED", "red"));
    }
    let pid_str = fs::read_to_string(pid_path()).unwrap_or_default();
    let pid = pid_str.trim();

    if is_running() {
        format!("Cerberus: {} (PID {})", console_style("RUNNING", "green"), pid)
    } else {
        remove_runtime_files();
        format!("Cerberus: {} (PID {pid} stale)", console_style("STOPPED", "red"))
    }
}

/// ¿El daemon está corriendo? (pid file + proceso vivo).
pub(crate) fn is_running() -> bool {
    let pid_path = pid_path();
    if !pid_path.exists() {
        return false;
    }
    let Ok(pid_str) = fs::read_to_string(&pid_path) else {
        return false;
    };
    let Ok(pid) = pid_str.trim().parse::<u32>() else {
        return false;
    };
    process_alive(pid)
}

/// Aplicar estilo de consola (ANSI basic).
fn console_style(text: &str, color: &str) -> String {
    match color {
        "green" => format!("\x1b[32m{text}\x1b[0m"),
        "red" => format!("\x1b[31m{text}\x1b[0m"),
        "yellow" => format!("\x1b[33m{text}\x1b[0m"),
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guard para serializar los tests que mutan `std::env` (global del proceso).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn require_pro_gate_for_pack_ops() {
        use ed25519_dalek::Signer;
        use serde_json::json;

        let free = LicenseManager::free();
        assert!(
            require_pro_for_pack_ops(&free).is_err(),
            "tier Free debe denegar operaciones de packs (Pro-only)"
        );

        // Contruir una licencia Pro firmada en un temp dir y cargarla.
        let dir = std::env::temp_dir().join(format!(
            "cerb_pro_gate_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keypair = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let license = json!({
            "tier": "pro",
            "email": "t@t.dev",
            "license_id": "t",
            "expires_at": null,
            "features": [],
        });
        let license_json = license.to_string();
        let signature = keypair.sign(license_json.as_bytes());
        let signed = cerberus_packs::license::SignedLicense {
            license_json,
            signature_hex: hex::encode(signature.to_bytes().as_slice()),
            signer_public_key_hex: hex::encode(keypair.verifying_key().as_bytes()),
            owner_public_key_hex: None,
        };
        let path = dir.join("license.json");
        std::fs::write(&path, serde_json::to_string(&signed).unwrap()).unwrap();
        let pro = LicenseManager::from_file_with_root(&path, &hex::encode(keypair.verifying_key().as_bytes()))
            .expect("pro license loads");
        assert!(
            require_pro_for_pack_ops(&pro).is_ok(),
            "tier Pro debe permitir operaciones de packs"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn clear_env() {
        for var in [
            "CERBERUS_LISTEN_HOST",
            "CERBERUS_MODE",
            "CERBERUS_UPSTREAMS",
            "CERBERUS_UPSTREAM_URL",
            "CERBERUS_ADMIN_TOKEN",
            "CERBERUS_RETENTION_DAYS",
            "CERBERUS_LICENSE_PUBLIC_KEY",
            "CERBERUS_LICENSE_PATH",
        ] {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn config_dir_is_dot_cerberus() {
        // config_dir() reads HOME/CERBERUS_CONFIG; acquire ENV_LOCK so a
        // parallel test that mutates HOME can't race this assertion.
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = config_dir();
        #[cfg(not(windows))]
        assert!(dir.to_string_lossy().contains(".cerberus"));
        #[cfg(windows)]
        assert!(dir.to_string_lossy().to_uppercase().contains("CERBERUS"));
    }

    #[test]
    fn pid_path_is_in_config_dir() {
        // pid_path() derives from config_dir() which reads HOME; same guard.
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = pid_path();
        assert_eq!(path, config_dir().join("cerberus.pid"));
        assert!(path.to_string_lossy().ends_with("cerberus.pid"));
    }

    #[test]
    fn console_style_adds_ansi() {
        let styled = console_style("test", "green");
        assert!(styled.contains("32m"));
        assert!(styled.contains("0m"));
    }

    #[test]
    fn load_proxy_config_none_when_no_file() {
        let dir = tempfile::tempdir().expect("create isolated config dir");
        let missing = dir.path().join("config.yaml");

        assert!(load_proxy_config_from(&missing).is_none());
    }

    #[test]
    fn load_proxy_config_reads_explicit_file() {
        let dir = tempfile::tempdir().expect("create isolated config dir");
        let config = dir.path().join("config.yaml");
        std::fs::write(&config, "mode: shadow\n").expect("write isolated config");

        let loaded = load_proxy_config_from(&config).expect("load isolated config");
        assert_eq!(loaded.mode, OperationMode::Shadow);
    }

    #[test]
    fn process_alive_for_current_process() {
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn packs_dir_is_under_config_dir() {
        assert_eq!(packs_dir(), config_dir().join("packs"));
    }

    // ─── Fix review v4, hallazgo 5: merge real de config.yaml ───────────────

    #[test]
    fn resolve_config_preserves_yaml_fields() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();
        let yaml = concat!(
            "listen: 127.0.0.1:9999\n",
            "mode: shadow\n",
            "fail_policy: open\n",
            "health_path: /custom-health\n",
            "max_body_bytes: 4096\n",
            "upstreams:\n",
            "  anthropic:\n",
            "    url: https://api.anthropic.com\n",
            "  openai:\n",
            "    url: https://api.openai.com\n",
        );
        let file_cfg = ProxyConfig::parse(yaml).expect("parse yaml");
        let cfg = resolve_config(8787, Some(file_cfg)).expect("resolve");

        // Campos del YAML que ANTES se perdían con `..default()`:
        assert_eq!(cfg.mode, OperationMode::Shadow);
        assert_eq!(cfg.fail_policy, cerberus_proxy::config::FailPolicy::Open);
        assert_eq!(cfg.health_path, "/custom-health");
        assert_eq!(cfg.max_body_bytes, Some(4096));

        // Listen: host del archivo + port del CLI.
        assert_eq!(cfg.listen, "127.0.0.1:8787");
        // Upstreams del YAML conservados.
        assert_eq!(cfg.upstreams.len(), 2);
        // Sin env de token → el YAML no inyecta token.
        assert!(cfg.admin_token.is_none());
        clear_env();
    }

    #[test]
    fn resolve_config_env_overrides_mode_host_upstreams_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();

        std::env::set_var("CERBERUS_LISTEN_HOST", "0.0.0.0");
        std::env::set_var("CERBERUS_MODE", "enforce");
        std::env::set_var("CERBERUS_UPSTREAM_URL", "https://api.example.com");
        std::env::set_var("CERBERUS_ADMIN_TOKEN", "s3cr3t-admin-token-1234567890");

        let cfg = resolve_config(9000, None).expect("resolve");
        assert_eq!(cfg.listen, "0.0.0.0:9000");
        assert_eq!(cfg.mode, OperationMode::Enforce);
        assert_eq!(cfg.admin_token.as_deref(), Some("s3cr3t-admin-token-1234567890"));
        // URL base → 3 upstreams (openai/anthropic/default).
        assert!(cfg.upstreams.contains_key("openai"));
        assert!(cfg.upstreams.contains_key("anthropic"));
        assert!(cfg.upstreams.contains_key("default"));
        clear_env();
    }

    #[test]
    fn resolve_config_errors_without_upstreams() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();
        let err = resolve_config(8787, None).expect_err("debe fallar");
        assert!(err.contains("upstreams"), "got: {err}");
        clear_env();
    }

    #[test]
    fn retention_days_default_and_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();
        assert_eq!(retention_days_from_env(), 90);
        std::env::set_var("CERBERUS_RETENTION_DAYS", "30");
        assert_eq!(retention_days_from_env(), 30);
        std::env::set_var("CERBERUS_RETENTION_DAYS", "garbage");
        assert_eq!(retention_days_from_env(), 90);
        clear_env();
    }

    // ─── F7 en el producto: licensing + packs (code review item 12) ────────

    fn test_keypair() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Firmar una licencia Pro en `dir/license.json` y devolver (ruta, root hex).
    fn write_signed_pro_license(dir: &std::path::Path) -> (PathBuf, String) {
        use ed25519_dalek::Signer;

        let license = cerberus_packs::license::License {
            tier: cerberus_packs::license::LicenseTier::Pro,
            email: "dev@cerberus.dev".to_string(),
            license_id: "f7-integration".to_string(),
            expires_at: None,
            features: Vec::new(),
        };
        let license_json = serde_json::to_string(&license).expect("serialize license");
        let keypair = test_keypair();
        let signature = keypair.sign(license_json.as_bytes());
        let signed = cerberus_packs::license::SignedLicense {
            license_json,
            signature_hex: hex::encode(signature.to_bytes().as_slice()),
            signer_public_key_hex: hex::encode(keypair.verifying_key().as_bytes()),
            owner_public_key_hex: None,
        };
        let path = dir.join("license.json");
        std::fs::write(&path, serde_json::to_string(&signed).expect("serialize signed license"))
            .expect("write license");
        (path, hex::encode(keypair.verifying_key().as_bytes()))
    }

    /// Directorio temporal único (std only, sin dep extra).
    fn temp_dir(prefix: &str) -> PathBuf {
        let mut d = std::env::temp_dir().join(format!(
            "cerberus_{prefix}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&d).expect("create temp dir");
        d = d.canonicalize().unwrap_or(d);
        d
    }

    #[test]
    fn license_wired_from_signed_file_at_boot() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();
        let dir = temp_dir("license_wired");
        let (license_file, root_hex) = write_signed_pro_license(&dir);

        // Arranque como el daemon: path via CERBERUS_LICENSE_PATH + trust root
        // via CERBERUS_LICENSE_PUBLIC_KEY → la licencia Pro se activa.
        std::env::set_var("CERBERUS_LICENSE_PUBLIC_KEY", &root_hex);
        std::env::set_var("CERBERUS_LICENSE_PATH", &license_file);
        assert_eq!(license_path(), license_file);

        let mgr = load_license(Some(license_file.as_path()));
        assert!(mgr.is_pro(), "F7: licencia firmada debe activar tier Pro en el daemon");
        assert!(
            license_summary(&mgr).contains("tier=pro"),
            "log del arranque debe incluir tier=pro: {}",
            license_summary(&mgr)
        );

        // Fail-open: firma no verificable (sin trust root) → Free, no panic.
        std::env::remove_var("CERBERUS_LICENSE_PUBLIC_KEY");
        let fallback = load_license(Some(license_file.as_path()));
        assert!(
            !fallback.is_pro(),
            "sin trust root el daemon debe caer a Free (fail-open)"
        );
        assert!(license_summary(&fallback).contains("tier=free"));

        // Archivo ausente → Free.
        let missing = dir.join("nope.json");
        assert!(!load_license(Some(&missing)).is_pro());

        std::env::remove_var("CERBERUS_LICENSE_PUBLIC_KEY");
        std::env::remove_var("CERBERUS_LICENSE_PATH");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn license_without_file_falls_back_to_free() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();
        let missing = std::env::temp_dir().join("cerberus-absent-license.json");
        let mgr = load_license(Some(&missing));
        assert_eq!(mgr.tier(), cerberus_packs::license::LicenseTier::Free);
        assert!(license_summary(&mgr).contains("tier=free"));
    }
}
