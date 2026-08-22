//! `cerberus pack` — cliente HTTP del control plane (revisor v6).
//!
//! Cuando el daemon está en marcha, el CLI es un CLIENTE del control plane del
//! daemon: NO abre otro `PackManager` ni toca disco. Las rutas `/api/packs/*`
//! las sirve el worker del daemon, que es el ÚNICO escritor del manifest en
//! runtime (la conmutación del engine vivo la hace el propio worker). Sin
//! daemon (modo local, un solo proceso) el CLI delega en `daemon::pack_*`.
//!
//! v6.1 — `install` envía los **bytes del pack firmado**, no un path. El path
//! lo resuelve el CLIENTE contra SU cwd (canonicalizado localmente); el
//! control plane nunca interpreta rutas ajenas ni depende de compartir
//! filesystem con el CLI. El contrato de cable vive en
//! [`cerberus_packs::wire`].

use std::process::Command as StdCommand;

use reqwest::Client;

use crate::daemon::{config_dir, pid_path};
use cerberus_packs::wire::{
    ControlPlaneEndpoint, PackInstallRequest, ENDPOINT_FILE, MAX_PACK_BYTES, PACK_INSTALL_PATH, PACK_LIST_PATH,
    PACK_ROLLBACK_PATH,
};
use cerberus_proxy::config::ProxyConfig;

const ADMIN_TOKEN_HEADER: &str = "x-cerberus-admin-token";
const DEFAULT_PORT: u16 = 8787;

/// ¿El daemon está corriendo? (pid file presente + proceso vivo).
#[must_use]
pub(crate) fn daemon_is_running() -> bool {
    let pid_path = pid_path();
    if !pid_path.exists() {
        return false;
    }
    let Ok(pid_str) = std::fs::read_to_string(&pid_path) else {
        return false;
    };
    let Ok(pid) = pid_str.trim().parse::<u32>() else {
        return false;
    };
    process_alive(pid)
}

/// ¿El proceso con `pid` sigue vivo? (`kill -0` en unix).
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let output = StdCommand::new("kill").arg("-0").arg(pid.to_string()).output();
        matches!(output, Ok(o) if o.status.success())
    }

    #[cfg(windows)]
    {
        let output = StdCommand::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output();
        matches!(output, Ok(o) if !o.stdout.is_empty())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Valor de env no vacío como `Option<String>`.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// De dónde salió el endpoint efectivo (para diagnósticos y tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointSource {
    /// Override explícito por entorno (`CERBERUS_LISTEN`).
    Env,
    /// Descriptor publicado por el daemon (`~/.cerberus/endpoint.json`).
    Descriptor,
    /// `listen` de `~/.cerberus/config.yaml`.
    Config,
    /// Default compilado.
    Default,
}

/// Endpoint efectivo del control plane resuelto por el CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedEndpoint {
    /// Puerto al que hablar.
    pub(crate) port: u16,
    /// Procedencia del puerto.
    pub(crate) source: EndpointSource,
}

impl ResolvedEndpoint {
    /// URL base: SIEMPRE loopback. El daemon puede ligar `0.0.0.0` (Docker),
    /// pero el CLI local nunca sale de `127.0.0.1`.
    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// Ruta del descriptor de endpoint publicado por el daemon.
pub(crate) fn endpoint_descriptor_path() -> std::path::PathBuf {
    config_dir().join(ENDPOINT_FILE)
}

/// Descriptor de endpoint publicado por el daemon, si es legible y válido.
///
/// Fail-safe: un descriptor ausente, corrupto o con puerto 0 no aborta nada —
/// se ignora y la resolución sigue con la config.
fn endpoint_descriptor() -> Option<ControlPlaneEndpoint> {
    let path = endpoint_descriptor_path();
    let raw = std::fs::read_to_string(&path).ok()?;
    match ControlPlaneEndpoint::from_json(&raw) {
        Ok(ep) => Some(ep),
        Err(e) => {
            eprintln!("aviso: {} inválido ({e}); usando la configuración", path.display());
            None
        }
    }
}

/// Descubrir el endpoint efectivo del control plane. Precedencia:
///   1. env `CERBERUS_LISTEN` (formato `host:port`) — override explícito;
///   2. `~/.cerberus/endpoint.json` publicado por el daemon (puerto REAL,
///      incluyendo puertos efímeros o un `listen` cambiado en caliente);
///   3. `listen` de `~/.cerberus/config.yaml`;
///   4. default `8787`.
pub(crate) fn resolve_endpoint() -> ResolvedEndpoint {
    if let Some(listen) = env_nonempty("CERBERUS_LISTEN") {
        return ResolvedEndpoint {
            port: port_from_listen(&listen),
            source: EndpointSource::Env,
        };
    }
    if let Some(ep) = endpoint_descriptor() {
        return ResolvedEndpoint {
            port: ep.port,
            source: EndpointSource::Descriptor,
        };
    }
    if let Some(listen) = config_listen() {
        return ResolvedEndpoint {
            port: port_from_listen(&listen),
            source: EndpointSource::Config,
        };
    }
    ResolvedEndpoint {
        port: DEFAULT_PORT,
        source: EndpointSource::Default,
    }
}

/// El puerto de un `listen` (`host:port`), o el default si no parsea.
#[must_use]
fn port_from_listen(listen: &str) -> u16 {
    cerberus_packs::wire::port_from_listen(listen).unwrap_or(DEFAULT_PORT)
}

/// `listen` de la config.yaml, si existe y parsea.
fn config_listen() -> Option<String> {
    let cfg = config_dir().join("config.yaml");
    if !cfg.exists() {
        return None;
    }
    ProxyConfig::from_file(cfg).ok().map(|c| c.listen)
}

/// Token de admin del control plane: env `CERBERUS_ADMIN_TOKEN` > `admin_token`
/// de la configuración YAML.
#[must_use]
fn admin_token() -> Option<String> {
    if let Some(t) = env_nonempty("CERBERUS_ADMIN_TOKEN") {
        return Some(t);
    }
    config_admin_token()
}

fn config_admin_token() -> Option<String> {
    let cfg = config_dir().join("config.yaml");
    if !cfg.exists() {
        return None;
    }
    ProxyConfig::from_file(cfg).ok().and_then(|c| c.admin_token)
}

/// Base URL del control plane (siempre contra loopback; el puerto denota al
/// daemon). El daemon puede ligar en `0.0.0.0` (Docker) pero el CLI local
/// siempre habla con `127.0.0.1`.
#[must_use]
fn base_url() -> String {
    resolve_endpoint().base_url()
}

/// Enviar un comando de pack al control plane del daemon y devolver su mensaje.
/// `body` véase solo en los POST con payload (install); list/rollback van sin
/// body. Cualquier status no-2xx o `{"error":...}` se propaga como `Err`.
async fn call(method: &str, path: &str, body: Option<String>) -> Result<String, String> {
    let token = admin_token().ok_or_else(|| {
        "el control plane exige un X-Cerberus-Admin-Token: define CERBERUS_ADMIN_TOKEN \
         o 'admin_token' en ~/.cerberus/config.yaml"
            .to_string()
    })?;
    let url = format!("{}{path}", base_url());
    let client = Client::new();
    let resp = if method == "post" {
        let mut r = client.post(&url).header(ADMIN_TOKEN_HEADER, token.as_str());
        if let Some(b) = body {
            r = r.header("content-type", "application/json").body(b);
        }
        r.send()
            .await
            .map_err(|e| format!("control plane request failed: {e}"))?
    } else {
        client
            .get(&url)
            .header(ADMIN_TOKEN_HEADER, token.as_str())
            .send()
            .await
            .map_err(|e| format!("control plane request failed: {e}"))?
    };
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("control plane body read failed: {e}"))?;

    let json: Option<serde_json::Value> = serde_json::from_str(&text).ok();
    match json {
        Some(v) => {
            if status != reqwest::StatusCode::OK {
                return Err(format!("control plane HTTP {status}: {}", json_error(&v, &text)));
            }
            match v.get("status").and_then(|s| s.as_str()) {
                Some("ok") => {
                    let msg = v
                        .get("message")
                        .and_then(|m| m.as_str())
                        .map_or_else(|| text.clone(), ToString::to_string);
                    Ok(msg)
                }
                _ => Err(json_error(&v, &text)),
            }
        }
        None => {
            if status == reqwest::StatusCode::OK {
                Ok(text)
            } else {
                Err(format!("control plane HTTP {status}: {text}"))
            }
        }
    }
}

/// Extraer el campo `error` de un JSON de error del control plane.
#[must_use]
fn json_error(json: &serde_json::Value, fallback: &str) -> String {
    json.get("error")
        .map_or_else(|| fallback.to_string(), |err| format!("{err}"))
}

/// `cerberus pack install <file>` vía control plane, **por bytes**.
///
/// El CLI resuelve el path contra SU cwd (canonicalizándolo), lee el pack
/// firmado y lo envía dentro del body ([`PackInstallRequest`]). El daemon
/// verifica firma, gate de licencia Pro y hace el swap del engine en caliente;
/// nunca abre rutas del cliente ni hereda su cwd. El CLI no abre el
/// `PackManager` (`P1`).
pub(crate) async fn install(pack_file: &str) -> Result<String, String> {
    let request = read_pack_request(pack_file)?;
    let body = request.to_body().map_err(|e| e.to_string())?;
    call("post", PACK_INSTALL_PATH, Some(body)).await
}

/// Leer y validar localmente el pack a instalar, produciendo la request.
///
/// Toda la semántica de rutas es LOCAL: se canonicaliza contra el cwd del CLI
/// (resolviendo relativos y symlinks) y del nombre solo viaja el basename
/// saneado, como etiqueta informativa.
fn read_pack_request(pack_file: &str) -> Result<PackInstallRequest, String> {
    let raw = std::path::Path::new(pack_file);
    let path =
        std::fs::canonicalize(raw).map_err(|e| format!("no se puede resolver el pack '{}': {e}", raw.display()))?;
    let meta = std::fs::metadata(&path).map_err(|e| format!("no se puede leer '{}': {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("'{}' no es un archivo de pack", path.display()));
    }
    if meta.len() > MAX_PACK_BYTES as u64 {
        return Err(format!(
            "pack '{}' demasiado grande: {} bytes (máximo {MAX_PACK_BYTES})",
            path.display(),
            meta.len()
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("no se puede leer '{}': {e}", path.display()))?;
    let origin = path.file_name().and_then(|s| s.to_str());
    PackInstallRequest::from_pack_bytes(&bytes, origin).map_err(|e| format!("pack '{}' inválido: {e}", path.display()))
}

/// `cerberus pack list` vía control plane.
pub(crate) async fn list() -> Result<String, String> {
    call("get", PACK_LIST_PATH, None).await
}

/// `cerberus pack rollback` vía control plane.
pub(crate) async fn rollback() -> Result<String, String> {
    call("post", PACK_ROLLBACK_PATH, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializa los tests que mutan `HOME`/`CERBERUS_LISTEN` (proceso global).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `SignedRulePack` mínimo estructuralmente válido (la firma la verifica el
    /// daemon contra SU trust root; el CLI solo valida la forma).
    fn sample_signed_pack() -> String {
        serde_json::json!({
            "pack_json": r#"{"metadata":{"name":"demo","version":"1.0.0","description":"d","author":"a","published":"2026-01-01","min_engine_version":"0.1.0"},"rules":[]}"#,
            "signature_hex": "aa".repeat(64),
            "signer_public_key_hex": "bb".repeat(32),
        })
        .to_string()
    }

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-cli-pack-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(dir.join(".cerberus")).expect("create home");
        dir
    }

    /// [v6.1] El CLI envía BYTES: la request lleva el pack completo y del path
    /// solo sobrevive el basename informativo.
    #[test]
    fn install_request_carries_bytes_not_path() {
        let home = temp_home("bytes");
        let nested = home.join("some").join("deep dir");
        std::fs::create_dir_all(&nested).expect("mkdir");
        let file = nested.join("demo-pack.json");
        let pack = sample_signed_pack();
        std::fs::write(&file, &pack).expect("write pack");

        let req = read_pack_request(file.to_str().expect("utf8 path")).expect("request");
        assert_eq!(req.pack, pack, "viajan los bytes exactos del pack firmado");
        assert_eq!(req.origin_name.as_deref(), Some("demo-pack.json"));
        let body = req.to_body().expect("body");
        assert!(
            !body.contains("deep dir"),
            "el body NO debe contener la ruta del cliente: {body}"
        );
        // El servidor lo acepta con el mismo contrato.
        let parsed = PackInstallRequest::parse_body(body.as_bytes()).expect("parse server-side");
        assert_eq!(parsed.pack, pack);
        std::fs::remove_dir_all(&home).ok();
    }

    /// El path se canonicaliza LOCALMENTE: un relativo con `..` se resuelve en
    /// el cliente y no viaja semántica de cwd al daemon.
    #[test]
    fn install_request_canonicalizes_locally() {
        let home = temp_home("canon");
        let sub = home.join("sub");
        std::fs::create_dir_all(&sub).expect("mkdir");
        let file = home.join("pack.json");
        std::fs::write(&file, sample_signed_pack()).expect("write");

        let traversal = sub.join("..").join("pack.json");
        let req = read_pack_request(traversal.to_str().expect("utf8")).expect("request");
        assert_eq!(req.origin_name.as_deref(), Some("pack.json"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// Fallo seguro: archivos ausentes, directorios y packs no-pack se rechazan
    /// ANTES de tocar la red, con un mensaje accionable.
    #[test]
    fn install_request_fails_safe() {
        let home = temp_home("failsafe");
        let missing = home.join("nope.json");
        let err = read_pack_request(missing.to_str().expect("utf8")).expect_err("ausente");
        assert!(err.contains("no se puede resolver el pack"), "{err}");

        let dir_err = read_pack_request(home.to_str().expect("utf8")).expect_err("directorio");
        assert!(dir_err.contains("no es un archivo de pack"), "{dir_err}");

        let junk = home.join("junk.json");
        std::fs::write(&junk, "{\"not\":\"a pack\"}").expect("write");
        let junk_err = read_pack_request(junk.to_str().expect("utf8")).expect_err("no es pack");
        assert!(junk_err.contains("inválido"), "{junk_err}");

        let empty = home.join("empty.json");
        std::fs::write(&empty, "").expect("write");
        assert!(read_pack_request(empty.to_str().expect("utf8")).is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    /// Descubrimiento del endpoint efectivo: env > endpoint.json > config.yaml
    /// > default, y el descriptor corrupto degrada sin abortar.
    #[test]
    fn endpoint_discovery_precedence() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("endpoint");
        let prev_home = std::env::var("HOME").ok();
        let prev_listen = std::env::var("CERBERUS_LISTEN").ok();
        std::env::set_var("HOME", &home);
        std::env::remove_var("CERBERUS_LISTEN");

        // 4. default.
        assert_eq!(
            resolve_endpoint(),
            ResolvedEndpoint {
                port: DEFAULT_PORT,
                source: EndpointSource::Default
            }
        );

        // 3. config.yaml.
        std::fs::write(home.join(".cerberus").join("config.yaml"), "listen: 0.0.0.0:9001\n").expect("cfg");
        assert_eq!(
            resolve_endpoint(),
            ResolvedEndpoint {
                port: 9001,
                source: EndpointSource::Config
            }
        );

        // 2. endpoint.json publicado por el daemon (puerto efímero real).
        let ep = ControlPlaneEndpoint::new("0.0.0.0:54321", 4242).expect("endpoint");
        std::fs::write(endpoint_descriptor_path(), ep.to_json().expect("json")).expect("write ep");
        let resolved = resolve_endpoint();
        assert_eq!(
            resolved,
            ResolvedEndpoint {
                port: 54321,
                source: EndpointSource::Descriptor
            }
        );
        assert_eq!(resolved.base_url(), "http://127.0.0.1:54321", "siempre loopback");

        // Descriptor corrupto ⇒ fail-safe hacia la config, sin panic.
        std::fs::write(endpoint_descriptor_path(), "{ not json").expect("write junk");
        assert_eq!(
            resolve_endpoint(),
            ResolvedEndpoint {
                port: 9001,
                source: EndpointSource::Config
            }
        );

        // 1. env gana sobre todo.
        std::env::set_var("CERBERUS_LISTEN", "127.0.0.1:7777");
        assert_eq!(
            resolve_endpoint(),
            ResolvedEndpoint {
                port: 7777,
                source: EndpointSource::Env
            }
        );
        // Un listen sin puerto válido cae al default (no aborta).
        std::env::set_var("CERBERUS_LISTEN", "host:noport");
        assert_eq!(resolve_endpoint().port, DEFAULT_PORT);

        match prev_listen {
            Some(v) => std::env::set_var("CERBERUS_LISTEN", v),
            None => std::env::remove_var("CERBERUS_LISTEN"),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        std::fs::remove_dir_all(&home).ok();
    }
}
