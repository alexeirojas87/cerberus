//! `cerberus pack` — HTTP client of the control plane (reviewer v6).
//!
//! When the daemon is running, the CLI is a CLIENT of the daemon's control
//! plane: it does NOT open another `PackManager` nor touch disk. The
//! `/api/packs/*` routes are served by the daemon's worker, which is the ONLY
//! writer of the manifest at runtime (the live engine swap is done by the
//! worker itself). Without a daemon (local mode, a single process) the CLI
//! delegates to `daemon::pack_*`.
//!
//! v6.1 — `install` sends the **signed pack bytes**, not a path. The path is
//! resolved by the CLIENT against ITS cwd (canonicalized locally); the control
//! plane never interprets foreign paths nor depends on sharing a filesystem
//! with the CLI. The wire contract lives in [`cerberus_packs::wire`].

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

/// Is the daemon running? (pid file present + live process).
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

/// Is the process with `pid` still alive? (`kill -0` on unix).
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

/// Non-empty env value as `Option<String>`.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Where the effective endpoint came from (for diagnostics and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointSource {
    /// Explicit override via environment (`CERBERUS_LISTEN`).
    Env,
    /// Descriptor published by the daemon (`~/.cerberus/endpoint.json`).
    Descriptor,
    /// `listen` from `~/.cerberus/config.yaml`.
    Config,
    /// Compiled default.
    Default,
}

/// Effective control plane endpoint resolved by the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedEndpoint {
    /// Port to talk to.
    pub(crate) port: u16,
    /// Origin of the port.
    pub(crate) source: EndpointSource,
}

impl ResolvedEndpoint {
    /// Base URL: ALWAYS loopback. The daemon may bind `0.0.0.0` (Docker),
    /// but the local CLI never leaves `127.0.0.1`.
    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// Path of the endpoint descriptor published by the daemon.
pub(crate) fn endpoint_descriptor_path() -> std::path::PathBuf {
    config_dir().join(ENDPOINT_FILE)
}

/// Endpoint descriptor published by the daemon, if readable and valid.
///
/// Fail-safe: a missing, corrupt, or port-0 descriptor does not abort
/// anything — it is ignored and resolution continues with the config.
fn endpoint_descriptor() -> Option<ControlPlaneEndpoint> {
    let path = endpoint_descriptor_path();
    let raw = std::fs::read_to_string(&path).ok()?;
    match ControlPlaneEndpoint::from_json(&raw) {
        Ok(ep) => Some(ep),
        Err(e) => {
            eprintln!("warning: {} invalid ({e}); using the config", path.display());
            None
        }
    }
}

/// Discover the effective control plane endpoint. Precedence:
///   1. env `CERBERUS_LISTEN` (format `host:port`) — explicit override;
///   2. `~/.cerberus/endpoint.json` published by the daemon (the REAL port,
///      including ephemeral ports or a `listen` changed at runtime);
///   3. `listen` from `~/.cerberus/config.yaml`;
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

/// The port of a `listen` (`host:port`), or the default if it doesn't parse.
#[must_use]
fn port_from_listen(listen: &str) -> u16 {
    cerberus_packs::wire::port_from_listen(listen).unwrap_or(DEFAULT_PORT)
}

/// `listen` from config.yaml, if it exists and parses.
fn config_listen() -> Option<String> {
    let cfg = config_dir().join("config.yaml");
    if !cfg.exists() {
        return None;
    }
    ProxyConfig::from_file(cfg).ok().map(|c| c.listen)
}

/// Control plane admin token: env `CERBERUS_ADMIN_TOKEN` > `admin_token`
/// from the YAML configuration.
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

/// Control plane base URL (always against loopback; the port identifies the
/// daemon). The daemon may bind `0.0.0.0` (Docker) but the local CLI always
/// talks to `127.0.0.1`.
#[must_use]
fn base_url() -> String {
    resolve_endpoint().base_url()
}

/// Send a pack command to the daemon's control plane and return its message.
/// `body` is only used in POSTs with a payload (install); list/rollback go
/// without a body. Any non-2xx status or `{"error":...}` is propagated as `Err`.
async fn call(method: &str, path: &str, body: Option<String>) -> Result<String, String> {
    let token = admin_token().ok_or_else(|| {
        "the control plane requires an X-Cerberus-Admin-Token: set CERBERUS_ADMIN_TOKEN \
         or 'admin_token' in ~/.cerberus/config.yaml"
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

/// Extract the `error` field from a control plane error JSON.
#[must_use]
fn json_error(json: &serde_json::Value, fallback: &str) -> String {
    json.get("error")
        .map_or_else(|| fallback.to_string(), |err| format!("{err}"))
}

/// `cerberus pack install <file>` via control plane, **by bytes**.
///
/// The CLI resolves the path against ITS cwd (canonicalizing it), reads the
/// signed pack and sends it inside the body ([`PackInstallRequest`]). The
/// daemon verifies the signature, the Pro license gate, and swaps the engine
/// at runtime; it never opens client paths nor inherits its cwd. The CLI does
/// not open the `PackManager` (`P1`).
pub(crate) async fn install(pack_file: &str) -> Result<String, String> {
    let request = read_pack_request(pack_file)?;
    let body = request.to_body().map_err(|e| e.to_string())?;
    call("post", PACK_INSTALL_PATH, Some(body)).await
}

/// Read and locally validate the pack to install, producing the request.
///
/// All path semantics are LOCAL: it is canonicalized against the CLI's cwd
/// (resolving relatives and symlinks) and only the sanitized basename travels
/// from the name, as an informational label.
fn read_pack_request(pack_file: &str) -> Result<PackInstallRequest, String> {
    let raw = std::path::Path::new(pack_file);
    let path = std::fs::canonicalize(raw).map_err(|e| format!("cannot resolve pack '{}': {e}", raw.display()))?;
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read '{}': {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("'{}' is not a pack file", path.display()));
    }
    if meta.len() > MAX_PACK_BYTES as u64 {
        return Err(format!(
            "pack '{}' too large: {} bytes (maximum {MAX_PACK_BYTES})",
            path.display(),
            meta.len()
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read '{}': {e}", path.display()))?;
    let origin = path.file_name().and_then(|s| s.to_str());
    PackInstallRequest::from_pack_bytes(&bytes, origin).map_err(|e| format!("pack '{}' invalid: {e}", path.display()))
}

/// `cerberus pack list` via control plane.
pub(crate) async fn list() -> Result<String, String> {
    call("get", PACK_LIST_PATH, None).await
}

/// `cerberus pack rollback` via control plane.
pub(crate) async fn rollback() -> Result<String, String> {
    call("post", PACK_ROLLBACK_PATH, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate `HOME`/`CERBERUS_LISTEN` (global process).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Minimal structurally valid `SignedRulePack` (the signature is verified
    /// by the daemon against ITS trust root; the CLI only validates the form).
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
        // Create both the unix config dir (.cerberus) and the Windows config
        // dir (Cerberus) so config_dir() resolves correctly on either platform.
        std::fs::create_dir_all(dir.join(".cerberus")).expect("create home");
        std::fs::create_dir_all(dir.join("Cerberus")).expect("create home (windows)");
        dir
    }

    /// [v6.1] The CLI sends BYTES: the request carries the full pack and only
    /// the informational basename survives from the path.
    #[test]
    fn install_request_carries_bytes_not_path() {
        let home = temp_home("bytes");
        let nested = home.join("some").join("deep dir");
        std::fs::create_dir_all(&nested).expect("mkdir");
        let file = nested.join("demo-pack.json");
        let pack = sample_signed_pack();
        std::fs::write(&file, &pack).expect("write pack");

        let req = read_pack_request(file.to_str().expect("utf8 path")).expect("request");
        assert_eq!(req.pack, pack, "the exact signed pack bytes travel");
        assert_eq!(req.origin_name.as_deref(), Some("demo-pack.json"));
        let body = req.to_body().expect("body");
        assert!(
            !body.contains("deep dir"),
            "the body must NOT contain the client path: {body}"
        );
        // The server accepts it with the same contract.
        let parsed = PackInstallRequest::parse_body(body.as_bytes()).expect("parse server-side");
        assert_eq!(parsed.pack, pack);
        std::fs::remove_dir_all(&home).ok();
    }

    /// The path is canonicalized LOCALLY: a relative with `..` is resolved on
    /// the client and no cwd semantics travel to the daemon.
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

    /// Fail-safe: missing files, directories, and non-pack packs are rejected
    /// BEFORE touching the network, with an actionable message.
    #[test]
    fn install_request_fails_safe() {
        let home = temp_home("failsafe");
        let missing = home.join("nope.json");
        let err = read_pack_request(missing.to_str().expect("utf8")).expect_err("missing");
        assert!(err.contains("cannot resolve pack"), "{err}");

        let dir_err = read_pack_request(home.to_str().expect("utf8")).expect_err("directory");
        assert!(dir_err.contains("is not a pack file"), "{dir_err}");

        let junk = home.join("junk.json");
        std::fs::write(&junk, "{\"not\":\"a pack\"}").expect("write");
        let junk_err = read_pack_request(junk.to_str().expect("utf8")).expect_err("not a pack");
        assert!(junk_err.contains("invalid"), "{junk_err}");

        let empty = home.join("empty.json");
        std::fs::write(&empty, "").expect("write");
        assert!(read_pack_request(empty.to_str().expect("utf8")).is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    /// Effective endpoint discovery: env > endpoint.json > config.yaml
    /// > default, and a corrupt descriptor degrades without aborting.
    #[test]
    fn endpoint_discovery_precedence() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("endpoint");
        let prev_home = std::env::var("HOME").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        let prev_listen = std::env::var("CERBERUS_LISTEN").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("APPDATA", &home);
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
        std::fs::write(config_dir().join("config.yaml"), "listen: 0.0.0.0:9001\n").expect("cfg");
        assert_eq!(
            resolve_endpoint(),
            ResolvedEndpoint {
                port: 9001,
                source: EndpointSource::Config
            }
        );

        // 2. endpoint.json published by the daemon (real ephemeral port).
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
        assert_eq!(resolved.base_url(), "http://127.0.0.1:54321", "always loopback");

        // Corrupt descriptor ⇒ fail-safe to the config, no panic.
        std::fs::write(endpoint_descriptor_path(), "{ not json").expect("write junk");
        assert_eq!(
            resolve_endpoint(),
            ResolvedEndpoint {
                port: 9001,
                source: EndpointSource::Config
            }
        );

        // 1. env wins over everything.
        std::env::set_var("CERBERUS_LISTEN", "127.0.0.1:7777");
        assert_eq!(
            resolve_endpoint(),
            ResolvedEndpoint {
                port: 7777,
                source: EndpointSource::Env
            }
        );
        // A listen without a valid port falls back to the default (no abort).
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
        match prev_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        std::fs::remove_dir_all(&home).ok();
    }
}
