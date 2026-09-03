//! Shared CLI → control-plane HTTP client (F6.B, Appendix B).
//!
//! Every daemon-backed CLI command is a **client of the live daemon's
//! Config API** — the daemon is the single writer of state, exactly like
//! the dashboard (§4.6: "the CLI and dashboard are two fronts over the
//! same Config API"). This module owns the resolution of:
//!
//! - **where** the control plane is (`CERBERUS_LISTEN` env >
//!   `~/.cerberus/endpoint.json` published by the daemon > `listen` from
//!   `config.yaml` > default 8787), always dialed over loopback;
//! - **the admin token** (`CERBERUS_ADMIN_TOKEN` env > `admin_token` from
//!   `config.yaml`) — F6.A fail-closed auth: data `/api/*` routes 401
//!   without it, and the CLI never bypasses the gate;
//! - a **clear unreachable-daemon error** instead of a raw reqwest dump.
//!
//! Moved here from `cli_pack` (F6.B) so every command shares one
//! resolution + error contract; `cli_pack` now delegates.

use reqwest::Client;

use crate::daemon::config_dir;
use cerberus_packs::wire::{ControlPlaneEndpoint, ENDPOINT_FILE};
use cerberus_proxy::config::ProxyConfig;

/// Canonical admin-token header (same constant as the proxy's wire).
pub(crate) const ADMIN_TOKEN_HEADER: &str = "x-cerberus-admin-token";
/// Default control-plane port (matches `cerberus start`).
pub(crate) const DEFAULT_PORT: u16 = 8787;

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
    pub(crate) fn base_url(&self) -> String {
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
pub(crate) fn port_from_listen(listen: &str) -> u16 {
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

/// Non-empty env value as `Option<String>`.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Control plane admin token: env `CERBERUS_ADMIN_TOKEN` > `admin_token`
/// from the YAML configuration.
#[must_use]
pub(crate) fn admin_token() -> Option<String> {
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

/// The error returned when the control plane cannot be reached — actionable
/// instead of a raw reqwest dump (hard rule: "clear error when the daemon
/// is unreachable").
fn unreachable_error(base: &str, e: &reqwest::Error) -> String {
    format!("cannot reach the Cerberus daemon at {base} ({e}) — is it running? Start it with `cerberus start`")
}

/// The error returned when no admin token is available (F6.A fail-closed).
fn missing_token_error() -> String {
    "the control plane requires an X-Cerberus-Admin-Token: set CERBERUS_ADMIN_TOKEN \
     or 'admin_token' in ~/.cerberus/config.yaml"
        .to_string()
}

/// Minimal RFC 3986 path-segment encoding for provider names in
/// `/api/upstreams/{name}` (no new dependency; unreserved chars pass).
#[must_use]
pub(crate) fn encode_path_segment(raw: &str) -> String {
    encode(raw, b"-._~")
}

/// Minimal query-component encoding (`cerberus events --provider/--tool`).
#[must_use]
pub(crate) fn encode_query_component(raw: &str) -> String {
    encode(raw, b"-._~")
}

fn encode(raw: &str, extra_safe: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        if b.is_ascii_alphanumeric() || extra_safe.contains(&b) {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// A resolved control-plane client. Cheap to construct per command.
pub(crate) struct ApiClient {
    base: String,
    token: Option<String>,
    http: Client,
}

impl ApiClient {
    /// Resolve the client from the environment/config (endpoint + token).
    #[must_use]
    pub(crate) fn resolve() -> Self {
        Self {
            base: resolve_endpoint().base_url(),
            token: admin_token(),
            http: Client::new(),
        }
    }

    /// Base URL of the resolved control plane (for messages, e.g. the
    /// dashboard URL).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn base_url(&self) -> &str {
        &self.base
    }

    /// Local base URL for a provider name (`add-provider` prints this so
    /// the operator can paste it into the agent's baseURL, Appendix C).
    #[must_use]
    pub(crate) fn provider_url(&self, name: &str) -> String {
        format!("{}/{}", self.base.trim_end_matches('/'), name)
    }

    /// GET a JSON document from the control plane. Any non-2xx or
    /// `{"error":...}` body becomes `Err`.
    pub(crate) async fn get_json(&self, path: &str) -> Result<serde_json::Value, String> {
        self.request_json("GET", path, None).await
    }

    /// Send a JSON body (POST/PUT/DELETE) and parse the JSON reply.
    pub(crate) async fn send_json(&self, method: &str, path: &str, body: String) -> Result<serde_json::Value, String> {
        self.request_json(method, path, Some(body)).await
    }

    /// Core request: attaches the admin token, returns the parsed JSON,
    /// and maps transport/auth failures to actionable messages.
    async fn request_json(&self, method: &str, path: &str, body: Option<String>) -> Result<serde_json::Value, String> {
        let token = self.token.clone().ok_or_else(missing_token_error)?;
        let url = format!("{}{path}", self.base);
        let mut req = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            other => return Err(format!("unsupported method {other}")),
        };
        req = req.header(ADMIN_TOKEN_HEADER, token.as_str());
        if let Some(b) = body {
            req = req.header("content-type", "application/json").body(b);
        }
        let resp = req.send().await.map_err(|e| unreachable_error(&self.base, &e))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("control plane body read failed: {e}"))?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|_| format!("control plane returned non-JSON (HTTP {status}): {text}"))?;
        if !status.is_success() {
            return Err(format!(
                "control plane HTTP {status}: {}",
                json.get("error").and_then(|e| e.as_str()).unwrap_or(&text)
            ));
        }
        if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
            return Err(err.to_string());
        }
        Ok(json)
    }

    /// GET returning the raw body text (no JSON requirement).
    #[allow(dead_code)]
    pub(crate) async fn get_text(&self, path: &str) -> Result<String, String> {
        let token = self.token.clone().ok_or_else(missing_token_error)?;
        let url = format!("{}{path}", self.base);
        let resp = self
            .http
            .get(&url)
            .header(ADMIN_TOKEN_HEADER, token.as_str())
            .send()
            .await
            .map_err(|e| unreachable_error(&self.base, &e))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("control plane body read failed: {e}"))?;
        if !status.is_success() {
            return Err(format!("control plane HTTP {status}: {text}"));
        }
        Ok(text)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Serializes ALL tests that mutate `HOME`/`APPDATA`/`CERBERUS_*`
    /// (global process state). Shared across modules: `cli_surface` tests
    /// that swap `HOME` take this same lock, so tests in different files
    /// cannot interleave (a real race observed on F6.B).
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp_home(tag: &str) -> std::path::PathBuf {
        // F6.B attempt 2 (security P2-2): unique per CALL — pid + monotonic
        // counter, immune to nanosecond-timestamp collisions between two
        // tests on the same clock tick (a sibling's remove_dir_all could
        // otherwise delete a live home mid-run).
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "cerberus-cli-api-{tag}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            seq
        ));
        // Create both the unix config dir (.cerberus) and the Windows config
        // dir (Cerberus) so config_dir() resolves correctly on either platform.
        std::fs::create_dir_all(dir.join(".cerberus")).expect("create home");
        std::fs::create_dir_all(dir.join("Cerberus")).expect("create home (windows)");
        dir
    }

    /// Effective endpoint discovery: env, endpoint.json, config.yaml,
    /// default (in that order); a corrupt descriptor degrades without
    /// aborting (moved from `cli_pack` with the resolution code — F6.B).
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

    /// Unreachable-daemon errors are actionable (mention the base URL and
    /// `cerberus start`), never a bare transport dump.
    #[tokio::test]
    async fn unreachable_error_message_is_actionable() {
        // Port 1 is privileged and nothing listens there in CI: real
        // connection-refused transport error.
        let err = reqwest::get("http://127.0.0.1:1/")
            .await
            .expect_err("nothing should listen on port 1");
        let msg = unreachable_error("http://127.0.0.1:59999", &err);
        assert!(msg.contains("http://127.0.0.1:59999"), "{msg}");
        assert!(msg.contains("cerberus start"), "{msg}");
    }

    /// The token error tells the operator HOW to authenticate.
    #[test]
    fn missing_token_error_mentions_sources() {
        let msg = missing_token_error();
        assert!(msg.contains("CERBERUS_ADMIN_TOKEN"), "{msg}");
        assert!(msg.contains("admin_token"), "{msg}");
    }
}
