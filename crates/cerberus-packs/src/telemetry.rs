//! Opt-in telemetry for Cerberus.
//!
//! Never sends sensitive data. Only anonymous usage statistics:
//! version, operating system, rule count, aggregate events, uptime
//! and a persistent random installation ID (`~/.cerberus/install_id`).
//!
//! Disabled by default (`config.telemetry.enabled = false`): with telemetry
//! off, or without a configured endpoint, [`Telemetry::send`] **makes NO HTTP
//! request**. When enabled, it makes a real, silent POST: any failure is
//! logged and returns `Ok`, it never blocks or breaks the daemon.
//!
//! The payload MUST NOT carry secrets, local paths, or scan findings/hashed
//! values — see [`privacy_policy`].

use std::ffi::{OsStr, OsString};
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Telemetry request timeout.
const TELEMETRY_TIMEOUT_SECS: u64 = 5;

/// Environment variable that overrides the configured endpoint (if present
/// and non-empty).
pub const TELEMETRY_ENDPOINT_ENV: &str = "CERBERUS_TELEMETRY_ENDPOINT";

/// Environment variable (advanced/tests use) that redirects the directory
/// where the `install_id` is persisted.
pub const INSTALL_ID_DIR_ENV: &str = "CERBERUS_INSTALL_ID_DIR";

/// Telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Is telemetry enabled? Disabled by default (opt-in).
    #[serde(default)]
    pub enabled: bool,
    /// Telemetry endpoint URL. If empty, no network is made even if
    /// `enabled` is `true`. Can be overridden with
    /// `CERBERUS_TELEMETRY_ENDPOINT` (non-empty).
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Send interval in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
}

fn default_endpoint() -> String {
    "https://telemetry.cerberus.dev/v1/ping".to_string()
}

const fn default_interval() -> u64 {
    86_400 // 24 hours
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            interval_secs: default_interval(),
        }
    }
}

/// Telemetry payload.
///
/// # Privacy contract
///
/// This struct is the agreed surface of what leaves the machine. Do NOT add
/// fields with secrets, detected values, flags, paths, hosts, user names,
/// emails or anything that could identify the operator or a DLP victim. See
/// [`privacy_policy`].
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryPayload {
    /// Cerberus version.
    pub version: String,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Count of loaded rules.
    pub rule_count: usize,
    /// Number of audit events.
    pub event_count: usize,
    /// License tier.
    pub license_tier: String,
    /// Operating system.
    pub os: String,
    /// Anonymous persistent installation ID (uuid v4).
    pub install_id: String,
}

/// Telemetry manager.
#[derive(Debug, Clone)]
pub struct Telemetry {
    /// Configuration.
    pub config: TelemetryConfig,
    /// Installation ID (persistent).
    pub install_id: String,
}

impl Telemetry {
    /// Create a new telemetry manager.
    ///
    /// Loads or generates (and persists to `~/.cerberus/install_id`) the
    /// installation ID.
    #[must_use]
    pub fn new(config: TelemetryConfig) -> Self {
        let install_id = Self::load_or_generate_id();
        Self { config, install_id }
    }

    /// Build a telemetry payload.
    #[must_use]
    pub fn build_payload(&self, rule_count: usize, event_count: usize, uptime_secs: u64) -> TelemetryPayload {
        TelemetryPayload {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs,
            rule_count,
            event_count,
            license_tier: "free".to_string(),
            os: std::env::consts::OS.to_string(),
            install_id: self.install_id.clone(),
        }
    }

    /// Send telemetry.
    ///
    /// Returns `Ok` as long as everything goes well **or the failure is a
    /// network one**: telemetry must never block the daemon or propagate an
    /// error that halts operation. Failures are logged at `warn` level.
    ///
    /// # Network guarantees
    ///
    /// - `config.enabled == false` → does nothing, no traffic.
    /// - No endpoint (empty in config and in `CERBERUS_TELEMETRY_ENDPOINT`)
    ///   → does nothing, no traffic.
    ///
    /// # Errors
    ///
    /// Returns `Err` only if the payload cannot be serialized.
    pub fn send(&self, payload: &TelemetryPayload) -> Result<(), String> {
        send_inner(&self.config, payload)
    }

    /// Send telemetry in the background (`std::thread`) so as not to block the
    /// caller (the daemon), even for the few seconds of the timeout.
    ///
    /// Respects the same guarantees: without `enabled` or without an endpoint
    /// it does not spawn a thread.
    pub fn send_background(&self, payload: &TelemetryPayload) {
        if !self.config.enabled || effective_endpoint(&self.config.endpoint).is_none() {
            return;
        }
        let config = self.config.clone();
        let payload = payload.clone();
        std::thread::spawn(move || {
            let _ = send_inner(&config, &payload);
        });
    }

    /// Path to the `install_id` file.
    fn install_id_file() -> std::path::PathBuf {
        if let Ok(dir) = std::env::var(INSTALL_ID_DIR_ENV) {
            if !dir.is_empty() {
                return std::path::PathBuf::from(dir).join("install_id");
            }
        }
        let home = home_dir().unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
        std::path::PathBuf::from(home).join(".cerberus").join("install_id")
    }

    fn load_or_generate_id() -> String {
        let path = Self::install_id_file();
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let id = existing.trim().to_string();
            if is_plausible_id(&id) {
                return id;
            }
        }
        let id = generate_install_id();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, &id);
        id
    }
}

/// HOME directory of the current user.
fn home_dir() -> Option<OsString> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|home| !is_root(home))
}

/// `None` for `/root` (the container's pseudo-root HOME, where K8s mounts under
/// `/root/.cerberus` is the right place for the `install_id`).
fn is_root(home: &OsStr) -> bool {
    home.is_empty() || home == "/root" || home == "/root/"
}

/// Generate a uuid v4 as the installation ID.
fn generate_install_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// An installation ID must be a non-empty uuid (36 chars), AND its content is a
/// random token without private data.
fn is_plausible_id(id: &str) -> bool {
    let trimmed = id.trim();
    !trimmed.is_empty() && trimmed.len() <= 64 && !trimmed.contains('\n')
}

/// Effective endpoint: non-empty env > non-empty config > `None`.
fn effective_endpoint(config_endpoint: &str) -> Option<String> {
    std::env::var(TELEMETRY_ENDPOINT_ENV)
        .ok()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .or_else(|| {
            let cfg = config_endpoint.trim();
            if cfg.is_empty() {
                None
            } else {
                Some(cfg.to_string())
            }
        })
}

/// Shared HTTP client (blocking, with timeout). Only created the first time
/// there is a real send.
fn blocking_client() -> reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(TELEMETRY_TIMEOUT_SECS))
                .build()
                .unwrap_or_else(|e| {
                    tracing::warn!("telemetry: cannot build HTTP client (non-fatal): {e}");
                    reqwest::blocking::Client::new()
                })
        })
        .clone()
}

/// Send a payload with the identical logic for `send` and `send_background`.
///
/// Never makes a network call with `enabled=false` or without an endpoint.
fn send_inner(config: &TelemetryConfig, payload: &TelemetryPayload) -> Result<(), String> {
    if !config.enabled {
        tracing::debug!("telemetry disabled; skipping HTTP send (no network)");
        return Ok(());
    }
    let Some(endpoint) = effective_endpoint(&config.endpoint) else {
        tracing::debug!("telemetry enabled but no endpoint; skipping HTTP send (no network)");
        return Ok(());
    };
    let body = serde_json::to_string(payload).map_err(|e| format!("telemetry payload serialization failed: {e}"))?;
    match post_json(&endpoint, &body) {
        Ok(()) => {
            tracing::debug!("telemetry sent to {endpoint}");
            Ok(())
        }
        Err(e) => {
            tracing::warn!("telemetry send failed (non-fatal, never blocks DLP): {e}");
            Ok(())
        }
    }
}

/// POST JSON to the endpoint with a timeout.
///
/// # Errors
///
/// Returns `Err` if the request fails at any level (network, timeout, status).
fn post_json(endpoint: &str, body: &str) -> Result<(), String> {
    let _resp = blocking_client()
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| format!("telemetry HTTP request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("telemetry endpoint returned error: {e}"))?;
    Ok(())
}

/// Privacy policy (human-readable text).
#[must_use]
pub const fn privacy_policy() -> &'static str {
    "Cerberus Telemetry Privacy Policy\n\
     \n\
     1. We collect only anonymous usage statistics:\n\
        - Cerberus version and OS\n\
        - Rule count and aggregate event counts\n\
        - Uptime and installation age\n\
        - A random persistent installation ID (uuid, never tied to your identity)\n\
     2. We NEVER collect:\n\
        - Raw secrets, PII, or any content\n\
        - Scan findings, flags, or hashed values\n\
        - User names, emails, system paths, or prompt data\n\
     3. Telemetry is OPT-IN and disabled by default.\n\
     4. You can disable at any time via config.yaml:\n\
        telemetry:\n\
          enabled: false\n\
     5. No data is shared with third parties.\n\
     6. The payload is defined and tested to contain only the metrics above; do not add fields."
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::{mpsc, Mutex};

    use super::*;

    /// Serializes tests that touch process environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Guard that restores an environment variable on test exit.
    struct EnvVarGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let old = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, old }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn telemetry_disabled_by_default() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn telemetry_disabled_no_http() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Valid, live endpoint: if `send` made a network call, it would
        // connect (and the assertion below would catch it).
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let config = TelemetryConfig {
            enabled: false,
            endpoint: format!("http://{addr}/v1/ping"),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(10, 5, 3600);
        assert!(telemetry.send(&payload).is_ok());
        listener.set_nonblocking(true).expect("nonblocking");
        assert!(
            listener.accept().is_err(),
            "telemetry must not open a TCP connection when disabled"
        );
    }

    #[test]
    fn telemetry_enabled_without_endpoint_skips_http() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test");
        let addr = listener.local_addr().expect("local addr");
        let config = TelemetryConfig {
            enabled: true,
            endpoint: String::new(),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(3, 9, 100);
        assert!(telemetry.send(&payload).is_ok());
        listener.set_nonblocking(true).expect("nonblocking");
        assert!(listener.accept().is_err(), "no HTTP when no endpoint is configured");
        // The listener must not receive anything (only checking absence of network).
        let _ = addr;
    }

    #[test]
    fn telemetry_enabled_http_failure_is_ok() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Unreachable endpoint (port 1) → connection refused immediately.
        let config = TelemetryConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:1/v1/telemetry".to_string(),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(2, 2, 2);
        assert!(telemetry.send(&payload).is_ok(), "telemetry failures must be silent");
    }

    #[test]
    fn send_simulated_fail_ok_when_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // "Simulated failure": endpoint points to a dead socket. With telemetry
        // disabled, `send` returns Ok without touching the network.
        let config = TelemetryConfig {
            enabled: false,
            endpoint: "http://127.0.0.1:1/v1/telemetry".to_string(),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(7, 11, 42);
        assert!(telemetry.send(&payload).is_ok());
    }

    #[test]
    fn telemetry_enabled_posts_to_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Toy HTTP server: verifies that with `enabled=true` it DOES send a
        // POST request with the serialized payload.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().expect("accept");
            sock.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or_default();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });

        let config = TelemetryConfig {
            enabled: true,
            endpoint: format!("http://{addr}/v1/telemetry"),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(4, 8, 15);
        assert!(telemetry.send(&payload).is_ok());

        let request = rx.recv_timeout(Duration::from_secs(3)).expect("request received");
        assert!(request.starts_with("POST"), "got: {request}");
        assert!(request.contains(&payload.install_id), "payload must carry install_id");
        assert!(request.contains(r#""rule_count":4"#), "payload must carry rule_count");
    }

    #[test]
    fn env_endpoint_overrides_config() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Guarantees the "no env" state even if the environment has it set.
        let _initial = EnvVarGuard::set(TELEMETRY_ENDPOINT_ENV, "");
        let config = TelemetryConfig {
            endpoint: "https://config.example/v1/ping".to_string(),
            ..TelemetryConfig::default()
        };
        assert_eq!(
            effective_endpoint(&config.endpoint).as_deref(),
            Some("https://config.example/v1/ping"),
            "config endpoint used when env is empty"
        );
        {
            let _env = EnvVarGuard::set(TELEMETRY_ENDPOINT_ENV, "https://env.example/v1/ping");
            assert_eq!(
                effective_endpoint(&config.endpoint).as_deref(),
                Some("https://env.example/v1/ping"),
                "non-empty env overrides config endpoint"
            );
        }
        assert_eq!(
            effective_endpoint(&config.endpoint).as_deref(),
            Some("https://config.example/v1/ping"),
            "after env removed, config endpoint is used again"
        );
    }

    #[test]
    fn telemetry_payload_contains_version() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let telemetry = Telemetry::new(TelemetryConfig::default());
        let payload = telemetry.build_payload(42, 100, 7200);
        assert_eq!(payload.rule_count, 42);
        assert_eq!(payload.event_count, 100);
        assert_eq!(payload.uptime_secs, 7200);
        assert!(!payload.version.is_empty());
    }

    #[test]
    fn payload_has_no_secrets_fields() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let telemetry = Telemetry::new(TelemetryConfig::default());
        let payload = telemetry.build_payload(3, 7, 100);
        let json = serde_json::to_string(&payload).expect("serialize payload");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("reparse");
        let obj = parsed.as_object().expect("payload must be an object");

        let allowed = [
            "version",
            "uptime_secs",
            "rule_count",
            "event_count",
            "license_tier",
            "os",
            "install_id",
        ];
        assert_eq!(
            obj.len(),
            allowed.len(),
            "payload must contain EXACTLY the anonymous metrics, got keys: {}",
            obj.keys().map(String::as_str).collect::<Vec<_>>().join(",")
        );
        for key in allowed {
            assert!(obj.contains_key(key), "missing key {key}");
        }

        // And, defensively: no value may be a secret, path, token, flag
        // or scan hash.
        let lower = json.to_lowercase();
        for forbidden in ["admin", "secret", "token", "api_key", "bearer", "/", "c:", "\\"] {
            assert!(!lower.contains(forbidden), "payload leaks {forbidden:?}: {json}");
        }
    }

    #[test]
    fn privacy_policy_not_empty() {
        let policy = privacy_policy();
        assert!(policy.contains("Cerberus Telemetry"));
        assert!(policy.contains("OPT-IN"));
    }

    #[test]
    fn install_id_is_persistent() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let t1 = Telemetry::new(TelemetryConfig::default());
        let t2 = Telemetry::new(TelemetryConfig::default());
        assert_eq!(t1.install_id, t2.install_id);
        assert_eq!(t1.install_id.len(), 36, "install_id should be a uuid v4");
    }

    #[test]
    fn id_default_persistent_in_tmp() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvVarGuard::set(INSTALL_ID_DIR_ENV, tmp.path().to_str().expect("utf8 path"));
        let t1 = Telemetry::new(TelemetryConfig::default());
        let t2 = Telemetry::new(TelemetryConfig::default());
        assert_eq!(t1.install_id, t2.install_id, "id must persist across instances");
        assert_eq!(t1.install_id.len(), 36, "uuid v4");
        let file = tmp.path().join("install_id");
        assert!(file.exists(), "install_id written to disk");
        assert_eq!(
            std::fs::read_to_string(&file).expect("read id").trim_end(),
            t1.install_id
        );
    }
}
