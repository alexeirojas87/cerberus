//! Healthcheck endpoint for the proxy.
//!
//! Responds with a status JSON: version, mode, upstreams, uptime.

use std::time::Instant;

use serde::Serialize;

use crate::config::{OperationMode, ProxyConfig};

/// Proxy status for the healthcheck.
#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    /// Overall status.
    pub status: &'static str,
    /// Proxy version.
    pub version: &'static str,
    /// Operation mode.
    pub mode: &'static str,
    /// Number of configured upstreams.
    pub upstream_count: usize,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Get the current health status.
#[must_use]
pub fn get_status(config: &ProxyConfig) -> HealthStatus {
    let start = *START_TIME.get_or_init(Instant::now);
    let mode_str = match config.mode {
        OperationMode::Shadow => "shadow",
        OperationMode::Enforce => "enforce",
    };

    HealthStatus {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        mode: mode_str,
        upstream_count: config.upstreams.len(),
        uptime_secs: start.elapsed().as_secs(),
    }
}

/// Serialize health status to a JSON string.
#[must_use]
pub fn health_json(config: &ProxyConfig) -> String {
    let status = get_status(config);
    serde_json::to_string(&status).unwrap_or_else(|_| r#"{"status":"error"}"#.to_string())
}

/// Is this the healthcheck path?
#[must_use]
pub fn is_health_path(path: &str, config: &ProxyConfig) -> bool {
    path == config.health_path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_is_ok() {
        let config = ProxyConfig::default();
        let status = get_status(&config);
        assert_eq!(status.status, "ok");
        assert_eq!(status.mode, "enforce");
    }

    #[test]
    fn health_status_shadow() {
        let config = ProxyConfig {
            mode: OperationMode::Shadow,
            ..ProxyConfig::default()
        };
        let status = get_status(&config);
        assert_eq!(status.mode, "shadow");
    }

    #[test]
    fn health_json_is_valid() {
        let config = ProxyConfig::default();
        let json = health_json(&config);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["version"], "0.1.0");
        assert!(parsed["uptime_secs"].as_u64().is_some());
    }

    #[test]
    fn is_health_path_matches() {
        let config = ProxyConfig::default();
        assert!(is_health_path("/health", &config));
        assert!(!is_health_path("/v1/chat", &config));
    }

    #[test]
    fn custom_health_path() {
        let config = ProxyConfig {
            health_path: "/status".to_string(),
            ..ProxyConfig::default()
        };
        assert!(is_health_path("/status", &config));
        assert!(!is_health_path("/health", &config));
    }

    #[test]
    fn upstream_count() {
        let config = ProxyConfig::with_upstream("test", "https://example.com");
        assert_eq!(get_status(&config).upstream_count, 1);
    }

    #[test]
    fn uptime_increases() {
        let config = ProxyConfig::default();
        let s1 = get_status(&config).uptime_secs;
        std::thread::sleep(std::time::Duration::from_millis(10));
        let s2 = get_status(&config).uptime_secs;
        assert!(s2 >= s1);
    }
}
