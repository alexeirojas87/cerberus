//! Config file types for the Cerberus proxy (§4.6 of the build plan).
//!
//! Supports YAML/JSON config with upstreams, mode, fail policy, and
//! rule pack overrides.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Top-level proxy configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Listen address. Default: `127.0.0.1:8787`
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Operation mode: `shadow` or `enforce`.
    #[serde(default)]
    pub mode: OperationMode,

    /// Fail policy when the engine errors.
    #[serde(default)]
    pub fail_policy: FailPolicy,

    /// Upstream providers (map of name → upstream config).
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,

    /// Log level. Default: `"info"`
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Healthcheck path. Default: `"/health"`
    #[serde(default = "default_health_path")]
    pub health_path: String,

    /// Maximum buffered request body in bytes (defense-in-depth against
    /// memory exhaustion on unbounded buffers). Default: 64 MB.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: Option<usize>,

    /// Admin token for the control plane (P0). If it is a non-empty `Some`,
    /// ALL `/api/*` routes require `Authorization: Bearer <token>` or
    /// `X-Cerberus-Admin-Token: <token>`. When it is `None` (dev mode/tests)
    /// the control plane is left open.
    ///
    /// **Security (review v4 #1):** if the proxy listens on a NON-loopback
    /// interface (e.g. `0.0.0.0` in docker), startup FAILS if the token is
    /// `None` or shorter than [`crate::api::ADMIN_TOKEN_MIN_BYTES`] (24) bytes.
    /// On loopback (`127.0.0.1` / `::1`) open dev-mode is allowed.
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Operator detection policy (fix review v6.1): action per category,
    /// override per rule, custom rules with the MVP `Rule` shape and a
    /// false-positive allowlist.
    ///
    /// It lives **here** (and therefore in the YAML) on purpose: before it
    /// was an in-memory overlay that was lost on restart and never reached
    /// the engine. Now the control plane persists it, startup restores it,
    /// and [`crate::detection_policy::EngineControl`] publishes it into the
    /// live engine without restarting. See [`crate::detection_policy`].
    #[serde(default)]
    pub policy: crate::detection_policy::DetectionPolicy,

    /// Reversible redaction (opt-in local vault, closed decision §9 #4).
    ///
    /// Default: `false` — redaction is **irreversible**. When `true`, redact
    /// spans are replaced by `[VAULT:<random>]` tokens and a **request-scoped**
    /// vault (capacity/TTL bounded, zeroized on consume/expiry/clear/drop)
    /// restores the originals on the non-streaming response. Nothing from the
    /// vault is persisted or logged (R9-8 / F2.2).
    #[serde(default)]
    pub reversible_redaction: bool,
}

fn default_listen() -> String {
    "127.0.0.1:8787".to_string()
}

/// Default maximum request body size (64 MiB).
#[allow(clippy::unnecessary_wraps)]
const fn default_max_body_bytes() -> Option<usize> {
    Some(64 * 1024 * 1024)
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_health_path() -> String {
    "/health".to_string()
}

/// Operation mode: shadow (log-only) or enforce (apply actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationMode {
    /// Scan and log findings, but let every request pass through intact.
    Shadow,
    /// Apply actions (block/redact) according to rules.
    #[default]
    Enforce,
}

/// Fail policy when the engine cannot scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FailPolicy {
    /// Let the request pass through even if the engine fails.
    Open,
    /// Reject the request if the engine fails.
    #[default]
    Closed,
}

/// Configuration for a single upstream provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    /// Base URL of the provider, e.g. `https://api.openai.com`
    pub url: String,

    /// Path prefix routed to this upstream (e.g. `/openai`). Requests whose
    /// path begins with this prefix are forwarded to `url` **without** the
    /// prefix. `None` = prefix must be inferred from the built-in table.
    #[serde(default)]
    pub path_prefix: Option<String>,

    /// Expected authentication header name. Default: `"authorization"`
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
}

fn default_auth_header() -> String {
    "authorization".to_string()
}

impl ProxyConfig {
    /// Load config from a YAML/JSON file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| format!("config read error: {e}"))?;
        Self::parse(&content)
    }

    /// Parse config from a YAML/JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be parsed.
    pub fn parse(content: &str) -> Result<Self, String> {
        serde_yaml::from_str(content)
            .or_else(|_| serde_json::from_str(content))
            .map_err(|e| format!("config parse error: {e}"))
    }

    /// Create a default config with a single upstream.
    #[must_use]
    pub fn with_upstream(name: &str, url: &str) -> Self {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            name.to_string(),
            UpstreamConfig {
                url: url.to_string(),
                path_prefix: None,
                auth_header: default_auth_header(),
            },
        );
        Self {
            upstreams,
            ..Self::default()
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            mode: OperationMode::default(),
            fail_policy: FailPolicy::default(),
            upstreams: HashMap::new(),
            log_level: default_log_level(),
            health_path: default_health_path(),
            max_body_bytes: default_max_body_bytes(),
            admin_token: None,
            policy: crate::detection_policy::DetectionPolicy::default(),
            reversible_redaction: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = ProxyConfig::default();
        assert_eq!(cfg.listen, "127.0.0.1:8787");
        assert_eq!(cfg.mode, OperationMode::Enforce);
        assert_eq!(cfg.fail_policy, FailPolicy::Closed);
        assert!(cfg.upstreams.is_empty());
    }

    #[test]
    fn parse_yaml_minimal() {
        let yaml = "listen: 0.0.0.0:8080\nmode: shadow\nfail_policy: open\n";
        let cfg = ProxyConfig::parse(yaml).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:8080");
        assert_eq!(cfg.mode, OperationMode::Shadow);
        assert_eq!(cfg.fail_policy, FailPolicy::Open);
    }

    #[test]
    fn reversible_redaction_is_opt_in_and_defaults_off() {
        // Closed decision §9 #4 (R9-8/F2.2): irreversible redaction is the
        // DEFAULT; the reversible vault is strictly opt-in.
        let cfg = ProxyConfig::default();
        assert!(!cfg.reversible_redaction, "default must be irreversible");
        let absent = ProxyConfig::parse("listen: 127.0.0.1:8787\n").unwrap();
        assert!(!absent.reversible_redaction, "YAML without the flag stays irreversible");
        let enabled = ProxyConfig::parse("listen: 127.0.0.1:8787\nreversible_redaction: true\n").unwrap();
        assert!(enabled.reversible_redaction, "opt-in parses true");
        let disabled = ProxyConfig::parse("reversible_redaction: false\n").unwrap();
        assert!(!disabled.reversible_redaction);
    }

    #[test]
    fn parse_yaml_with_upstreams() {
        let yaml = r"
listen: 127.0.0.1:8787
mode: enforce
upstreams:
  anthropic:
    url: https://api.anthropic.com
  openai:
    url: https://api.openai.com
";
        let cfg = ProxyConfig::parse(yaml).unwrap();
        assert_eq!(cfg.upstreams.len(), 2);
        assert_eq!(cfg.upstreams["anthropic"].url, "https://api.anthropic.com");
    }

    #[test]
    fn parse_json() {
        let json = r#"{"listen":"0.0.0.0:9090","mode":"shadow"}"#;
        let cfg = ProxyConfig::parse(json).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9090");
        assert_eq!(cfg.mode, OperationMode::Shadow);
    }

    #[test]
    fn with_upstream_helper() {
        let cfg = ProxyConfig::with_upstream("test", "https://test.api.com/v1");
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.upstreams["test"].url, "https://test.api.com/v1");
    }

    #[test]
    fn legacy_yaml_without_policy_preserves_actions_declared_by_rules() {
        let cfg = ProxyConfig::parse("listen: 127.0.0.1:8787\n").unwrap();
        assert_eq!(
            cfg.policy,
            crate::detection_policy::DetectionPolicy::seeded(),
            "a legacy config.yaml (without `policy`) does not invent overrides"
        );
        assert!(cfg.policy.categories.is_empty());
        assert!(cfg.policy.rule_actions.is_empty());
    }

    #[test]
    fn policy_round_trips_through_the_config_yaml() {
        // Real custom rules (pattern/flag/category/severity/action/constraints)
        // + categories + overrides + allowlist, persisted in the YAML.
        let yaml = r#"
listen: 127.0.0.1:8787
upstreams:
  default:
    url: https://api.openai.com
policy:
  categories:
    secrets: block
  rules:
    secret.openai_api_key: warn
  custom_rules:
    - flag: custom.badge_id
      category: internal_code
      severity: critical
      action: block
      patterns: ['BADGE-[0-9]{4}']
      minLength: 10
      maxLength: 32
      contextKeywords: ["badge"]
      allowedExamples: ["BADGE-0000"]
      validators: ["shannon-entropy>1.0"]
  allowlist:
    - sk-EXAMPLE-do-not-flag
"#;
        let cfg = ProxyConfig::parse(yaml).unwrap();
        assert_eq!(
            cfg.policy.categories.get(&cerberus_engine::rule::Category::Secrets),
            Some(&cerberus_engine::rule::Action::Block)
        );
        assert_eq!(
            cfg.policy.rule_actions.get("secret.openai_api_key"),
            Some(&cerberus_engine::rule::Action::Warn)
        );
        assert_eq!(cfg.policy.custom_rules.len(), 1);
        let rule = &cfg.policy.custom_rules[0];
        assert_eq!(rule.flag, "custom.badge_id");
        assert_eq!(rule.category, cerberus_engine::rule::Category::InternalCode);
        assert_eq!(rule.severity, cerberus_engine::rule::Severity::Critical);
        assert_eq!(rule.action, cerberus_engine::rule::Action::Block);
        assert_eq!(rule.patterns, vec!["BADGE-[0-9]{4}".to_string()]);
        assert_eq!(rule.min_length, Some(10));
        assert_eq!(rule.max_length, Some(32));
        assert_eq!(rule.context_keywords, vec!["badge".to_string()]);
        assert_eq!(rule.allowed_examples, vec!["BADGE-0000".to_string()]);
        assert_eq!(rule.validators, vec!["shannon-entropy>1.0".to_string()]);
        assert_eq!(cfg.policy.allowlist, vec!["sk-EXAMPLE-do-not-flag".to_string()]);
        cfg.policy.validate().expect("the policy from the YAML is valid");

        // …and it survives a serialization round trip (what the API persists).
        let dumped = serde_yaml::to_string(&cfg).expect("serialize config");
        let reloaded = ProxyConfig::parse(&dumped).expect("reparse");
        assert_eq!(reloaded.policy, cfg.policy);
    }

    #[test]
    fn invalid_yaml_returns_error() {
        let err = ProxyConfig::parse("not: : valid yaml: [").unwrap_err();
        assert!(err.contains("error"), "got: {err}");
    }

    #[test]
    fn fail_policy_deserialize() {
        assert_eq!(serde_yaml::from_str::<FailPolicy>("open").unwrap(), FailPolicy::Open);
        assert_eq!(
            serde_yaml::from_str::<FailPolicy>("closed").unwrap(),
            FailPolicy::Closed
        );
    }

    #[test]
    fn operation_mode_deserialize() {
        assert_eq!(
            serde_yaml::from_str::<OperationMode>("shadow").unwrap(),
            OperationMode::Shadow
        );
        assert_eq!(
            serde_yaml::from_str::<OperationMode>("enforce").unwrap(),
            OperationMode::Enforce
        );
    }

    #[test]
    fn default_auth_header() {
        let yaml = "url: https://api.example.com";
        let cfg: UpstreamConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.auth_header, "authorization");
    }

    #[test]
    fn admin_token_defaults_none() {
        let cfg = ProxyConfig::default();
        assert!(cfg.admin_token.is_none());
    }

    #[test]
    fn admin_token_deserialize_optional() {
        let yaml = "listen: 127.0.0.1:8787\nadmin_token: s3cr3t\n";
        let cfg = ProxyConfig::parse(yaml).unwrap();
        assert_eq!(cfg.admin_token.as_deref(), Some("s3cr3t"));
    }
}
