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

    /// Fail policy when the engine errors. Canonical wire name:
    /// `fail_policy`. `fail_mode` (the Appendix A.1 spelling) is accepted as
    /// a deserialization alias (R9-12).
    #[serde(default, alias = "fail_mode")]
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
    /// `X-Cerberus-Admin-Token: <token>`.
    ///
    /// **Dev-mode semantics (R9-5, F6 — explicit decision):** when it is
    /// `None` or empty the control plane is **CLOSED, not open**. There is no
    /// valid credential, so every data `/api/*` route answers **401** —
    /// loopback included (fix-plan F6.1: "si falta token, mutation/data API
    /// responde 401 aun en loopback"). Only the static dashboard HTML and
    /// `/health` stay public (neither serves data). The old behavior ("When
    /// it is `None` (dev mode/tests) the control plane is left open") was the
    /// R9-5 vulnerability and is gone: dev usability is provided by
    /// `cerberus init` generating a strong token into `config.yaml` and by
    /// the `CERBERUS_ADMIN_TOKEN` env override.
    ///
    /// **Security (review v4 #1, unchanged):** if the proxy listens on a
    /// NON-loopback interface (e.g. `0.0.0.0` in docker), startup FAILS if
    /// the token is `None` or shorter than
    /// [`crate::api::ADMIN_TOKEN_MIN_BYTES`] (24) bytes.
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Exact Host allowlist for the control plane (R9-5 anti-DNS-rebinding,
    /// F6.1, config-driven per Appendix A.1). Entries are **exact**
    /// hostnames — no wildcards, no paths (a wildcard/blank entry fails the
    /// policy build at startup, fail-closed).
    ///
    /// When empty, the DEFAULT policy applies (fail-closed):
    /// - loopback bind (default `127.0.0.1:8787`): `localhost`, `127.0.0.1`
    ///   and `[::1]` are allowed, with or without the real port;
    /// - non-loopback bind: **nothing** is allowed except explicitly
    ///   configured entries — a public deployment must name its hostnames.
    ///
    /// Disallowed `Host` headers on `/api/*` are rejected with 403 BEFORE
    /// authentication (a rebinding page can never reach the auth layer).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Extra `Origin` allowlist for browser requests (R9-5/F6.1). Requests
    /// that carry an `Origin` header must be same-origin with an allowed
    /// Host (see [`Self::allowed_hosts`]) or appear here, exactly. CLI/curl
    /// without `Origin` are unaffected (the admin token still gates them).
    #[serde(default)]
    pub allowed_origins: Vec<String>,

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

/// Fail policy when the engine cannot scan (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FailPolicy {
    /// Let the request pass through even if the engine fails.
    Open,
    /// Reject the request if the engine fails.
    Closed,
    /// §4.1 default: **fail-closed for `critical` rules, fail-open for the
    /// rest** (R9-12). Concretely, an engine failure (redaction failure) is
    /// rejected only when the request carries `critical`-severity findings;
    /// otherwise the original body is forwarded (fail-open). A failure that
    /// happens BEFORE any finding exists (undecodable body) or outside the
    /// engine (upstream connection failure) has indeterminate criticality →
    /// fail-closed posture.
    #[default]
    #[serde(rename = "closed-on-critical", alias = "closedoncritical")]
    ClosedOnCritical,
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

    /// Per-upstream operation mode (§4.7 / R9-11): `shadow` or `enforce`.
    /// `None` (absent) → the upstream inherits the global `ProxyConfig::mode`.
    #[serde(default)]
    pub mode: Option<OperationMode>,

    /// Appendix A.1 compat wire name (R9-20): the YAML example writes
    /// `expected_auth: header` while the implementation canonically names the
    /// header carrying the provider credential `auth_header`. **Canonical
    /// name: `auth_header`**; `expected_auth` is accepted for parse
    /// compatibility, its only supported MVP value is `header` (the
    /// credential travels in a header — the one named by `auth_header`), any
    /// other value is a parse error. Input-compat only: it is never
    /// serialized back (the canonical serialized state is `auth_header`).
    #[serde(default, deserialize_with = "deserialize_expected_auth", skip_serializing)]
    pub expected_auth: Option<String>,
}

fn default_auth_header() -> String {
    "authorization".to_string()
}

/// Validate the Appendix A.1 `expected_auth` compat field (R9-20): the only
/// supported MVP value is `header` (the Appendix A.1 example). Anything else
/// fails the parse (fail-closed: no silently ignored config).
fn deserialize_expected_auth<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value.as_deref() {
        None | Some("header") => Ok(value),
        Some(other) => Err(serde::de::Error::custom(format!(
            "unsupported expected_auth value {other:?}: only \"header\" is supported (the credential \
             travels in the header named by `auth_header`, default \"authorization\")"
        ))),
    }
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
                mode: None,
                expected_auth: None,
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
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
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
        // R9-12: `closed-on-critical` (§4.1) is the DEFAULT fail policy.
        assert_eq!(cfg.fail_policy, FailPolicy::ClosedOnCritical);
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
        // R9-7 (F6.3): the allowlist carries the HMAC FINGERPRINT of the
        // value (`hmac:` + 64 hex, domain cerberus:allowlist:v1) — a raw
        // value no longer parses through validate() (see the raw-rejection
        // test below); the daemon migrates legacy raw YAML entries at boot.
        let fp = format!("hmac:{}", "c5a2".repeat(16));
        let yaml = format!(
            r#"
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
      patterns: ['BADGE-[0-9]{{4}}']
      minLength: 10
      maxLength: 32
      contextKeywords: ["badge"]
      allowedExamples: ["BADGE-0000"]
      validators: ["shannon-entropy>1.0"]
  allowlist:
    - {fp}
"#
        );
        let cfg = ProxyConfig::parse(&yaml).unwrap();
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
        assert_eq!(cfg.policy.allowlist, vec![fp]);
        cfg.policy.validate().expect("the policy from the YAML is valid");

        // …and it survives a serialization round trip (what the API persists).
        let dumped = serde_yaml::to_string(&cfg).expect("serialize config");
        let reloaded = ProxyConfig::parse(&dumped).expect("reparse");
        assert_eq!(reloaded.policy, cfg.policy);
    }

    #[test]
    fn raw_allowlist_entry_is_rejected_by_the_store_write_gate() {
        // R9-7: the config store (DetectionPolicy) rejects RAW values — the
        // raw secret must never land in config.yaml / the API. Legacy raw
        // YAMLs are migrated at daemon boot (see daemon.rs) before this
        // validation runs.
        let mut policy = crate::detection_policy::DetectionPolicy::empty();
        policy.allowlist.push("sk-EXAMPLE-do-not-flag".to_string());
        let err = policy.validate().unwrap_err();
        assert!(err.contains("HMAC fingerprints"), "got: {err}");
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
        // R9-12: the §4.1 / Appendix A.1 value parses (canonical + compat
        // spellings).
        assert_eq!(
            serde_yaml::from_str::<FailPolicy>("closed-on-critical").unwrap(),
            FailPolicy::ClosedOnCritical
        );
        assert_eq!(
            serde_yaml::from_str::<FailPolicy>("closedoncritical").unwrap(),
            FailPolicy::ClosedOnCritical
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
        // R9-5 (F6): None means the control plane is CLOSED (401), not open.
        // The doc contract is enforced by the api.rs auth-gate tests; here we
        // pin the config shape itself.
        assert!(cfg.allowed_hosts.is_empty());
        assert!(cfg.allowed_origins.is_empty());
    }

    #[test]
    fn host_origin_allowlist_parses_and_round_trips() {
        // R9-5/F6.1: config-driven (A.1) exact allowlist entries.
        let yaml = r"
listen: 0.0.0.0:8787
allowed_hosts:
  - cerberus.corp.example
allowed_origins:
  - https://ops.corp.example
";
        let cfg = ProxyConfig::parse(yaml).unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["cerberus.corp.example".to_string()]);
        assert_eq!(cfg.allowed_origins, vec!["https://ops.corp.example".to_string()]);

        // …and they survive a serialization round trip (the YAML is the
        // serialized state of the Config API).
        let dumped = serde_yaml::to_string(&cfg).expect("dump");
        let reloaded = ProxyConfig::parse(&dumped).expect("reparse");
        assert_eq!(reloaded.allowed_hosts, cfg.allowed_hosts);
        assert_eq!(reloaded.allowed_origins, cfg.allowed_origins);
    }

    #[test]
    fn admin_token_deserialize_optional() {
        let yaml = "listen: 127.0.0.1:8787\nadmin_token: s3cr3t\n";
        let cfg = ProxyConfig::parse(yaml).unwrap();
        assert_eq!(cfg.admin_token.as_deref(), Some("s3cr3t"));
    }

    // ── R9-12: `closed-on-critical` default + `fail_mode` alias ──

    #[test]
    fn a1_yaml_with_fail_mode_and_expected_auth_parses() {
        // The EXACT Appendix A.1 shape (subset): `fail_mode` key and
        // `expected_auth: header` upstreams must parse (R9-12 + R9-20).
        let yaml = r"
listen: 127.0.0.1:8787
fail_mode: closed-on-critical
upstreams:
  anthropic:  { url: https://api.anthropic.com, expected_auth: header }
  openai:     { url: https://api.openai.com,    expected_auth: header }
";
        let cfg = ProxyConfig::parse(yaml).expect("the A.1 example must parse");
        assert_eq!(cfg.fail_policy, FailPolicy::ClosedOnCritical);
        assert_eq!(cfg.upstreams["anthropic"].expected_auth.as_deref(), Some("header"));
        // `expected_auth: header` is compat sugar: the credential header name
        // keeps the canonical default.
        assert_eq!(cfg.upstreams["anthropic"].auth_header, "authorization");
        // No per-upstream mode in A.1 → inherit the global.
        assert_eq!(cfg.upstreams["anthropic"].mode, None);
        assert_eq!(cfg.upstreams["openai"].mode, None);
    }

    #[test]
    fn fail_policy_defaults_to_closed_on_critical_when_absent() {
        // §4.1: the RECOMMENDED default is fail-closed for critical rules,
        // fail-open for the rest — a YAML without the key must get it.
        let cfg = ProxyConfig::parse("listen: 127.0.0.1:8787\n").unwrap();
        assert_eq!(cfg.fail_policy, FailPolicy::ClosedOnCritical);
    }

    #[test]
    fn fail_policy_open_and_closed_still_configurable() {
        for (raw, expected) in [
            ("fail_policy: open", FailPolicy::Open),
            ("fail_policy: closed", FailPolicy::Closed),
            ("fail_policy: closed-on-critical", FailPolicy::ClosedOnCritical),
            // A.1 key spelling as an alias on the full config too.
            ("fail_mode: closed-on-critical", FailPolicy::ClosedOnCritical),
        ] {
            let cfg = ProxyConfig::parse(&format!("listen: 127.0.0.1:8787\n{raw}\n")).unwrap();
            assert_eq!(cfg.fail_policy, expected, "input: {raw}");
        }
    }

    #[test]
    fn fail_policy_serializes_canonical_name_and_round_trips() {
        let dumped = serde_yaml::to_string(&FailPolicy::ClosedOnCritical).expect("serialize");
        assert_eq!(
            dumped.trim(),
            "closed-on-critical",
            "serialized wire name must match A.1"
        );
        let reloaded: FailPolicy = serde_yaml::from_str(&dumped).expect("reparse");
        assert_eq!(reloaded, FailPolicy::ClosedOnCritical);
    }

    // ── R9-11: per-upstream `mode: shadow|enforce` ──

    #[test]
    fn per_upstream_mode_parses_with_global_fallback() {
        let yaml = r"
listen: 127.0.0.1:8787
mode: enforce
upstreams:
  anthropic: { url: https://api.anthropic.com, mode: shadow }
  openai:    { url: https://api.openai.com,    mode: enforce }
  nanbuilders: { url: https://api.nan.builders/v1 }
";
        let cfg = ProxyConfig::parse(yaml).unwrap();
        assert_eq!(cfg.upstreams["anthropic"].mode, Some(OperationMode::Shadow));
        assert_eq!(cfg.upstreams["openai"].mode, Some(OperationMode::Enforce));
        // Absent per-upstream mode → the global `mode: enforce` applies.
        assert_eq!(cfg.upstreams["nanbuilders"].mode, None);
        // Flow-style YAML (the A.1 inline-map shape) parses the same way.
        let flow = ProxyConfig::parse("upstreams:\n  x: { url: https://x.test, mode: shadow }\n").unwrap();
        assert_eq!(flow.upstreams["x"].mode, Some(OperationMode::Shadow));
    }

    #[test]
    fn per_upstream_mode_rejects_invalid_value() {
        let err = ProxyConfig::parse("upstreams:\n  x: { url: https://x.test, mode: bogus }\n").unwrap_err();
        assert!(err.contains("error"), "got: {err}");
    }

    #[test]
    fn per_upstream_mode_survives_config_serialization() {
        // The YAML is the serialized state of the Config API: a per-upstream
        // mode must survive a dump/reload round trip (hot-reload persistence).
        let cfg = ProxyConfig::parse(
            "mode: shadow\nupstreams:\n  a: { url: https://a.test, mode: enforce }\n  b: { url: https://b.test }\n",
        )
        .unwrap();
        let dumped = serde_yaml::to_string(&cfg).expect("dump");
        let reloaded = ProxyConfig::parse(&dumped).expect("reparse");
        assert_eq!(reloaded.upstreams["a"].mode, Some(OperationMode::Enforce));
        assert_eq!(reloaded.upstreams["b"].mode, None);
        assert_eq!(reloaded.mode, OperationMode::Shadow);
    }

    // ── R9-20: `expected_auth` compat validation ──

    #[test]
    fn expected_auth_header_only_supported_value() {
        let ok: UpstreamConfig = serde_yaml::from_str("url: https://x.test\nexpected_auth: header\n").unwrap();
        assert_eq!(ok.expected_auth.as_deref(), Some("header"));
        assert_eq!(ok.auth_header, "authorization", "canonical name keeps its default");
        // Anything else is a parse error (fail-closed, never ignored silently).
        let err = serde_yaml::from_str::<UpstreamConfig>("url: https://x.test\nexpected_auth: query\n").unwrap_err();
        assert!(err.to_string().contains("expected_auth"), "got: {err}");
        // …and it is input-compat only: never serialized back.
        let dumped = serde_yaml::to_string(&ok).expect("dump");
        assert!(!dumped.contains("expected_auth"), "dumped: {dumped}");
    }

    #[test]
    fn auth_header_wire_name_remains_canonical() {
        // R9-20 decision: `auth_header` (the header NAME) stays the single
        // canonical wire name; `expected_auth` accepts the A.1 spelling.
        let cfg: UpstreamConfig =
            serde_yaml::from_str("url: https://x.test\nauth_header: x-api-key\nexpected_auth: header\n").unwrap();
        assert_eq!(cfg.auth_header, "x-api-key");
        assert_eq!(cfg.expected_auth.as_deref(), Some("header"));
    }
}
