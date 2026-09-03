//! Event schema for audit events (§6 of the build plan).
//!
//! Each event records what was protected, with **zero leakage** of secrets:
//! the raw value is never stored, only SHA-256 hashes.

use std::collections::HashMap;

use cerberus_engine::engine::Finding;
use cerberus_engine::rule::{Action, Severity};
use serde::{Deserialize, Serialize};

/// An audit event.
///
/// Never contains raw secret values. Only flags, categories,
/// counts and hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: String,
    /// Timestamp ISO 8601.
    pub ts: String,
    /// Operation mode: "local" or "api".
    pub mode: String,
    /// Tool that originated the request (e.g. "claude-code").
    pub tool: String,
    /// Target LLM provider (e.g. "anthropic").
    pub provider: String,
    /// Flags of the rules that triggered.
    pub flags: Vec<String>,
    /// Count per flag.
    pub counts: HashMap<String, usize>,
    /// Action taken globally.
    pub action_taken: String,
    /// SHA-256 hashes of the detected values. **Never the raw values.**
    pub hashed_values: Vec<String>,
    /// Maximum severity.
    pub severity: String,
    /// Unix timestamp (for ordering and retention).
    pub ts_unix: i64,
}

impl AuditEvent {
    /// Build an event from findings and metadata.
    #[must_use]
    pub fn from_findings(findings: &[Finding], action_taken: Action, mode: &str, tool: &str, provider: &str) -> Self {
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut flags: Vec<String> = Vec::new();
        let mut hashed_values: Vec<String> = Vec::new();
        let mut max_severity = Severity::Low;

        for f in findings {
            let flag = f.flag.clone();
            *counts.entry(flag.clone()).or_insert(0) += 1;
            if !flags.contains(&flag) {
                flags.push(flag);
            }
            if !hashed_values.contains(&f.hashed_value) {
                hashed_values.push(f.hashed_value.clone());
            }
            if f.severity > max_severity {
                max_severity = f.severity;
            }
        }

        let now = chrono::Utc::now();

        Self {
            id: format!("evt_{}", uuid::Uuid::new_v4().to_string().replace('-', "")),
            ts: now.to_rfc3339(),
            mode: mode.to_string(),
            tool: tool.to_string(),
            provider: provider.to_string(),
            flags,
            counts,
            action_taken: action_taken.to_string(),
            hashed_values,
            severity: max_severity.to_string(),
            ts_unix: now.timestamp(),
        }
    }

    /// Verify that no raw value is present in the event.
    #[must_use]
    pub fn no_raw_values(&self, raw_values: &[&str]) -> bool {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        !raw_values.iter().any(|v| serialized.contains(*v))
    }

    /// Build a CONTROL-PLANE audit event (F6.B attempt 2, security P2-1).
    ///
    /// Config-mutation actions (`POST /api/reload`, `PUT /api/config`,
    /// allowlist add/remove, upstream add/remove, packs enable/disable/update)
    /// previously left NO trace in the event store — `GET /api/events` showed
    /// only dataplane `proxy` events while the whole live config could be
    /// swapped with a single authenticated call. These events close that gap.
    ///
    /// * `action` — the honest action name (e.g. `config-reload`,
    ///   `config-update`, `allowlist-add`); it lands in `flags` so the
    ///   existing `--by flag` stats and the events feed group it.
    /// * `detail` — optional non-secret metadata (a pack name, an upstream
    ///   name). **NEVER** a token, a raw allowlist value or a fingerprint:
    ///   this event must stay secret-free end-to-end.
    /// * `mode` — the operation mode of the daemon at mutation time.
    ///
    /// The event carries no findings, so `counts`/`hashed_values` are empty
    /// and the severity is `info`-grade (`low` in the finding scale).
    #[must_use]
    pub fn control_plane(mode: &str, action: &str, detail: &str) -> Self {
        let now = chrono::Utc::now();
        let mut flags = vec![action.to_string()];
        if !detail.is_empty() {
            flags.push(detail.to_string());
        }
        Self {
            id: format!("evt_{}", uuid::Uuid::new_v4().to_string().replace('-', "")),
            ts: now.to_rfc3339(),
            mode: mode.to_string(),
            tool: "control-plane".to_string(),
            provider: "control".to_string(),
            flags,
            counts: HashMap::new(),
            action_taken: "audit".to_string(),
            hashed_values: Vec::new(),
            severity: Severity::Low.to_string(),
            ts_unix: now.timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::rule::{Action, Category, Severity};

    fn make_finding(flag: &str, action: Action, value: &str, severity: Severity) -> Finding {
        Finding {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity,
            action,
            start: 0,
            end: value.len(),
            hashed_value: format!("sha256:{}", sha256_fake(value)),
        }
    }

    fn sha256_fake(value: &str) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(value.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    #[test]
    fn event_from_findings_has_id() {
        let findings = vec![make_finding("test.flag", Action::Block, "secret-value", Severity::High)];
        let event = AuditEvent::from_findings(&findings, Action::Block, "local", "test-tool", "test-provider");
        assert!(event.id.starts_with("evt_"));
    }

    #[test]
    fn event_has_no_raw_values() {
        let raw = "my-super-secret-api-key-12345";
        let findings = vec![make_finding("test.secret", Action::Redact, raw, Severity::High)];
        let event = AuditEvent::from_findings(&findings, Action::Redact, "local", "cli", "openai");
        assert!(event.no_raw_values(&[raw]), "event must not contain raw value");
    }

    #[test]
    fn event_counts_multiple_flags() {
        let findings = vec![
            make_finding("flag.a", Action::Redact, "val1", Severity::High),
            make_finding("flag.a", Action::Redact, "val2", Severity::High),
            make_finding("flag.b", Action::Warn, "val3", Severity::High),
        ];
        let event = AuditEvent::from_findings(&findings, Action::Redact, "local", "t", "p");
        assert_eq!(*event.counts.get("flag.a").unwrap(), 2);
        assert_eq!(*event.counts.get("flag.b").unwrap(), 1);
    }

    #[test]
    fn event_serializes_to_json() {
        let findings = vec![make_finding("t", Action::Block, "some-secret-value", Severity::High)];
        let event = AuditEvent::from_findings(&findings, Action::Block, "local", "cli", "anthropic");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("evt_"));
        assert!(json.contains("sha256:"));
        assert!(json.contains("block"));
        assert!(!json.contains("some-secret-value"));
    }

    #[test]
    fn event_severity_maps_correctly() {
        let findings = vec![
            make_finding("low", Action::Warn, "v1", Severity::Low),
            make_finding("mid", Action::Warn, "v2", Severity::High),
            make_finding("critical", Action::Block, "v3", Severity::Critical),
        ];
        let event = AuditEvent::from_findings(&findings, Action::Block, "local", "t", "p");
        assert_eq!(event.severity, "critical");
    }

    #[test]
    fn event_has_timestamp() {
        let event = AuditEvent::from_findings(&[], Action::Allow, "local", "t", "p");
        assert!(!event.ts.is_empty());
        assert!(event.ts_unix > 0);
    }

    /// F6.B attempt 2 (security P2-1): control-plane events carry the honest
    /// action name and stay secret-free (no counts, no hashed values, empty
    /// findings surface). The `no_raw_values` contract must also hold.
    #[test]
    fn control_plane_event_is_honest_and_secret_free() {
        let event = AuditEvent::control_plane("enforce", "config-reload", "");
        assert_eq!(event.tool, "control-plane");
        assert_eq!(event.provider, "control");
        assert_eq!(event.action_taken, "audit");
        assert_eq!(event.flags, vec!["config-reload".to_string()]);
        assert!(event.counts.is_empty());
        assert!(event.hashed_values.is_empty());
        assert_eq!(event.severity, "low");
        assert_eq!(event.mode, "enforce");
        assert!(event.id.starts_with("evt_"));

        // The detail lands as a second flag (only when non-empty).
        let detailed = AuditEvent::control_plane("shadow", "pack-enable", "e2e-pack");
        assert_eq!(detailed.flags, vec!["pack-enable".to_string(), "e2e-pack".to_string()]);

        // No raw secret may ever survive serialization.
        let secret = "sk-super-secret-raw-value-000111";
        let leaky = AuditEvent::control_plane("local", "allowlist-add", "");
        assert!(
            leaky.no_raw_values(&[secret]),
            "control-plane events must stay secret-free"
        );
    }
}
