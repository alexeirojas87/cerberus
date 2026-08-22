//! Event schema for audit events (§6 del build plan).
//!
//! Cada evento registra qué se protegió, con **fuga cero** de secretos:
//! nunca se almacena el valor crudo, solo hashes SHA-256.

use std::collections::HashMap;

use cerberus_engine::engine::Finding;
use cerberus_engine::rule::{Action, Severity};
use serde::{Deserialize, Serialize};

/// Un evento de auditoría.
///
/// Nunca contiene valores crudos de secretos. Solo flags, categorías,
/// conteos y hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// Identificador único del evento.
    pub id: String,
    /// Timestamp ISO 8601.
    pub ts: String,
    /// Modo de operación: "local" o "api".
    pub mode: String,
    /// Herramienta que originó el request (ej. "claude-code").
    pub tool: String,
    /// Proveedor LLM destino (ej. "anthropic").
    pub provider: String,
    /// Flags de las reglas que dispararon.
    pub flags: Vec<String>,
    /// Conteo por flag.
    pub counts: HashMap<String, usize>,
    /// Acción tomada globalmente.
    pub action_taken: String,
    /// SHA-256 hashes de los valores detectados. **Nunca los valores crudos.**
    pub hashed_values: Vec<String>,
    /// Severidad máxima.
    pub severity: String,
    /// Timestamp Unix (para ordenamiento y retención).
    pub ts_unix: i64,
}

impl AuditEvent {
    /// Construir un evento a partir de findings y metadatos.
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

    /// Verificar que ningún valor crudo está presente en el evento.
    #[must_use]
    pub fn no_raw_values(&self, raw_values: &[&str]) -> bool {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        !raw_values.iter().any(|v| serialized.contains(*v))
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
}
