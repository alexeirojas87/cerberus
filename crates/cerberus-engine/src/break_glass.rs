//! Break-glass / bypass auditado (§4.7 del build plan).
//!
//! Permite que un dev fuerce el envío de algo que Cerberus bloquearía,
//! dejando un registro auditado del bypass. Mecanismos:
//!
//! - **Header `X-Cerberus-Bypass`** en el request HTTP.
//! - **Llamada programática** (`BreakGlass::allow_once`).
//!
//! El bypass solo se aplica a findings con acción `Block`; los findings
//! con `Redact`/`Warn`/`Allow` se procesan normalmente.

use crate::engine::Finding;
use crate::rule::Action;

/// Registro de un bypass: qué se omitió y por qué.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassRecord {
    /// Motivo provisto por el dev.
    pub reason: String,
    /// Timestamp (Unix epoch nanos) del bypass.
    pub timestamp_nanos: u128,
    /// Flags de los findings que se omitieron.
    pub bypassed_flags: Vec<String>,
    /// Cantidad de findings bloqueantes omitidos.
    pub bypassed_count: usize,
}

/// Control de break-glass.
#[derive(Debug, Clone, Default)]
pub struct BreakGlass {
    /// Si está habilitado el break-glass.
    pub enabled: bool,
}

impl BreakGlass {
    /// Crear una instancia con break-glass habilitado.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Aplica bypass sobre findings: remueve los `Block` y devuelve
    /// los findings restantes más un `BypassRecord` si hubo bypass.
    ///
    /// Si `self.enabled` es `false` o no hay findings `Block`,
    /// devuelve los findings originales y `None`.
    #[must_use]
    pub fn apply(&self, findings: &[Finding], reason: &str) -> (Vec<Finding>, Option<BypassRecord>) {
        if !self.enabled {
            return (findings.to_vec(), None);
        }

        let blocked: Vec<&Finding> = findings.iter().filter(|f| f.action == Action::Block).collect();
        if blocked.is_empty() {
            return (findings.to_vec(), None);
        }

        let bypassed_flags: Vec<String> = blocked.iter().map(|f| f.flag.clone()).collect();
        let bypassed_count = blocked.len();

        let passed: Vec<Finding> = findings.iter().filter(|f| f.action != Action::Block).cloned().collect();

        let record = BypassRecord {
            reason: reason.to_string(),
            timestamp_nanos: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            bypassed_flags,
            bypassed_count,
        };

        (passed, Some(record))
    }

    /// Atajo: `allow_once(reason)` es equivalente a
    /// `BreakGlass::enabled().apply(findings, reason)`.
    #[must_use]
    pub fn allow_once(findings: &[Finding], reason: &str) -> (Vec<Finding>, Option<BypassRecord>) {
        Self::enabled().apply(findings, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Finding;
    use crate::rule::{Action, Category, Severity};

    fn make_finding(flag: &str, action: Action) -> Finding {
        Finding {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action,
            start: 0,
            end: 5,
            hashed_value: "sha256:test".to_string(),
        }
    }

    #[test]
    fn disabled_returns_original() {
        let bg = BreakGlass { enabled: false };
        let findings = vec![make_finding("t", Action::Block)];
        let (passed, record) = bg.apply(&findings, "reason");
        assert_eq!(passed.len(), 1);
        assert!(record.is_none());
    }

    #[test]
    fn enabled_without_block_returns_original() {
        let bg = BreakGlass::enabled();
        let findings = vec![make_finding("t", Action::Redact)];
        let (passed, record) = bg.apply(&findings, "reason");
        assert_eq!(passed.len(), 1);
        assert!(record.is_none());
    }

    #[test]
    fn enabled_with_block_removes_block() {
        let bg = BreakGlass::enabled();
        let findings = vec![
            make_finding("blocked", Action::Block),
            make_finding("redacted", Action::Redact),
        ];
        let (passed, record) = bg.apply(&findings, "testing");
        assert_eq!(passed.len(), 1);
        assert_eq!(passed[0].flag, "redacted");
        let rec = record.unwrap();
        assert_eq!(rec.reason, "testing");
        assert_eq!(rec.bypassed_flags, vec!["blocked"]);
        assert_eq!(rec.bypassed_count, 1);
    }

    #[test]
    fn allow_once_static_works() {
        let findings = vec![make_finding("b", Action::Block)];
        let (passed, record) = BreakGlass::allow_once(&findings, "dev override");
        assert!(passed.is_empty());
        let rec = record.unwrap();
        assert_eq!(rec.reason, "dev override");
        assert_eq!(rec.bypassed_flags, vec!["b"]);
    }

    #[test]
    fn multiple_blocks_all_bypassed() {
        let bg = BreakGlass::enabled();
        let findings = vec![
            make_finding("b1", Action::Block),
            make_finding("b2", Action::Block),
            make_finding("w", Action::Warn),
        ];
        let (passed, record) = bg.apply(&findings, "multiple");
        assert_eq!(passed.len(), 1);
        assert_eq!(passed[0].flag, "w");
        let rec = record.unwrap();
        assert_eq!(rec.bypassed_count, 2);
        assert_eq!(rec.bypassed_flags, vec!["b1", "b2"]);
    }
}
