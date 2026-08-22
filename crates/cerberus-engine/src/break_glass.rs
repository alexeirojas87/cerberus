//! Break-glass / audited bypass (§4.7 of the build plan).
//!
//! Allows a dev to force-send something that Cerberus would block,
//! leaving an audited record of the bypass. Mechanisms:
//!
//! - **Header `X-Cerberus-Bypass`** in the HTTP request.
//! - **Programmatic call** (`BreakGlass::allow_once`).
//!
//! The bypass only applies to findings with action `Block`; findings
//! with `Redact`/`Warn`/`Allow` are processed normally.

use crate::engine::Finding;
use crate::rule::Action;

/// Record of a bypass: what was skipped and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassRecord {
    /// Reason provided by the dev.
    pub reason: String,
    /// Timestamp (Unix epoch nanos) of the bypass.
    pub timestamp_nanos: u128,
    /// Flags of the findings that were skipped.
    pub bypassed_flags: Vec<String>,
    /// Number of blocking findings that were skipped.
    pub bypassed_count: usize,
}

/// Break-glass control.
#[derive(Debug, Clone, Default)]
pub struct BreakGlass {
    /// Whether break-glass is enabled.
    pub enabled: bool,
}

impl BreakGlass {
    /// Create an instance with break-glass enabled.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Apply bypass over findings: removes the `Block` ones and returns
    /// the remaining findings plus a `BypassRecord` if there was a bypass.
    ///
    /// If `self.enabled` is `false` or there are no `Block` findings,
    /// returns the original findings and `None`.
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

    /// Shortcut: `allow_once(reason)` is equivalent to
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
