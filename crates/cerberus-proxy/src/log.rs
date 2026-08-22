//! Logging for the proxy — no secrets in the logs.
//!
//! Raw values of secrets/PII are never logged. Only flags, categories,
//! counts and hashes (which are already hashed by the detection engine)
//! are recorded.

use cerberus_engine::engine::Finding;
use cerberus_engine::rule::Action;
use tracing::Level;

/// Log level for security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
    /// Blocked request.
    Blocked,
    /// Redacted request.
    Redacted,
    /// Warning (something was detected but let through).
    Warned,
    /// Bypass (break-glass used).
    Bypassed,
    /// Clean request.
    Clean,
}

impl SecurityEvent {
    const fn level(self) -> Level {
        match self {
            Self::Blocked | Self::Bypassed => Level::WARN,
            Self::Redacted | Self::Warned => Level::INFO,
            Self::Clean => Level::DEBUG,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Blocked => "request blocked by Cerberus",
            Self::Redacted => "request redacted by Cerberus",
            Self::Warned => "request warned by Cerberus",
            Self::Bypassed => "request bypassed (break-glass) by Cerberus",
            Self::Clean => "request clean — no secrets detected",
        }
    }
}

/// Log a security event.
///
/// Never contains raw secret values. Only flags, categories, counts and
/// hashes.
pub fn log_security_event(event: SecurityEvent, findings: &[Finding], action_taken: Action) {
    let flags: Vec<&str> = findings.iter().map(|f| f.flag.as_str()).collect();
    let categories: Vec<String> = findings.iter().map(|f| f.category.to_string()).collect();
    let hashes: Vec<&str> = findings.iter().map(|f| f.hashed_value.as_str()).collect();

    let msg = event.message();
    match event.level() {
        Level::WARN => {
            tracing::warn!(event_type = msg, action_taken = %action_taken, finding_count = findings.len(), flags = ?flags, categories = ?categories, hashes = ?hashes);
        }
        Level::INFO => {
            tracing::info!(event_type = msg, action_taken = %action_taken, finding_count = findings.len(), flags = ?flags, categories = ?categories, hashes = ?hashes);
        }
        _ => {
            tracing::debug!(event_type = msg, action_taken = %action_taken, finding_count = findings.len(), flags = ?flags, categories = ?categories, hashes = ?hashes);
        }
    }
}

/// Initialize the global logger with format and filter.
pub fn init_logging(log_level: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::rule::{Action, Category, Severity};

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
    fn security_event_levels() {
        assert_eq!(SecurityEvent::Blocked.level(), Level::WARN);
        assert_eq!(SecurityEvent::Redacted.level(), Level::INFO);
        assert_eq!(SecurityEvent::Warned.level(), Level::INFO);
        assert_eq!(SecurityEvent::Bypassed.level(), Level::WARN);
        assert_eq!(SecurityEvent::Clean.level(), Level::DEBUG);
    }

    #[test]
    fn security_event_messages() {
        assert!(SecurityEvent::Blocked.message().contains("blocked"));
        assert!(SecurityEvent::Redacted.message().contains("redacted"));
        assert!(SecurityEvent::Clean.message().contains("clean"));
    }

    #[test]
    fn log_security_event_no_panic() {
        let findings = vec![make_finding("test.flag", Action::Block)];
        log_security_event(SecurityEvent::Blocked, &findings, Action::Block);
    }
}
