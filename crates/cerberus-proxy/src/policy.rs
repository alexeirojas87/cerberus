//! Fail-open / fail-closed policy (§4.7 of the build plan).
//!
//! If the engine fails (compilation error, regex, etc.), is the request
//! blocked (fail-closed, safe) or let through (fail-open, available)?

use crate::config::FailPolicy;

/// Result of evaluating the failure policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Reject the request (fail-closed).
    Reject,
    /// Let the request through (fail-open).
    Allow,
}

/// Evaluate the failure policy.
#[must_use]
pub const fn evaluate(policy: FailPolicy, _error: &str) -> PolicyDecision {
    match policy {
        FailPolicy::Open => PolicyDecision::Allow,
        FailPolicy::Closed => PolicyDecision::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_rejects() {
        assert_eq!(evaluate(FailPolicy::Closed, "engine error"), PolicyDecision::Reject);
    }

    #[test]
    fn fail_open_allows() {
        assert_eq!(evaluate(FailPolicy::Open, "engine error"), PolicyDecision::Allow);
    }

    #[test]
    fn fail_open_passes_any_error() {
        let decision = evaluate(FailPolicy::Open, "regex compilation fail");
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn fail_closed_rejects_any_error() {
        let decision = evaluate(FailPolicy::Closed, "any error");
        assert_eq!(decision, PolicyDecision::Reject);
    }
}
