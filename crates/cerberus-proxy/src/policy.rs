//! Fail-open / fail-closed policy (§4.1 of the build plan).
//!
//! If the engine fails (compilation error, regex, redaction failure, etc.),
//! is the request blocked (fail-closed, safe) or let through (fail-open,
//! available)? The default policy is `closed-on-critical` (R9-12): fail
//! closed only when the request involves `critical`-severity rules, fail
//! open for the rest.

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
///
/// `has_critical_findings` reports whether the request carries
/// `critical`-severity findings (the §4.1 "critical rules"). It only matters
/// for [`FailPolicy::ClosedOnCritical`]:
/// `Open` always allows, `Closed` always rejects, and
/// `ClosedOnCritical` rejects **only** when critical findings are present —
/// indeterminate criticality (no findings at all, e.g. the body could not be
/// decoded) counts as critical and is rejected (fail-closed posture).
#[must_use]
pub const fn evaluate(policy: FailPolicy, _error: &str, has_critical_findings: bool) -> PolicyDecision {
    match policy {
        FailPolicy::Open => PolicyDecision::Allow,
        FailPolicy::Closed => PolicyDecision::Reject,
        FailPolicy::ClosedOnCritical => {
            if has_critical_findings {
                PolicyDecision::Reject
            } else {
                PolicyDecision::Allow
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_rejects() {
        assert_eq!(
            evaluate(FailPolicy::Closed, "engine error", true),
            PolicyDecision::Reject
        );
        assert_eq!(
            evaluate(FailPolicy::Closed, "engine error", false),
            PolicyDecision::Reject
        );
    }

    #[test]
    fn fail_open_allows() {
        assert_eq!(evaluate(FailPolicy::Open, "engine error", true), PolicyDecision::Allow);
        assert_eq!(evaluate(FailPolicy::Open, "engine error", false), PolicyDecision::Allow);
    }

    #[test]
    fn fail_open_passes_any_error() {
        let decision = evaluate(FailPolicy::Open, "regex compilation fail", false);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn fail_closed_rejects_any_error() {
        let decision = evaluate(FailPolicy::Closed, "any error", false);
        assert_eq!(decision, PolicyDecision::Reject);
    }

    // ── R9-12: `closed-on-critical` decision table (§4.1) ──

    #[test]
    fn closed_on_critical_rejects_when_critical_findings_present() {
        let decision = evaluate(FailPolicy::ClosedOnCritical, "redaction failure", true);
        assert_eq!(decision, PolicyDecision::Reject, "critical rule → fail closed");
    }

    #[test]
    fn closed_on_critical_allows_non_critical_failures() {
        let decision = evaluate(FailPolicy::ClosedOnCritical, "redaction failure", false);
        assert_eq!(decision, PolicyDecision::Allow, "non-critical rules → fail open");
    }

    #[test]
    fn closed_on_critical_matches_closed_with_critical_findings() {
        let decision = evaluate(FailPolicy::ClosedOnCritical, "redaction failure", true);
        assert_eq!(decision, evaluate(FailPolicy::Closed, "redaction failure", true));
    }
}
