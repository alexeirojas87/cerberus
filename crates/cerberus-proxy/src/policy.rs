//! Política fail-open / fail-closed (§4.7 del build plan).
//!
//! Si el motor falla (error de compilación, regex, etc.), ¿se bloquea
//! el request (fail-closed, seguro) o se deja pasar (fail-open,
//! disponible)?

use crate::config::FailPolicy;

/// Resultado de evaluar la política de fallo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Rechazar el request (fail-closed).
    Reject,
    /// Dejar pasar el request (fail-open).
    Allow,
}

/// Evaluar la política de fallo.
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
