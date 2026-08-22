//! Shadow / enforce mode (§4.7 del build plan).
//!
//! - `shadow`: escanea y registra qué bloquearía/redactaría, pero
//!   **deja pasar todo intacto**.
//! - `enforce`: aplica las acciones de verdad (block/redact).

use cerberus_engine::engine::{Finding, ScanOutput};
use cerberus_engine::rule::Action;

use crate::config::OperationMode;

/// Resultado de aplicar el modo de operación a un scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeResult {
    /// Enforce mode: aplicar acción según findings.
    Enforce {
        /// Finding más severo.
        action: Action,
        /// Todos los findings.
        findings: Vec<Finding>,
    },
    /// Shadow mode: solo registrar, pasar intacto.
    Shadow {
        /// Lo que se *habría* hecho (solo informativo).
        would_be_action: Action,
        /// Findings para registro.
        findings: Vec<Finding>,
        /// El texto debe pasar intacto.
        pass_through: bool,
    },
}

impl ModeResult {
    /// ¿El request debe pasar intacto?
    #[must_use]
    pub fn should_forward(&self) -> bool {
        match self {
            Self::Enforce { action, .. } => *action != Action::Block,
            Self::Shadow { pass_through, .. } => *pass_through,
        }
    }

    /// Obtener los findings para audit.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        match self {
            Self::Enforce { ref findings, .. } | Self::Shadow { ref findings, .. } => findings,
        }
    }

    /// Obtener la acción que aplica.
    #[must_use]
    pub const fn action(&self) -> Action {
        match self {
            Self::Enforce { action, .. } => *action,
            Self::Shadow { would_be_action, .. } => *would_be_action,
        }
    }
}

/// Aplicar el modo de operación a un scan output.
#[must_use]
pub fn apply_mode(output: &ScanOutput, mode: OperationMode) -> ModeResult {
    match mode {
        OperationMode::Shadow => ModeResult::Shadow {
            would_be_action: output.action_overall,
            findings: output.findings.clone(),
            pass_through: true,
        },
        OperationMode::Enforce => ModeResult::Enforce {
            action: output.action_overall,
            findings: output.findings.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OperationMode;
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
    fn enforce_with_block_blocks() {
        let output = ScanOutput {
            findings: vec![make_finding("t", Action::Block)],
            action_overall: Action::Block,
        };
        let result = apply_mode(&output, OperationMode::Enforce);
        assert!(!result.should_forward());
        assert_eq!(result.action(), Action::Block);
    }

    #[test]
    fn enforce_with_redact_redacts() {
        let output = ScanOutput {
            findings: vec![make_finding("t", Action::Redact)],
            action_overall: Action::Redact,
        };
        let result = apply_mode(&output, OperationMode::Enforce);
        assert!(result.should_forward());
        assert_eq!(result.action(), Action::Redact);
    }

    #[test]
    fn shadow_always_passes_through() {
        let output = ScanOutput {
            findings: vec![make_finding("t", Action::Block)],
            action_overall: Action::Block,
        };
        let result = apply_mode(&output, OperationMode::Shadow);
        assert!(result.should_forward());
        if let ModeResult::Shadow {
            would_be_action,
            pass_through,
            ..
        } = result
        {
            assert!(pass_through);
            assert_eq!(would_be_action, Action::Block);
        } else {
            panic!("expected Shadow mode result");
        }
    }

    #[test]
    fn shadow_preserves_findings() {
        let output = ScanOutput {
            findings: vec![make_finding("t", Action::Redact)],
            action_overall: Action::Redact,
        };
        let result = apply_mode(&output, OperationMode::Shadow);
        assert_eq!(result.findings().len(), 1);
    }

    #[test]
    fn enforce_empty_findings_passes() {
        let output = ScanOutput {
            findings: Vec::new(),
            action_overall: Action::Warn,
        };
        let result = apply_mode(&output, OperationMode::Enforce);
        assert!(result.should_forward());
        assert_eq!(result.action(), Action::Warn);
    }
}
