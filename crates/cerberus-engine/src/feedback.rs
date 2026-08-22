//! Hook de feedback (§4.7 del build plan).
//!
//! Proporciona una señal estructurada de "qué se redactó/bloqueó" para que
//! la capa de red la muestre al dev: notificación de escritorio, línea en
//! el CLI y/o mensaje inyectado en la respuesta del LLM.
//!
//! La redacción silenciosa genera desconfianza. Esta señal permite que el
//! dev **siempre se entere** de lo que Cerberus está protegiendo.

use std::collections::HashMap;

use crate::engine::Finding;
use crate::rule::{Action, Category, Severity};

/// Feedback estructurado sobre qué acciones tomó Cerberus en un scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactFeedback {
    /// Conteo por flag.
    pub by_flag: HashMap<String, usize>,
    /// Conteo por acción.
    pub by_action: HashMap<Action, usize>,
    /// Conteo por categoría.
    pub by_category: HashMap<Category, usize>,
    /// Severidad máxima encontrada.
    pub max_severity: Severity,
    /// Cantidad total de findings.
    pub total: usize,
    /// Lista de mensajes legibles para el dev.
    pub messages: Vec<String>,
}

impl RedactFeedback {
    /// Construir feedback a partir de findings y la acción global tomada.
    #[must_use]
    pub fn from_findings(findings: &[Finding], action_taken: Action) -> Self {
        let mut by_flag: HashMap<String, usize> = HashMap::new();
        let mut by_action: HashMap<Action, usize> = HashMap::new();
        let mut by_category: HashMap<Category, usize> = HashMap::new();
        let mut max_severity = Severity::Low;
        let mut messages: Vec<String> = Vec::new();

        for f in findings {
            *by_flag.entry(f.flag.clone()).or_insert(0) += 1;
            *by_action.entry(f.action).or_insert(0) += 1;
            *by_category.entry(f.category).or_insert(0) += 1;
            if f.severity > max_severity {
                max_severity = f.severity;
            }
        }

        let total = findings.len();

        // Generar mensajes legibles según la acción global
        match action_taken {
            Action::Block => {
                let flags: Vec<&str> = by_flag.keys().map(String::as_str).collect();
                messages.push(format!(
                    "🔒 Cerberus bloqueó el request: {} detectado(s)",
                    flags.join(", ")
                ));
            }
            Action::Redact => {
                let count = total;
                messages.push(format!("✂️ Cerberus redactó {count} secreto(s) en este mensaje"));
            }
            Action::Warn => {
                messages.push("⚠️ Cerberus advierte: se detectaron datos sensibles".to_string());
            }
            Action::Allow => {
                // No se necesita feedback para allow
            }
        }

        Self {
            by_flag,
            by_action,
            by_category,
            max_severity,
            total,
            messages,
        }
    }

    /// ¿Hubo alguna intervención (block/redact/warn)?
    #[must_use]
    pub const fn has_intervention(&self) -> bool {
        self.total > 0
    }

    /// Devuelve un resumen de una línea para CLI/logs.
    #[must_use]
    pub fn summary_line(&self) -> String {
        if self.total == 0 {
            return "✓ Cerberus: sin datos sensibles detectados".to_string();
        }
        let action_counts: Vec<String> = self.by_action.iter().map(|(a, c)| format!("{a}: {c}")).collect();
        format!("Cerberus: {} hallazgo(s) [{}]", self.total, action_counts.join(", "))
    }
}

/// Opciones de configuración para el hook de feedback.
#[derive(Debug, Clone)]
pub struct FeedbackOptions {
    /// Si se genera feedback (puede desactivarse para tests/silencio).
    pub enabled: bool,
    /// Inyectar mensaje de feedback en el body de respuesta del LLM.
    pub inject_response: bool,
}

impl Default for FeedbackOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            inject_response: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Finding;

    fn make_finding(flag: &str, action: Action, category: Category, severity: Severity) -> Finding {
        Finding {
            flag: flag.to_string(),
            category,
            severity,
            action,
            start: 0,
            end: 5,
            hashed_value: "sha256:test".to_string(),
        }
    }

    #[test]
    fn feedback_no_findings() {
        let feedback = RedactFeedback::from_findings(&[], Action::Allow);
        assert_eq!(feedback.total, 0);
        assert!(!feedback.has_intervention());
        assert!(feedback.by_flag.is_empty());
    }

    #[test]
    fn feedback_counts_by_flag() {
        let findings = vec![
            make_finding("secret.key1", Action::Redact, Category::Secrets, Severity::High),
            make_finding("secret.key2", Action::Redact, Category::Secrets, Severity::Critical),
            make_finding("secret.key1", Action::Redact, Category::Secrets, Severity::High),
        ];
        let feedback = RedactFeedback::from_findings(&findings, Action::Redact);
        assert_eq!(feedback.total, 3);
        assert_eq!(*feedback.by_flag.get("secret.key1").unwrap(), 2);
        assert_eq!(*feedback.by_flag.get("secret.key2").unwrap(), 1);
    }

    #[test]
    fn feedback_counts_by_action() {
        let findings = vec![
            make_finding("a", Action::Block, Category::Secrets, Severity::Critical),
            make_finding("b", Action::Redact, Category::Secrets, Severity::High),
            make_finding("c", Action::Warn, Category::Pii, Severity::Medium),
        ];
        let feedback = RedactFeedback::from_findings(&findings, Action::Block);
        assert_eq!(*feedback.by_action.get(&Action::Block).unwrap(), 1);
        assert_eq!(*feedback.by_action.get(&Action::Redact).unwrap(), 1);
        assert_eq!(*feedback.by_action.get(&Action::Warn).unwrap(), 1);
    }

    #[test]
    fn feedback_max_severity() {
        let findings = vec![
            make_finding("a", Action::Warn, Category::Secrets, Severity::Low),
            make_finding("b", Action::Block, Category::Secrets, Severity::Critical),
        ];
        let feedback = RedactFeedback::from_findings(&findings, Action::Block);
        assert_eq!(feedback.max_severity, Severity::Critical);
    }

    #[test]
    fn feedback_block_message() {
        let findings = vec![make_finding(
            "secret.openai_key",
            Action::Block,
            Category::Secrets,
            Severity::Critical,
        )];
        let feedback = RedactFeedback::from_findings(&findings, Action::Block);
        assert!(!feedback.messages.is_empty());
        assert!(feedback.messages[0].contains("bloqueó"));
    }

    #[test]
    fn feedback_redact_message() {
        let findings = vec![
            make_finding("secret.k1", Action::Redact, Category::Secrets, Severity::High),
            make_finding("secret.k2", Action::Redact, Category::Secrets, Severity::High),
        ];
        let feedback = RedactFeedback::from_findings(&findings, Action::Redact);
        assert!(!feedback.messages.is_empty());
        assert!(feedback.messages[0].contains("redactó"));
    }

    #[test]
    fn feedback_warn_message() {
        let findings = vec![make_finding("pii.email", Action::Warn, Category::Pii, Severity::Medium)];
        let feedback = RedactFeedback::from_findings(&findings, Action::Warn);
        assert!(!feedback.messages.is_empty());
        assert!(feedback.messages[0].contains("advierte"));
    }

    #[test]
    fn feedback_allow_no_message() {
        let feedback = RedactFeedback::from_findings(&[], Action::Allow);
        assert!(feedback.messages.is_empty());
    }

    #[test]
    fn feedback_summary_line_clean() {
        let feedback = RedactFeedback::from_findings(&[], Action::Allow);
        assert!(feedback.summary_line().contains("sin datos sensibles"));
    }

    #[test]
    fn feedback_summary_line_with_findings() {
        let findings = vec![
            make_finding("a", Action::Block, Category::Secrets, Severity::Critical),
            make_finding("b", Action::Redact, Category::Secrets, Severity::High),
        ];
        let feedback = RedactFeedback::from_findings(&findings, Action::Block);
        let line = feedback.summary_line();
        assert!(line.contains("hallazgo"));
        assert!(line.contains("block") || line.contains("redact"));
    }

    #[test]
    fn feedback_by_category() {
        let findings = vec![
            make_finding("a", Action::Block, Category::Secrets, Severity::High),
            make_finding("b", Action::Warn, Category::Pii, Severity::Medium),
        ];
        let feedback = RedactFeedback::from_findings(&findings, Action::Block);
        assert_eq!(*feedback.by_category.get(&Category::Secrets).unwrap(), 1);
        assert_eq!(*feedback.by_category.get(&Category::Pii).unwrap(), 1);
    }

    #[test]
    fn feedback_default_options() {
        let opts = FeedbackOptions::default();
        assert!(opts.enabled);
        assert!(!opts.inject_response);
    }
}
