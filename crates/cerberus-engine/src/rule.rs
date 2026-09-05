//! Rule model for the Cerberus detection engine (§6 of the build plan).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Detection category a rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Secrets: API keys, tokens, credentials.
    Secrets,
    /// Personally identifiable information.
    Pii,
    /// Internal/private code or infrastructure details.
    #[serde(rename = "internal_code")]
    InternalCode,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Secrets => "secrets",
            Self::Pii => "pii",
            Self::InternalCode => "internal_code",
        };
        f.write_str(s)
    }
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// Action to take when a rule fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Allow the request through without intervention.
    Allow,
    /// Warn but do not intervene.
    Warn,
    /// Redact the sensitive value.
    Redact,
    /// Block the request.
    Block,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Redact => "redact",
            Self::Block => "block",
        };
        f.write_str(s)
    }
}

/// A declarative detection rule (§6 of the build plan).
///
/// Mirrors the product JSON/YAML schema: `flag`, `category`, `severity`,
/// `action` (default [`Action::Warn`]), `hash_normalization`, context
/// keywords, length constraints, allowed examples, regex patterns and
/// validators.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Rule {
    /// Stable identifier, e.g. `"secret.openai_api_key"`.
    pub flag: String,
    /// Detection category.
    pub category: Category,
    /// Severity used for the overall verdict.
    pub severity: Severity,
    /// Action applied when this rule fires. Defaults to [`Action::Warn`].
    #[serde(default = "default_action")]
    pub action: Action,
    /// Optional normalization applied to the raw value before hashing
    /// (e.g. `"trim"`).
    #[serde(default, rename = "hashNormalization")]
    pub hash_normalization: Option<String>,
    /// Required context keywords. A match is retained when at least one
    /// keyword occurs in the case-insensitive scan context.
    #[serde(default, rename = "contextKeywords")]
    pub context_keywords: Vec<String>,
    /// Minimum accepted match length in bytes.
    #[serde(default, rename = "minLength")]
    pub min_length: Option<usize>,
    /// Maximum accepted match length in bytes.
    #[serde(default, rename = "maxLength")]
    pub max_length: Option<usize>,
    /// Examples that are explicitly allowed and should not fire.
    #[serde(default, rename = "allowedExamples")]
    pub allowed_examples: Vec<String>,
    /// Regular expression patterns (any match fires the rule).
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Named validators, e.g. `"luhn"` or `"shannon-entropy>4.0"`.
    #[serde(default)]
    pub validators: Vec<String>,
}

const fn default_action() -> Action {
    Action::Warn
}

/// Byte span of a matched value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    /// Start byte offset (inclusive).
    pub start: usize,
    /// End byte offset (exclusive).
    pub end: usize,
}

impl Span {
    /// Create a new span.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_defaults_to_warn() {
        let json = r#"{"flag":"f","category":"secrets","severity":"high"}"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.action, Action::Warn);
    }

    #[test]
    fn action_is_honoured_when_present() {
        let json = r#"{"flag":"f","category":"secrets","severity":"high","action":"block"}"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.action, Action::Block);
    }

    #[test]
    fn full_rule_deserializes() {
        let json = r#"{
            "flag":"secret.openai_api_key",
            "category":"secrets",
            "severity":"critical",
            "action":"redact",
            "hashNormalization":"trim",
            "contextKeywords":["openai"],
            "minLength":20,
            "maxLength":128,
            "allowedExamples":["sk-test-example"],
            "patterns":["\\bsk-[A-Za-z0-9]{20,}\\b"],
            "validators":[]
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.flag, "secret.openai_api_key");
        assert_eq!(rule.category, Category::Secrets);
        assert_eq!(rule.severity, Severity::Critical);
        assert_eq!(rule.action, Action::Redact);
        assert_eq!(rule.hash_normalization.as_deref(), Some("trim"));
        assert_eq!(rule.context_keywords, vec!["openai"]);
        assert_eq!(rule.min_length, Some(20));
        assert_eq!(rule.max_length, Some(128));
        assert_eq!(rule.allowed_examples, vec!["sk-test-example"]);
        assert_eq!(rule.patterns, vec![r"\bsk-[A-Za-z0-9]{20,}\b"]);
        assert!(rule.validators.is_empty());
    }

    #[test]
    fn enum_display() {
        assert_eq!(Category::Secrets.to_string(), "secrets");
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Action::Block.to_string(), "block");
    }
}
