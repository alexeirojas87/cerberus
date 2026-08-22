//! Scan request / result types and the public API entry point.
//!
//! The request is generic (`text` + arbitrary `metadata` labels). No domain
//! IDs (`AgentId`, `PbiId`, `CorrelationId`) leak into the core — exactly
//! as required by the lessons learned from the C# Cerberus (§1, point 3).

use std::collections::HashMap;

use crate::engine::{CompiledEngine, ScanOutput};

/// A scan request: raw text plus arbitrary metadata labels.
///
/// # Design note
///
/// There are NO domain-specific fields (`AgentId`, `PbiId`, `CorrelationId`).
/// The `metadata` map carries any labelling the caller needs without coupling
/// the engine to a particular infrastructure.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// The text to scan for secrets / PII.
    pub text: String,
    /// Arbitrary labels (tool, provider, correlation — whatever the caller
    /// needs for audit / telemetry).
    pub metadata: HashMap<String, String>,
}

impl ScanRequest {
    /// Build a new scan request.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            metadata: HashMap::new(),
        }
    }

    /// Add a metadata label.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Convenience function: scan text with a compiled engine.
///
/// This is the main entry point for the detection pipeline.
///
/// # Errors
///
/// Returns the engine's error message if the scan fails.
#[must_use]
pub fn scan(engine: &CompiledEngine, request: &ScanRequest) -> ScanOutput {
    engine.scan(&request.text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineBuilder;
    use crate::rule::{Action, Category, Rule, Severity};

    fn make_rule(flag: &str, patterns: &[&str], action: Action) -> Rule {
        Rule {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action,
            hash_normalization: None,
            context_keywords: Vec::new(),
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: patterns.iter().map(std::string::ToString::to_string).collect(),
            validators: Vec::new(),
        }
    }

    #[test]
    fn scan_request_is_generic_no_domain_ids() {
        let req = ScanRequest::new("hello").with_metadata("tool", "claude-code");
        assert_eq!(req.text, "hello");
        assert_eq!(req.metadata.get("tool").unwrap(), "claude-code");
    }

    #[test]
    fn scan_request_without_metadata() {
        let req = ScanRequest::new("world");
        assert!(req.metadata.is_empty());
    }

    #[test]
    fn scan_through_convenience_fn() {
        let rules = vec![make_rule("t", &[r"secret"], Action::Block)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let req = ScanRequest::new("this is a secret");
        let result = scan(&engine, &req);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].flag, "t");
    }
}
