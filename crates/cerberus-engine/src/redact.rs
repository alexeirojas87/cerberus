//! Redaction engine — applies detection findings to produce a transformed payload.
//!
//! Given a text and the findings from the detection engine, this module
//! rewrites the text according to each finding's action:
//!
//! - **Block** — the entire request is rejected (`RedactError::Blocked`).
//! - **Redact** — the matched span is replaced with a configurable token.
//! - **Warn / Allow** — the text passes through unchanged.
//!
//! Span overlaps are resolved by the most severe action
//! (`Block > Redact > Warn > Allow`).

use crate::engine::Finding;

/// Actions the redaction engine can take for a single finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedactAction {
    /// Block the entire request.
    Block,
    /// Redact the span.
    Redact,
    /// Warn — pass through unchanged.
    Warn,
    /// Allow — pass through unchanged.
    Allow,
}

/// Error returned when redaction cannot proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactError {
    /// A finding with `Block` action was found; the request must be rejected.
    Blocked {
        /// The flag that triggered the block.
        flag: String,
    },
}

impl std::fmt::Display for RedactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked { flag } => write!(f, "request blocked by rule '{flag}'"),
        }
    }
}

/// Options that control the redaction token format.
#[derive(Debug, Clone)]
pub struct RedactOptions {
    /// Token template. `{flag}` is replaced with the finding's flag.
    /// Default: `"[REDACTED:{flag}]"`
    pub token_template: String,
    /// When `true`, the replacement has the same byte length as the original
    /// value (using `*` filler). Default: `false`.
    pub preserve_length: bool,
}

impl Default for RedactOptions {
    fn default() -> Self {
        Self {
            token_template: "[REDACTED:{flag}]".to_string(),
            preserve_length: false,
        }
    }
}

impl RedactOptions {
    fn make_token(&self, flag: &str, span_len: usize) -> String {
        #[allow(clippy::literal_string_with_formatting_args)]
        let template = "{flag}";
        let token = self.token_template.replace(template, flag);
        if self.preserve_length {
            let filler = "*".repeat(span_len);
            if token.len() > span_len {
                token[..span_len].to_string()
            } else {
                format!("{}{}", token, &filler[token.len()..])
            }
        } else {
            token
        }
    }
}

/// Apply redaction to `text` based on `findings`.
///
/// # Errors
///
/// Returns `RedactError::Blocked` if any finding has action `Block`.
///
/// # Panics
///
/// Panics if a finding's span is out of bounds (should not happen with
/// valid findings produced by the detection engine).
pub fn apply_redaction(text: &str, findings: &[Finding], options: &RedactOptions) -> Result<String, RedactError> {
    if findings.is_empty() {
        return Ok(text.to_string());
    }

    // Validate spans before processing
    let text_len = text.len();
    for f in findings {
        if f.start > f.end || f.end > text_len {
            return Err(RedactError::Blocked { flag: f.flag.clone() });
        }
    }

    // Check for any block action first
    for f in findings {
        if f.action == crate::rule::Action::Block {
            return Err(RedactError::Blocked { flag: f.flag.clone() });
        }
    }

    // Sort findings by start position
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| f.start);

    // Resolve overlapping spans: keep only the most severe action per position
    let resolved = resolve_spans(&sorted);

    // Build the redacted string from right to left (to preserve positions)
    let mut result = text.to_string();
    for f in resolved.iter().rev() {
        if f.action == crate::rule::Action::Redact {
            let token = options.make_token(&f.flag, f.end - f.start);
            result.replace_range(f.start..f.end, &token);
        }
        // Warn and Allow fall through — no modification
    }

    Ok(result)
}

/// Resolve overlapping findings: when spans overlap, keep only the finding
/// with the most severe action. Within the same action, keep the first.
#[must_use]
pub fn resolve_spans<'a>(sorted: &[&'a Finding]) -> Vec<&'a Finding> {
    let mut result: Vec<&Finding> = Vec::new();
    for &f in sorted {
        if let Some(last) = result.last() {
            if last.end > f.start {
                let last_sev = action_severity(last.action);
                let f_sev = action_severity(f.action);
                if f_sev > last_sev {
                    result.pop();
                    result.push(f);
                }
                // else: keep the previous finding (more severe or same)
                continue;
            }
        }
        result.push(f);
    }
    result
}

const fn action_severity(action: crate::rule::Action) -> u8 {
    match action {
        crate::rule::Action::Allow => 0,
        crate::rule::Action::Warn => 1,
        crate::rule::Action::Redact => 2,
        crate::rule::Action::Block => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Finding;
    use crate::rule::{Action, Category, Severity};

    fn make_finding(flag: &str, action: Action, start: usize, end: usize) -> Finding {
        Finding {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action,
            start,
            end,
            hashed_value: "sha256:test".to_string(),
        }
    }

    #[test]
    fn redact_replaces_span() {
        let text = "my api key is sk-abc123def456";
        let findings = vec![make_finding("test.key", Action::Redact, 14, 29)];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        assert_eq!(result, "my api key is [REDACTED:test.key]");
    }

    #[test]
    fn block_returns_error() {
        let text = "secret data";
        let findings = vec![make_finding("test.block", Action::Block, 0, 6)];
        let err = apply_redaction(text, &findings, &RedactOptions::default()).unwrap_err();
        assert!(matches!(err, RedactError::Blocked { .. }));
    }

    #[test]
    fn warn_passes_through() {
        let text = "contains warning-flag";
        let findings = vec![make_finding("test.warn", Action::Warn, 9, 21)];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        assert_eq!(result, text);
    }

    #[test]
    fn allow_passes_through() {
        let text = "allow this";
        let findings = vec![make_finding("test.allow", Action::Allow, 0, 10)];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        assert_eq!(result, text);
    }

    #[test]
    fn multiple_redactions() {
        let text = "key1 abc key2 def";
        let findings = vec![
            make_finding("k1", Action::Redact, 5, 8),
            make_finding("k2", Action::Redact, 14, 17),
        ];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        assert_eq!(result, "key1 [REDACTED:k1] key2 [REDACTED:k2]");
    }

    #[test]
    fn no_findings_returns_original() {
        let text = "nothing to see here";
        let result = apply_redaction(text, &[], &RedactOptions::default()).unwrap();
        assert_eq!(result, text);
    }

    #[test]
    fn overlapping_spans_most_severe_wins() {
        // Two overlapping findings: Redact (more severe, at 10..16) vs Warn (8..14)
        // Resolved: only Redact(10..16) survives
        let text = "this is a secret value";
        let findings = vec![
            make_finding("warn", Action::Warn, 8, 14),
            make_finding("redact", Action::Redact, 10, 16),
        ];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        // Replace bytes 10..16 ("secret") with "[REDACTED:redact]"
        assert_eq!(result, "this is a [REDACTED:redact] value");
    }

    #[test]
    fn custom_token_template() {
        let text = "key=sk-xxx";
        let findings = vec![make_finding("test.key", Action::Redact, 4, 10)];
        let opts = RedactOptions {
            token_template: "{{{flag}}}".to_string(),
            ..Default::default()
        };
        let result = apply_redaction(text, &findings, &opts).unwrap();
        assert_eq!(result, "key={{test.key}}");
    }

    #[test]
    fn custom_token_template_simple() {
        let text = "key=sk-xxx";
        let findings = vec![make_finding("test.key", Action::Redact, 4, 10)];
        let opts = RedactOptions {
            token_template: "{{flag}}".to_string(),
            ..Default::default()
        };
        let result = apply_redaction(text, &findings, &opts).unwrap();
        assert_eq!(result, "key={test.key}");
    }

    #[test]
    fn preserve_length_shorter() {
        let text = "key=12345";
        let findings = vec![make_finding("t", Action::Redact, 4, 9)];
        let opts = RedactOptions {
            preserve_length: true,
            token_template: "[R]".to_string(),
        };
        let result = apply_redaction(text, &findings, &opts).unwrap();
        // 5 chars preserved: "[R]" (3) + "**" (2)
        assert_eq!(result, "key=[R]**");
    }

    #[test]
    fn preserve_length_longer_truncates() {
        let text = "key=AB";
        let findings = vec![make_finding("t", Action::Redact, 4, 6)];
        let opts = RedactOptions {
            preserve_length: true,
            token_template: "[REDACTED:toolong]".to_string(),
        };
        let result = apply_redaction(text, &findings, &opts).unwrap();
        // Only 2 chars preserved
        assert_eq!(result, "key=[R");
    }

    #[test]
    fn json_structure_preserved() {
        let text = r#"{"prompt":"my api key is sk-abc123","user":"alice"}"#;
        let findings = vec![make_finding("test.key", Action::Redact, 26, 34)];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        // The JSON structure should still be valid
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        let prompt = parsed["prompt"].as_str().unwrap();
        assert!(!prompt.contains("sk-abc123"));
        assert!(prompt.contains("[REDACTED:test.key]"));
        assert_eq!(parsed["user"], "alice");
    }

    #[test]
    fn block_takes_precedence_over_redact() {
        let text = "blocking and redacting";
        let findings = vec![
            make_finding("block", Action::Block, 0, 8),
            make_finding("redact", Action::Redact, 13, 22),
        ];
        let err = apply_redaction(text, &findings, &RedactOptions::default()).unwrap_err();
        assert!(matches!(err, RedactError::Blocked { .. }));
    }

    #[test]
    fn empty_text_returns_empty() {
        let result = apply_redaction("", &[], &RedactOptions::default()).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn findings_out_of_order_sorted() {
        let text = "aaa XXX bbb YYY";
        // indices: 0-2 'aaa', 3 ' ', 4-6 'XXX', 7 ' ', 8-10 'bbb', 11 ' ', 12-14 'YYY'
        // len = 15
        let findings = vec![
            make_finding("second", Action::Redact, 12, 15),
            make_finding("first", Action::Redact, 4, 7),
        ];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        // Replace 12..15=YYY with [REDACTED:second] (16):
        //   "aaa XXX bbb [REDACTED:second]" (31 chars)
        // Replace 4..7=XXX with [REDACTED:first] (15):
        //   "aaa [REDACTED:first] bbb [REDACTED:second]" (47 chars)
        // This test is valid but the expected length doesn't matter for correctness
        assert!(!result.contains("XXX"));
        assert!(!result.contains("YYY"));
        assert!(result.contains("[REDACTED:first]"));
        assert!(result.contains("[REDACTED:second]"));
        // First finding in text order must be first
        let pos_first = result.find("[REDACTED:first]").unwrap();
        let pos_second = result.find("[REDACTED:second]").unwrap();
        assert!(pos_first < pos_second);
    }

    #[test]
    fn invalid_span_end_before_start_returns_error() {
        let text = "hello";
        let findings = vec![make_finding("bad", Action::Redact, 3, 1)];
        let err = apply_redaction(text, &findings, &RedactOptions::default()).unwrap_err();
        assert!(matches!(err, RedactError::Blocked { .. }));
    }

    #[test]
    fn invalid_span_out_of_bounds_returns_error() {
        let text = "hi";
        let findings = vec![make_finding("bad", Action::Redact, 0, 10)];
        let err = apply_redaction(text, &findings, &RedactOptions::default()).unwrap_err();
        assert!(matches!(err, RedactError::Blocked { .. }));
    }

    // --- action-precedence integration tests ---

    #[test]
    fn full_precedence_chain_block_over_redact_over_warn_over_allow() {
        // All overlapping: Block > Redact > Warn > Allow
        let text = "this is a test secret value here";
        let findings = vec![
            make_finding("allow", Action::Allow, 8, 12),
            make_finding("warn", Action::Warn, 8, 14),
            make_finding("redact", Action::Redact, 10, 16),
            make_finding("block", Action::Block, 8, 18),
        ];
        // apply_redaction should return Blocked for the block finding
        let err = apply_redaction(text, &findings, &RedactOptions::default()).unwrap_err();
        assert!(matches!(err, RedactError::Blocked { .. }));
    }

    #[test]
    fn redact_wins_over_warn_and_allow_span_overlap() {
        let text = "aaa bbb ccc";
        // Overlap region: 4..7
        // warn: 0..7, allow: 4..11, redact: 4..7
        // Redact has highest severity among non-block → should redact
        let findings = vec![
            make_finding("allow", Action::Allow, 4, 11),
            make_finding("warn", Action::Warn, 0, 7),
            make_finding("redact", Action::Redact, 4, 7),
        ];
        let result = apply_redaction(text, &findings, &RedactOptions::default()).unwrap();
        assert!(result.contains("[REDACTED:redact]"));
    }

    #[test]
    fn resolve_spans_ordered_by_precedence() {
        let f_allow = make_finding("a", Action::Allow, 0, 10);
        let f_warn = make_finding("w", Action::Warn, 3, 8);
        let f_redact = make_finding("r", Action::Redact, 4, 7);
        let sorted = vec![&f_allow, &f_warn, &f_redact];
        let resolved = resolve_spans(&sorted);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].flag, "r");
    }

    #[test]
    fn resolve_non_overlapping_spans_all_kept() {
        let f1 = make_finding("first", Action::Warn, 0, 5);
        let f2 = make_finding("second", Action::Redact, 10, 15);
        let resolved = resolve_spans(&[&f1, &f2]);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].flag, "first");
        assert_eq!(resolved[1].flag, "second");
    }
}
