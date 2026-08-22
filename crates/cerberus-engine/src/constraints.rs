//! Constraint evaluator for post-match filtering.
//!
//! After a regex/AC match is found, constraints reduce false positives by
//! checking that the matched value and its surrounding context satisfy
//! additional requirements defined in the rule: `minLength`, `maxLength`,
//! `allowedExamples`, `contextKeywords`.

use crate::rule::Rule;

/// Check all constraints on a matched value against its context.
///
/// Returns `true` if the match passes all constraints and should be kept,
/// `false` if it should be discarded as a false positive.
///
/// # Constraints evaluated (in order)
///
/// 1. **minLength** — value is too short
/// 2. **maxLength** — value is too long
/// 3. **allowedExamples** — value is a known false positive
/// 4. **contextKeywords** — required context keywords are absent (case-insensitive)
#[must_use]
pub fn check_constraints(rule: &Rule, value: &str, context: &str) -> bool {
    if let Some(min_len) = rule.min_length {
        if value.len() < min_len {
            return false;
        }
    }

    if let Some(max_len) = rule.max_length {
        if value.len() > max_len {
            return false;
        }
    }

    if rule.allowed_examples.iter().any(|ex| ex == value) {
        return false;
    }

    // contextKeywords: case-insensitive check (P0-1 fix).
    // Keywords are already normalized to lowercase at rule compilation.
    // We normalize the context once and check membership.
    if !rule.context_keywords.is_empty() {
        let ctx_lower = context.to_lowercase();
        if !rule.context_keywords.iter().any(|kw| ctx_lower.contains(kw.as_str())) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{Action, Category, Rule, Severity};

    fn make_rule(
        min_length: Option<usize>,
        max_length: Option<usize>,
        allowed_examples: &[&str],
        context_keywords: &[&str],
    ) -> Rule {
        Rule {
            flag: "test.constraints".to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Redact,
            hash_normalization: None,
            context_keywords: context_keywords.iter().map(std::string::ToString::to_string).collect(),
            min_length,
            max_length,
            allowed_examples: allowed_examples.iter().map(std::string::ToString::to_string).collect(),
            patterns: vec![r"\bsk-[A-Za-z0-9]+\b".to_string()],
            validators: Vec::new(),
        }
    }

    #[test]
    fn min_length_short_value_is_discarded() {
        let rule = make_rule(Some(10), None, &[], &[]);
        assert!(!check_constraints(&rule, "short", "some context"));
    }

    #[test]
    fn min_length_long_enough_value_passes() {
        let rule = make_rule(Some(10), None, &[], &[]);
        assert!(check_constraints(&rule, "this is long enough", "some context"));
    }

    #[test]
    fn min_length_exact_boundary_passes() {
        let rule = make_rule(Some(5), None, &[], &[]);
        assert!(check_constraints(&rule, "12345", "ctx"));
        assert!(!check_constraints(&rule, "1234", "ctx"));
    }

    #[test]
    fn max_length_long_value_is_discarded() {
        let rule = make_rule(None, Some(10), &[], &[]);
        assert!(!check_constraints(&rule, "this is too long", "some context"));
    }

    #[test]
    fn max_length_short_enough_passes() {
        let rule = make_rule(None, Some(10), &[], &[]);
        assert!(check_constraints(&rule, "short", "ctx"));
    }

    #[test]
    fn max_length_exact_boundary_passes() {
        let rule = make_rule(None, Some(5), &[], &[]);
        assert!(check_constraints(&rule, "12345", "ctx"));
        assert!(!check_constraints(&rule, "123456", "ctx"));
    }

    #[test]
    fn allowed_examples_known_false_positive_discarded() {
        let rule = make_rule(None, None, &["sk-test", "sk-example"], &[]);
        assert!(!check_constraints(&rule, "sk-test", "some context"));
        assert!(!check_constraints(&rule, "sk-example", "some context"));
    }

    #[test]
    fn allowed_examples_non_matching_value_passes() {
        let rule = make_rule(None, None, &["sk-test"], &[]);
        assert!(check_constraints(&rule, "sk-real-value", "some context"));
    }

    #[test]
    fn context_keywords_present_passes() {
        let rule = make_rule(None, None, &[], &["api"]);
        assert!(check_constraints(&rule, "sk-xxx", "my api key is sk-xxx"));
    }

    #[test]
    fn context_keywords_absent_discarded() {
        let rule = make_rule(None, None, &[], &["api"]);
        assert!(!check_constraints(&rule, "sk-xxx", "my sk-xxx"));
    }

    #[test]
    fn no_constraints_always_passes() {
        let rule = make_rule(None, None, &[], &[]);
        assert!(check_constraints(&rule, "anything", "any context"));
        assert!(check_constraints(&rule, "", ""));
    }

    #[test]
    fn context_keywords_empty_list_passes() {
        let rule = make_rule(None, None, &[], &[]);
        assert!(check_constraints(&rule, "sk-xxx", "no keywords here"));
    }

    #[test]
    fn multiple_context_keywords_any_one_suffices() {
        let rule = make_rule(None, None, &[], &["api", "token", "secret"]);
        assert!(check_constraints(&rule, "sk-xxx", "my token is here"));
        assert!(check_constraints(&rule, "sk-xxx", "my api is here"));
        assert!(check_constraints(&rule, "sk-xxx", "my secret is here"));
        assert!(!check_constraints(&rule, "sk-xxx", "nothing relevant here"));
    }

    #[test]
    fn combined_min_length_and_context_keywords() {
        let rule = make_rule(Some(10), None, &[], &["api"]);
        assert!(check_constraints(&rule, "this is long enough", "my api key here"));
        assert!(!check_constraints(&rule, "short", "my api key here"));
        assert!(!check_constraints(&rule, "this is long enough", "no keyword here"));
    }

    #[test]
    fn all_constraints_together() {
        let rule = make_rule(Some(3), Some(20), &["known-fp"], &["required"]);
        assert!(check_constraints(&rule, "valid-value", "this has the required keyword"));
        assert!(!check_constraints(&rule, "ab", "this has the required keyword"));
        assert!(!check_constraints(
            &rule,
            "this value is way too long for the limit",
            "this has the required keyword"
        ));
        assert!(!check_constraints(&rule, "known-fp", "this has the required keyword"));
        assert!(!check_constraints(&rule, "valid-value", "no keyword present"));
    }

    // ─── P0-1: Case-insensitive contextKeywords ───────────────────────────

    #[test]
    fn context_keywords_case_insensitive_uppercase_context() {
        // P0-1: "OPENAI_API_KEY" should match keyword "openai" (lowercase)
        let rule = make_rule(None, None, &[], &["openai"]);
        assert!(
            check_constraints(&rule, "sk-xxx", "OPENAI_API_KEY=sk-xxx"),
            "uppercase context should match lowercase keyword"
        );
    }

    #[test]
    fn context_keywords_case_insensitive_mixed_case() {
        let rule = make_rule(None, None, &[], &["api"]);
        assert!(
            check_constraints(&rule, "sk-xxx", "My Api Key is sk-xxx"),
            "mixed-case context should match lowercase keyword"
        );
    }

    #[test]
    fn context_keywords_normalized_at_build_time() {
        // Simulates what EngineBuilder::build() does: lowercase all keywords.
        let mut rule = Rule {
            flag: "test.ci2".to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Redact,
            hash_normalization: None,
            context_keywords: vec!["OPENAI".to_string(), "API_KEY".to_string()],
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec![r"\bsk-[A-Za-z0-9]+\b".to_string()],
            validators: Vec::new(),
        };
        // Simulate compilation normalization
        for kw in &mut rule.context_keywords {
            *kw = kw.to_lowercase();
        }
        // Now lowercase "openai" should match both "OPENAI" and "openai" contexts
        assert!(
            check_constraints(&rule, "sk-xxx", "OPENAI_API_KEY=sk-xxx"),
            "lowercase keyword matches uppercase context"
        );
        assert!(
            check_constraints(&rule, "sk-xxx", "openai api key=sk-xxx"),
            "lowercase keyword matches lowercase context"
        );
    }

    #[test]
    fn keywords_ignored_when_pattern_is_high_specificity() {
        // P0-2: High-specificity patterns like AKIA detect with matching context.
        // The keyword check is a filter — the pattern match happens first,
        // then constraints validate the context.
        let rule = Rule {
            flag: "test.aws".to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Block,
            hash_normalization: None,
            context_keywords: vec!["aws".to_string()],
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec!["\\bAKIA[0-9A-Z]{16}\\b".to_string()],
            validators: Vec::new(),
        };
        // With keyword present: detects
        assert!(check_constraints(&rule, "AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY_ID"));
        // Without keyword: fails constraint (keyword present in rule, absent in context)
        assert!(!check_constraints(
            &rule,
            "AKIAIOSFODNN7EXAMPLE",
            "xyzzy blip flarp no relevant keyword here"
        ));
    }
}
