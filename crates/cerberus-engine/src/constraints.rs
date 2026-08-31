//! Constraint evaluator for post-match filtering.
//!
//! After a regex/AC match is found, constraints reduce false positives by
//! checking that the matched value and its surrounding context satisfy
//! additional requirements defined in the rule: `minLength`, `maxLength`,
//! `allowedExamples`, `contextKeywords`.
//!
//! # Performance contract (repair attempt 5, R9-F1.2 perf blocker 2)
//!
//! The previous implementation lowercased the **entire** scan context once per
//! match (`context.to_lowercase()`), which made `CompiledEngine::scan` quadratic
//! in a keyword-bearing payload (a 100 KB phone list reached ~195 ms, far over
//! the §5 p99 < 3–5 ms budget). [`ContextAnalyzer`] now normalizes the context
//! at most once per scan and reuses it for every match, keeping scan cost
//! linear.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::OnceLock;

use crate::rule::Rule;
use regex::Regex;

/// True for Unicode scalar values that continue a word. Underscore remains a
/// deliberate token separator so keywords match segments in identifiers such
/// as `OPENAI_API_KEY`.
#[inline]
fn is_word_char(ch: char) -> bool {
    static UNICODE_WORD: OnceLock<Regex> = OnceLock::new();
    if ch == '_' {
        return false;
    }
    let mut encoded = [0u8; 4];
    UNICODE_WORD
        .get_or_init(|| Regex::new(r"\w").expect("regex crate \\w compiles"))
        .is_match(ch.encode_utf8(&mut encoded))
}

fn collect_line_bounds(text: &str) -> Vec<(usize, usize)> {
    let mut bounds = Vec::new();
    let mut start = 0usize;
    for (idx, byte) in text.as_bytes().iter().enumerate() {
        if *byte == b'\n' {
            bounds.push((start, idx));
            start = idx + 1;
        }
    }
    bounds.push((start, text.len()));
    bounds
}

/// A case-insensitive, word-boundary keyword search over a lowercased haystack.
///
/// Returns `true` if `keyword` occurs in `haystack` with a non-word byte (or a
/// boundary of the string) on both sides. Matching by word boundary prevents
/// substring collisions such as `tel` inside `hotel`, `phone` inside
/// `megaphone`, `contact` inside `contactless`, and `e164` inside `XE164foo`.
fn keyword_at_word_boundary(haystack: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }
    haystack
        .match_indices(keyword)
        // `match_indices` yields byte offsets that align with `needle` bytes;
        // Both the context and keywords are Unicode-lowercased before matching,
        // so the returned offsets address the normalized strings.
        .any(|(pos, _)| {
            let end = pos + keyword.len();
            let before_ok = !haystack[..pos].chars().next_back().is_some_and(is_word_char);
            let after_ok = !haystack[end..].chars().next().is_some_and(is_word_char);
            before_ok && after_ok
        })
}

/// Normalized, per-scan context used by every constraint check.
///
/// The context is Unicode-lowercased exactly once. Line boundaries are
/// precomputed so the contextual phone policy can
/// require a word-boundary keyword on the *same line* as the match instead of
/// anywhere in the whole document.
#[derive(Debug)]
pub struct ContextAnalyzer<'a> {
    context: &'a str,
    lower: String,
    /// `(start, end)` byte ranges of each line in the original context. Match
    /// offsets use these coordinates even when Unicode lowercase expands.
    line_bounds: Vec<(usize, usize)>,
    /// Equivalent line ranges within `lower`, used only to slice normalized
    /// text for keyword matching.
    lower_line_bounds: Vec<(usize, usize)>,
    /// Lazily computed per keyword-set bitset of which lines contain a
    /// word-boundary keyword hit. Keyed by the keyword vector so a scan sharing
    /// one analyzer across many rules computes each set once.
    keyword_lines: RefCell<HashMap<Vec<String>, Rc<Vec<bool>>>>,
    /// Cached whole-context result per keyword set for structured-body leaf
    /// scans, so `keyword_anywhere` does not rescan the body for every leaf.
    keyword_anywhere: RefCell<HashMap<Vec<String>, bool>>,
}

impl<'a> ContextAnalyzer<'a> {
    /// Build an analyzer over `context`, lowercasing and line-splitting once.
    #[must_use]
    pub fn new(context: &'a str) -> Self {
        let lower = context.to_lowercase();
        let line_bounds = collect_line_bounds(context);
        let lower_line_bounds = collect_line_bounds(&lower);
        Self {
            context,
            lower,
            line_bounds,
            lower_line_bounds,
            keyword_lines: RefCell::new(HashMap::new()),
            keyword_anywhere: RefCell::new(HashMap::new()),
        }
    }

    /// The raw context string (used by callers that need the original case).
    #[must_use]
    pub const fn raw(&self) -> &'a str {
        self.context
    }

    /// Find the line index covering byte offset `at` via binary search.
    fn line_index(&self, at: usize) -> usize {
        match self.line_bounds.binary_search_by(|&(start, end)| {
            if end <= at {
                std::cmp::Ordering::Less
            } else if start > at {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(idx) => idx,
            Err(idx) => idx.min(self.line_bounds.len() - 1),
        }
    }

    /// Bitset (one flag per line) of lines containing a word-boundary keyword.
    /// Computed once per distinct keyword set per scan and cached.
    fn keyword_line_bits(&self, keywords: &[String]) -> Rc<Vec<bool>> {
        if let Some(cached) = self.keyword_lines.borrow().get(keywords) {
            return cached.clone();
        }
        let bits: Vec<bool> = self
            .lower_line_bounds
            .iter()
            .map(|&(start, end)| {
                let line = &self.lower[start..end];
                keywords.iter().any(|kw| keyword_at_word_boundary(line, kw))
            })
            .collect();
        let rc = Rc::new(bits);
        self.keyword_lines.borrow_mut().insert(keywords.to_vec(), rc.clone());
        rc
    }

    /// Contextual `contextKeywords` check with a bounded, same-line proximity
    /// window. `match_start`/`match_end` are byte offsets into the context and
    /// MUST be valid in context coordinates (only true when the scanned text is
    /// the context itself, e.g. `CompiledEngine::scan`).
    #[must_use]
    pub fn keyword_near_match(&self, keywords: &[String], match_start: usize, match_end: usize) -> bool {
        let bits = self.keyword_line_bits(keywords);
        let start_line = self.line_index(match_start);
        let end_line = self.line_index(match_end.saturating_sub(1));
        (start_line..=end_line).any(|line| bits.get(line).copied().unwrap_or(false))
    }

    /// Contextual `contextKeywords` check WITHOUT a proximity window: a
    /// word-boundary keyword may appear anywhere in the context. Used by the
    /// JSON leaf path where the match offsets are relative to a leaf value, not
    /// the full context body, so line proximity is not defined.
    #[must_use]
    pub fn keyword_anywhere(&self, keywords: &[String]) -> bool {
        if let Some(&cached) = self.keyword_anywhere.borrow().get(keywords) {
            return cached;
        }
        let found = keywords.iter().any(|kw| keyword_at_word_boundary(&self.lower, kw));
        self.keyword_anywhere.borrow_mut().insert(keywords.to_vec(), found);
        found
    }
}

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
/// 4. **contextKeywords** — a required keyword must appear, word-bounded and on
///    the same line as the match (case-insensitive)
///
/// This convenience form treats the whole `context` as a single window. The
/// engine threads a precomputed [`ContextAnalyzer`] through the hot path via
/// [`check_constraints_with_analyzer`] instead.
#[must_use]
pub fn check_constraints(rule: &Rule, value: &str, context: &str) -> bool {
    let analyzer = ContextAnalyzer::new(context);
    // Single-window convenience form: the whole context is one line, so the
    // proximity window collapses to the whole string.
    check_constraints_inner(rule, value, &analyzer, true, 0, context.len())
}

/// Constraint checks that do not involve `contextKeywords` (length limits and
/// `allowedExamples` only). Used by the engine hot path for keyword-free rules
/// so no context work happens at all for them.
#[must_use]
pub fn check_constraints_simple(rule: &Rule, value: &str) -> bool {
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
    true
}

/// Engine hot-path constraint check using a pre-normalized [`ContextAnalyzer`].
///
/// `offsets_in_context` is `true` when `match_start`/`match_end` index into the
/// analyzer's context (the plain-text `scan` path), enabling the same-line
/// proximity window. When `false` (JSON leaf scans where the value was extracted
/// from a different buffer), the keyword check falls back to a word-boundary
/// search over the whole context with no distance bound.
#[must_use]
pub fn check_constraints_with_analyzer(
    rule: &Rule,
    value: &str,
    analyzer: &ContextAnalyzer<'_>,
    offsets_in_context: bool,
    match_start: usize,
    match_end: usize,
) -> bool {
    check_constraints_inner(rule, value, analyzer, offsets_in_context, match_start, match_end)
}

fn check_constraints_inner(
    rule: &Rule,
    value: &str,
    analyzer: &ContextAnalyzer<'_>,
    offsets_in_context: bool,
    match_start: usize,
    match_end: usize,
) -> bool {
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

    // contextKeywords: case-insensitive, word-boundary, bounded proximity.
    // Keywords are already normalized to lowercase at rule compilation.
    if !rule.context_keywords.is_empty() {
        if offsets_in_context {
            if !analyzer.keyword_near_match(&rule.context_keywords, match_start, match_end) {
                return false;
            }
        } else if !analyzer.keyword_anywhere(&rule.context_keywords) {
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
    fn context_keywords_case_insensitive_unicode() {
        let mut rule = make_rule(None, None, &[], &["ÉMAIL"]);
        for keyword in &mut rule.context_keywords {
            *keyword = keyword.to_lowercase();
        }

        assert!(check_constraints(&rule, "1234567", "émail 1234567"));
        assert!(check_constraints(&rule, "1234567", "ÉMAIL 1234567"));
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

    // ─── Repair attempt 5: word-boundary context keywords (MED-3) ──────────

    #[test]
    fn keyword_tel_does_not_match_hotel_motel_intl() {
        let rule = make_rule(None, None, &[], &["tel"]);
        assert!(!check_constraints(&rule, "5551234567", "hotel 5551234567 lobby"));
        assert!(!check_constraints(&rule, "5551234567", "motel 5551234567"));
        assert!(!check_constraints(&rule, "5551234567", "intl 5551234567"));
        // A standalone tel token still fires.
        assert!(check_constraints(&rule, "5551234567", "tel 5551234567"));
        assert!(check_constraints(&rule, "5551234567", "Tel: 5551234567"));
    }

    #[test]
    fn keyword_phone_does_not_match_megaphone() {
        let rule = make_rule(None, None, &[], &["phone"]);
        assert!(!check_constraints(&rule, "5551234567", "megaphone 5551234567"));
        assert!(check_constraints(&rule, "5551234567", "phone 5551234567"));
        assert!(check_constraints(&rule, "5551234567", "PHONE 5551234567"));
    }

    #[test]
    fn keyword_contact_does_not_match_contactless() {
        let rule = make_rule(None, None, &[], &["contact"]);
        assert!(!check_constraints(&rule, "5551234567", "contactless order 5551234567"));
        assert!(check_constraints(&rule, "5551234567", "contact 5551234567"));
    }

    #[test]
    fn keyword_e164_does_not_match_xe164foo() {
        let rule = make_rule(None, None, &[], &["e164"]);
        assert!(!check_constraints(&rule, "5551234567", "XE164foo 5551234567 bar"));
        assert!(check_constraints(&rule, "5551234567", "e164 5551234567"));
    }

    #[test]
    fn analyzer_normalizes_context_once_is_ascii_safe() {
        // Multi-byte context must not panic and offsets must stay stable.
        let analyzer = ContextAnalyzer::new("café phone ☎ 8005550199 naïve");
        assert!(analyzer.keyword_anywhere(&["phone".to_string()]));
    }

    #[test]
    fn analyzer_line_proximity_requires_same_line() {
        let analyzer = ContextAnalyzer::new("phone list backup:\norder id 1234567\ninvoice 2345678\n");
        let kws: Vec<String> = ["phone", "tel", "contact"].iter().map(|s| (*s).to_string()).collect();
        // "1234567" is at the offset on line 2 which has no keyword.
        let start = analyzer.raw().find("1234567").unwrap();
        assert!(
            !analyzer.keyword_near_match(&kws, start, start + 7),
            "keyword on a different line must not grant proximity"
        );
        // A value on the keyword's own line does.
        let analyzer2 = ContextAnalyzer::new("phone 8005550199\nunrelated 999\n");
        let start2 = analyzer2.raw().find("8005550199").unwrap();
        assert!(analyzer2.keyword_near_match(&kws, start2, start2 + 10));
    }

    #[test]
    fn unicode_lowercase_expansion_preserves_same_line_offsets() {
        let context = format!("{}\nÉMAIL 1234567", "İ".repeat(20));
        let analyzer = ContextAnalyzer::new(&context);
        let start = analyzer.raw().find("1234567").unwrap();

        assert!(analyzer.keyword_near_match(&["émail".to_string()], start, start + 7));
    }

    #[test]
    fn unicode_lowercase_expansion_does_not_leak_keyword_across_lines() {
        let context = format!("ÉMAIL {}\nunrelated 1234567", "İ".repeat(20));
        let analyzer = ContextAnalyzer::new(&context);
        let start = analyzer.raw().find("1234567").unwrap();

        assert!(!analyzer.keyword_near_match(&["émail".to_string()], start, start + 7));
    }

    #[test]
    fn unicode_keyword_requires_unicode_word_boundaries() {
        let analyzer = ContextAnalyzer::new("préémailø 1234567");
        assert!(!analyzer.keyword_anywhere(&["émail".to_string()]));

        // Preserve the established identifier-token contract: underscore is
        // a separator, just as it is for `openai` in `OPENAI_API_KEY`.
        let identifier = ContextAnalyzer::new("prefix_ÉMAIL_suffix");
        assert!(identifier.keyword_anywhere(&["émail".to_string()]));

        for joined in ["pre\u{0301}tel", "pre\u{200d}tel"] {
            let analyzer = ContextAnalyzer::new(joined);
            assert!(
                !analyzer.keyword_anywhere(&["tel".to_string()]),
                "combining marks and join controls continue a Unicode word: {joined:?}"
            );
        }
    }
}
