//! Generic entropy-based secret detector.
//!
//! Captures proprietary secrets that do not match any known regex pattern
//! but have high Shannon entropy and appear near indicative keywords.
//! This is a first-class virtual rule that always runs inside the engine.

use std::cmp::Reverse;
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::engine::{hash_value, Finding};
use crate::rule::{Action, Category, Severity};

/// Hash a value: HMAC-SHA256 if a secret is present, otherwise plain SHA-256.
/// (Review 2, P2 #11: entropy no longer emits deterministic SHA-256 when the
/// proxy has `CERBERUS_HMAC_SECRET`.)
#[must_use]
fn hash_with_secret(value: &str, secret: Option<&[u8]>) -> String {
    secret.map_or_else(
        || hash_value(value),
        |key| crate::engine::hmac_sha256_hex(key, value.as_bytes()),
    )
}

/// Indicative keywords that suggest a nearby value may be a secret.
const KEYWORDS: &[&str] = &[
    "password",
    "token",
    "apikey",
    "api_key",
    "secret",
    "key",
    "credential",
    "auth_token",
    "auth-token",
    "auth.token",
    "auth",
    "bearer",
    "hash",
    "salt",
    "private",
    "passwd",
    "pwd",
    "access_key",
    "secret_key",
    "db_password",
    "connection_string",
];

/// Characters to consider as non-word boundaries between keyword and value.
/// Includes leading opening brackets (`{`, `(`, `[`) so they are skipped like
/// the trailing trim removes their closing partners (repair attempt 5, LOW-1).
const SKIP_CHARS: &[char] = &[' ', '\t', '\n', '\r', '=', ':', '"', '\'', ',', '{', '(', '['];
/// Maximum window (in bytes) after a keyword to look for a value.
const NEAR_KEYWORD_WINDOW: usize = 200;
/// Minimum length of a candidate value to consider for entropy analysis.
const MIN_VALUE_LENGTH: usize = 8;

/// Public documentation fixtures that are intentionally non-secret.
const KNOWN_SAFE_EXAMPLES: &[&str] = &["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"];

/// Precompiled state for the generic entropy detector.
///
/// Engines own one instance so their scan path never needs to compile the
/// keyword expression. The public compatibility helper below uses a separate
/// process-wide instance for callers that do not have a
/// [`CompiledEngine`](crate::engine::CompiledEngine).
#[derive(Debug)]
pub(crate) struct EntropyDetector {
    keyword_prefilter: AhoCorasick,
    keyword_regex: Regex,
}

impl EntropyDetector {
    pub(crate) fn compile() -> Result<Self, String> {
        let mut keywords: Vec<String> = KEYWORDS.iter().map(|keyword| regex::escape(keyword)).collect();
        keywords.sort_by_key(|keyword| Reverse(keyword.len()));
        let pattern = format!(r"(?i)\b({})\b", keywords.join("|"));
        let keyword_prefilter = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(KEYWORDS)
            .map_err(|error| error.to_string())?;
        let keyword_regex = Regex::new(&pattern).map_err(|error| error.to_string())?;
        Ok(Self {
            keyword_prefilter,
            keyword_regex,
        })
    }

    pub(crate) fn detect_near_keywords(&self, text: &str, threshold: f64, secret: Option<&[u8]>) -> Vec<Finding> {
        if self.keyword_prefilter.find(text.as_bytes()).is_none() {
            return Vec::new();
        }
        detect_near_keywords_with_regex(&self.keyword_regex, text, threshold, secret)
    }

    /// Detect using the precompiled keyword regex directly, without the
    /// standalone presence prefilter.
    ///
    /// Callers that have already proven keyword presence through a merged
    /// presence automaton use this to avoid a second full-text pass.
    pub(crate) fn detect_near_keywords_proven(
        &self,
        text: &str,
        threshold: f64,
        secret: Option<&[u8]>,
    ) -> Vec<Finding> {
        detect_near_keywords_with_regex(&self.keyword_regex, text, threshold, secret)
    }

    /// Raw indicative keywords, for callers that fold them into a merged
    /// presence automaton instead of using the standalone prefilter.
    pub(crate) const fn keywords() -> &'static [&'static str] {
        KEYWORDS
    }

    #[cfg(test)]
    pub(crate) fn compiled_pattern_count(&self) -> usize {
        usize::from(!self.keyword_regex.as_str().is_empty())
    }
}

/// Compute the Shannon entropy of a byte string.
///
/// Returns a value in [0.0, 8.0] where:
/// - ≈0.0 for repetitive strings (e.g. `"aaaa"`)
/// - >4.0 for random-looking tokens (e.g. API keys, high-entropy passwords)
#[must_use]
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut total: usize = 0;
    for c in text.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    let len = total as f64;
    let mut entropy = 0.0_f64;
    for &n in counts.values() {
        let p = n as f64 / len;
        entropy = p.mul_add(-p.log2(), entropy);
    }
    entropy
}

/// Find high-entropy values near indicative keywords in `text`.
///
/// For each keyword occurrence, searches up to [`NEAR_KEYWORD_WINDOW`] bytes
/// forward for a candidate value. If the value's Shannon entropy exceeds
/// `threshold`, a [`Finding`] is produced. `secret` (optional) enables
/// HMAC-SHA256 instead of plain SHA-256 (review 2, P2 #11).
#[must_use]
pub fn detect_near_keywords(text: &str, threshold: f64, secret: Option<&[u8]>) -> Vec<Finding> {
    static DETECTOR: OnceLock<EntropyDetector> = OnceLock::new();
    let detector =
        DETECTOR.get_or_init(|| EntropyDetector::compile().expect("the static entropy keyword regex must compile"));
    detector.detect_near_keywords(text, threshold, secret)
}

fn detect_near_keywords_with_regex(
    keyword_regex: &Regex,
    text: &str,
    threshold: f64,
    secret: Option<&[u8]>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_spans: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    for kw_match in keyword_regex.find_iter(text) {
        let kw_end = kw_match.end();
        // HIGH-1 fix (repair attempt 5): the fixed byte window can end inside a
        // multi-byte character; snap it down to the nearest char boundary so
        // slicing never panics on attacker-controlled UTF-8 payloads.
        let mut search_end = std::cmp::min(kw_end.wrapping_add(NEAR_KEYWORD_WINDOW), text.len());
        while !text.is_char_boundary(search_end) {
            search_end -= 1;
        }
        let context = &text[kw_end..search_end];
        if let Some((value, value_offset)) = extract_value(context) {
            if value.len() < MIN_VALUE_LENGTH {
                continue;
            }
            if KNOWN_SAFE_EXAMPLES.contains(&value) {
                continue;
            }
            let ent = shannon_entropy(value);
            if ent > threshold {
                let abs_start = kw_end.wrapping_add(value_offset);
                let abs_end = abs_start.wrapping_add(value.len());
                // Adjacent keywords (`key token=<secret>`) must emit exactly one
                // finding with a clean span, not a duplicate per keyword.
                if !seen_spans.insert((abs_start, abs_end)) {
                    continue;
                }
                findings.push(Finding {
                    flag: "entropy.high_entropy_secret".to_string(),
                    category: Category::Secrets,
                    severity: Severity::Medium,
                    action: Action::Warn,
                    start: abs_start,
                    end: abs_end,
                    hashed_value: hash_with_secret(value, secret),
                });
            }
        }
    }
    findings
}

/// True when `prefix` is one of the indicative keywords (case-insensitive).
fn is_keyword(prefix: &str) -> bool {
    let lower = prefix.to_ascii_lowercase();
    KEYWORDS.iter().any(|kw| *kw == lower)
}

/// Extract the first candidate value token from a context string.
///
/// Skips leading whitespace and separators (`=`, `:`, `"`, `'`, `,`) then
/// returns the first contiguous non-whitespace token plus its byte offset
/// within `context`. If the token is actually `<keyword>=<value>` (an adjacent
/// keyword swallowed into the window), the keyword text and separator are
/// skipped so the returned span contains no keyword prose (repair attempt 5,
/// correctness F-1).
fn extract_value(context: &str) -> Option<(&str, usize)> {
    let mut cursor = 0usize;
    loop {
        let rel = context[cursor..].find(|c: char| !SKIP_CHARS.contains(&c) && c != '}' && c != ';')?;
        let start = cursor + rel;
        let remaining = &context[start..];
        let end = remaining
            .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\'' || c == '}')
            .unwrap_or(remaining.len());
        let token = &remaining[..end];
        // Only cut at an embedded separator when everything before it is
        // itself a keyword; values that merely contain '=' or ':' (e.g. base64
        // padding) keep their exact span.
        let sep = token.find(['=', ':']);
        if let Some(pos) = sep {
            if pos > 0 && is_keyword(&token[..pos]) {
                cursor = start + pos + 1;
                continue;
            }
        }
        let value = token.trim_end_matches(['.', '!', '?', ':', ')', ']']);
        return if value.is_empty() { None } else { Some((value, start)) };
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    // --- shannon_entropy ---

    #[test]
    fn entropy_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_repeated_char() {
        let e = shannon_entropy("aaaa");
        assert!(e < 0.01, "entropy of 'aaaa' should be ~0, got {e}");
    }

    #[test]
    fn entropy_high_random_token() {
        let e = shannon_entropy("sk-abcDEFghijklmnopqrstuvwxyz1234");
        assert!(e > 4.0, "entropy of random token should be > 4.0, got {e}");
    }

    #[test]
    fn entropy_low_password() {
        let e = shannon_entropy("abc123");
        assert!(e < 3.0, "entropy of 'abc123' should be < 3.0, got {e}");
    }

    #[test]
    fn entropy_medium_mixed() {
        let e = shannon_entropy("J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE");
        assert!(e > 4.0, "entropy of complex secret should be > 4.0, got {e}");
    }

    // --- detect_near_keywords ---

    #[test]
    fn detect_low_entropy_near_keyword_no_finding() {
        let text = "password=abc123";
        let findings = detect_near_keywords(text, 4.0, None);
        assert!(findings.is_empty(), "low-entropy 'abc123' should not be detected");
    }

    #[test]
    fn detect_high_entropy_near_keyword() {
        let text = "password=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let findings = detect_near_keywords(text, 4.0, None);
        assert_eq!(findings.len(), 1, "should detect high-entropy password");
        assert_eq!(findings[0].flag, "entropy.high_entropy_secret");
        assert_eq!(findings[0].category, Category::Secrets);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].action, Action::Warn);
    }

    #[test]
    fn detect_no_keywords_no_findings() {
        let text = "the quick brown fox jumps over the lazy dog";
        let findings = detect_near_keywords(text, 4.0, None);
        assert!(findings.is_empty(), "no keywords should produce no findings");
    }

    #[test]
    fn detect_token_after_colon() {
        let text = "api_key: J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let findings = detect_near_keywords(text, 4.0, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_token_after_equals() {
        let text = "SECRET=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let findings = detect_near_keywords(text, 4.0, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_case_insensitive_keyword() {
        let text = "Token=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let findings = detect_near_keywords(text, 4.0, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_hashed_value_not_raw() {
        let text = "password=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let findings = detect_near_keywords(text, 4.0, None);
        assert_eq!(findings.len(), 1);
        assert_ne!(findings[0].hashed_value, "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE");
        assert!(findings[0].hashed_value.starts_with("sha256:"));
    }

    #[test]
    fn detect_short_value_no_finding() {
        let text = "key=abc";
        let findings = detect_near_keywords(text, 4.0, None);
        assert!(findings.is_empty(), "value shorter than 8 chars should not be detected");
    }

    #[test]
    fn detect_within_window_multiple_keywords() {
        let text = "password=J8sK2m9xR4pL7vN3qW5t secret=aaaa  token=X7yZ1qW3rT5vB9nM2kL8pC4hJ6fD0sA";
        let findings = detect_near_keywords(text, 4.0, None);
        // "password=..." -> high entropy
        // "secret=aaaa" -> low entropy (repeated 'a')
        // "token=..." -> high entropy
        assert_eq!(findings.len(), 2, "should detect 2 high-entropy values out of 3");
    }

    #[test]
    fn detect_json_style() {
        let text = r#"{"password": "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE"}"#;
        let findings = detect_near_keywords(text, 4.0, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_excludes_sentence_punctuation_from_secret_span() {
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let text = format!("secret access key={token}.");
        let findings = detect_near_keywords(&text, 4.0, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(&text[findings[0].start..findings[0].end], token);
    }

    #[test]
    fn auth_keyword_variants_emit_one_exact_finding() {
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        for keyword in ["auth_token", "auth-token", "auth.token"] {
            let text = format!("{keyword}={token}:");
            let findings = detect_near_keywords(&text, 4.0, None);
            assert_eq!(findings.len(), 1, "{keyword} must not emit duplicates");
            assert_eq!(&text[findings[0].start..findings[0].end], token);
        }
    }

    #[test]
    fn canonical_public_aws_example_is_not_a_secret() {
        let text = "AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.";
        assert!(detect_near_keywords(text, 4.0, None).is_empty());
    }

    #[test]
    fn entropy_finding_never_raw() {
        let text = "token=my-super-secret-key-that-should-never-leak";
        let findings = detect_near_keywords(text, 4.0, None);
        for f in &findings {
            assert!(
                !f.hashed_value.contains("my-super-secret-key"),
                "Finding must not contain raw value"
            );
        }
    }

    #[test]
    fn repeated_detection_preserves_exact_findings() {
        let detector = EntropyDetector::compile().unwrap();
        assert_eq!(detector.compiled_pattern_count(), 1);

        let text = "Token=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let expected = detector.detect_near_keywords(text, 4.0, Some(b"test-hmac-key"));
        assert_eq!(expected.len(), 1);

        for _ in 0..32 {
            assert_eq!(
                detector.detect_near_keywords(text, 4.0, Some(b"test-hmac-key")),
                expected
            );
        }
    }

    // ─── Repair attempt 5: HIGH-1 non-char-boundary window panic PoCs ───────

    #[test]
    fn high1_accent_window_poc_does_not_panic() {
        // Panel PoC: "password=" followed by 200 bytes of U+00E9 straddling the
        // 200-byte window edge. Must not panic and must not find (low entropy).
        let text = format!("password={}", "é".repeat(100));
        let findings = detect_near_keywords(&text, 4.0, None);
        assert!(
            findings.is_empty(),
            "200 bytes of a repeated accent must not be a secret"
        );
    }

    #[test]
    fn high1_euro_window_poc_does_not_panic() {
        // Panel PoC: "key=" + 197 x's + '€' — window end lands inside '€'.
        let text = format!("key={}€", "x".repeat(197));
        let findings = detect_near_keywords(&text, 4.0, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn high1_cjk_window_poc_does_not_panic() {
        // Panel PoC: "key " + "密钥".repeat(120).
        let text = format!("key {}", "密钥".repeat(120));
        let findings = detect_near_keywords(&text, 4.0, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn high1_multibyte_secret_beyond_window_edge_still_scanned_safely() {
        // Boundary snapping must not break normal detection: the secret sits in
        // the window while the multibyte run straddles the window edge.
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let text = format!("key={token} {}", "é".repeat(90));
        let findings = detect_near_keywords(&text, 4.0, None);
        assert_eq!(findings.len(), 1, "secret inside the window is still found");
        assert_eq!(&text[findings[0].start..findings[0].end], token);
    }

    // ─── Repair attempt 5: LOW-1 leading brackets + F-1 adjacent keywords ──

    #[test]
    fn low1_leading_brackets_are_not_part_of_the_secret_span() {
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        for (prefix, suffix) in [("{", "}"), ("(", ")"), ("[", "]")] {
            let text = format!("password={prefix}{token}{suffix}");
            let findings = detect_near_keywords(&text, 4.0, None);
            assert_eq!(findings.len(), 1, "bracketed secret must emit exactly one finding");
            assert_eq!(
                &text[findings[0].start..findings[0].end],
                token,
                "leading bracket must be trimmed symmetrically with trailing close"
            );
        }
    }

    #[test]
    fn f1_adjacent_keywords_emit_one_clean_finding() {
        // Correctness F-1: "key token=<secret>" previously emitted two findings,
        // one swallowing "token=" into the secret span.
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let text = format!("key token={token}");
        let findings = detect_near_keywords(&text, 4.0, None);
        assert_eq!(findings.len(), 1, "adjacent keywords must not double count");
        assert_eq!(
            &text[findings[0].start..findings[0].end],
            token,
            "span must not contain keyword text"
        );

        // Keyword prose must not leak into the span for other adjacency shapes.
        for text in [
            format!("key secret:{token}"),
            format!("token auth:{token}"),
            format!("key secret={token}"),
        ] {
            let findings = detect_near_keywords(&text, 4.0, None);
            assert_eq!(findings.len(), 1, "exactly one finding for {text}");
            assert_eq!(
                &text[findings[0].start..findings[0].end],
                token,
                "clean span for {text}"
            );
        }
    }

    #[test]
    fn value_with_embedded_equals_or_colon_keeps_exact_span() {
        // The keyword-prefix cut must NOT damage real secrets that merely
        // contain separators (base64 padding, URLs, key:value prose).
        let text = "secret=YWJjdGhlZmcta2V5LXZhbHVl=";
        let findings = detect_near_keywords(text, 4.0, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(&text[findings[0].start..findings[0].end], "YWJjdGhlZmcta2V5LXZhbHVl=");
    }
}
