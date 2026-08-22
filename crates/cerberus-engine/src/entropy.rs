//! Generic entropy-based secret detector.
//!
//! Captures proprietary secrets that do not match any known regex pattern
//! but have high Shannon entropy and appear near indicative keywords.
//! This is a first-class virtual rule that always runs inside the engine.

use regex::Regex;

use crate::engine::{hash_value, Finding};
use crate::rule::{Action, Category, Severity};

/// Hashear un valor: HMAC-SHA256 si hay secret, si no SHA-256 plano.
/// (Revisión 2, P2 #11: la entropía ya no emite SHA-256 determinista cuando el
/// proxy tiene `CERBERUS_HMAC_SECRET`.)
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
const SKIP_CHARS: &[char] = &[' ', '\t', '\n', '\r', '=', ':', '"', '\'', ','];
/// Maximum window (in bytes) after a keyword to look for a value.
const NEAR_KEYWORD_WINDOW: usize = 200;
/// Minimum length of a candidate value to consider for entropy analysis.
const MIN_VALUE_LENGTH: usize = 8;

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
/// `threshold`, a [`Finding`] is produced. `secret` (opcional) habilita
/// HMAC-SHA256 en lugar de SHA-256 plano (revisión 2, P2 #11).
#[must_use]
pub fn detect_near_keywords(text: &str, threshold: f64, secret: Option<&[u8]>) -> Vec<Finding> {
    let mut findings = Vec::new();

    let pattern = format!(r"(?i)\b({})\b", KEYWORDS.join("|"));
    let Ok(kw_re) = Regex::new(&pattern) else {
        return findings;
    };

    for kw_match in kw_re.find_iter(text) {
        let kw_end = kw_match.end();
        let search_end = std::cmp::min(kw_end.wrapping_add(NEAR_KEYWORD_WINDOW), text.len());
        let context = &text[kw_end..search_end];
        if let Some((value, value_offset)) = extract_value(context) {
            if value.len() < MIN_VALUE_LENGTH {
                continue;
            }
            let ent = shannon_entropy(value);
            if ent > threshold {
                let abs_start = kw_end.wrapping_add(value_offset);
                let abs_end = abs_start.wrapping_add(value.len());
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

/// Extract the first candidate value token from a context string.
///
/// Skips leading whitespace and separators (`=`, `:`, `"`, `'`, `,`), then
/// returns the first contiguous non-whitespace token plus its byte offset
/// within `context`.
fn extract_value(context: &str) -> Option<(&str, usize)> {
    let start = context.find(|c: char| !SKIP_CHARS.contains(&c) && c != '}' && c != ';')?;
    let remaining = &context[start..];
    let end = remaining
        .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\'' || c == '}')
        .unwrap_or(remaining.len());
    let value = &remaining[..end];
    if value.is_empty() {
        None
    } else {
        Some((value, start))
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
}
