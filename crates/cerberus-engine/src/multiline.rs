//! Multiline block detection for PEM private keys, SSH keys, and .env files.
//!
//! These patterns span multiple lines and represent high-severity leaks that
//! single-line regex cannot capture reliably. The module is called **after**
//! normal single-line regex matching has completed.

use regex::Regex;

use crate::engine::Finding;
use crate::rule::Rule;

/// Check whether a pattern should be treated as multiline.
///
/// A pattern is considered multiline if it contains `\n`, `-----BEGIN`,
/// or `\n\n` — markers that indicate the pattern spans multiple lines.
#[must_use]
pub fn is_multiline_pattern(pattern: &str) -> bool {
    pattern.contains("-----BEGIN") || pattern.contains("\\n\\n") || pattern.contains("\\n")
}

/// Detect multiline blocks in the given text for a specific rule.
///
/// Called **after** normal single-line regex matching. Only evaluates
/// patterns that are considered multiline (containing `\n`, `-----BEGIN`,
/// or `\n\n`). Patterns are compiled with `(?m)` for multi-line mode.
///
/// Returns `Some(Finding)` if a multiline block is detected, `None` otherwise.
#[must_use]
pub fn detect_multiline(text: &str, rule: &Rule) -> Option<Finding> {
    let multiline_patterns: Vec<&str> = rule
        .patterns
        .iter()
        .map(String::as_str)
        .filter(|p| is_multiline_pattern(p))
        .collect();

    if multiline_patterns.is_empty() {
        return None;
    }

    for pattern in &multiline_patterns {
        let multiline_regex_str = format!("(?m){pattern}");
        if let Ok(re) = Regex::new(&multiline_regex_str) {
            if let Some(mat) = re.find(text) {
                let raw_value = &text[mat.start()..mat.end()];
                let hashed = crate::engine::hash_value(raw_value.trim());

                return Some(Finding {
                    flag: rule.flag.clone(),
                    category: rule.category,
                    severity: rule.severity,
                    action: rule.action,
                    start: mat.start(),
                    end: mat.end(),
                    hashed_value: hashed,
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{Action, Category, Severity};

    fn make_rule(flag: &str, patterns: &[&str]) -> Rule {
        Rule {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::Critical,
            action: Action::Block,
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
    fn detects_pem_rsa_private_key() {
        let text = "some text before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\nsome text after";
        let rule = make_rule(
            "secret.pem_rsa",
            &[r"-----BEGIN RSA PRIVATE KEY-----\n(?:.*\n)*?-----END RSA PRIVATE KEY-----"],
        );
        let finding = detect_multiline(text, &rule);
        assert!(finding.is_some(), "PEM RSA key should be detected");
        let f = finding.unwrap();
        assert_eq!(f.flag, "secret.pem_rsa");
        assert!(f.start < f.end);
        assert!(f.hashed_value.starts_with("sha256:"));
    }

    #[test]
    fn detects_pem_ec_private_key() {
        let text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIIm3V\n-----END EC PRIVATE KEY-----";
        let rule = make_rule(
            "secret.pem_ec",
            &[r"-----BEGIN EC PRIVATE KEY-----\n(?:.*\n)*?-----END EC PRIVATE KEY-----"],
        );
        let finding = detect_multiline(text, &rule);
        assert!(finding.is_some(), "PEM EC key should be detected");
    }

    #[test]
    fn detects_pem_openssh_private_key() {
        let text =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----";
        let rule = make_rule(
            "secret.pem_openssh",
            &[r"-----BEGIN OPENSSH PRIVATE KEY-----\n(?:.*\n)*?-----END OPENSSH PRIVATE KEY-----"],
        );
        let finding = detect_multiline(text, &rule);
        assert!(finding.is_some(), "PEM OPENSSH key should be detected");
    }

    #[test]
    fn detects_pem_dsa_private_key() {
        let text = "-----BEGIN DSA PRIVATE KEY-----\nMIIBvAIBAAKBgQDw\n-----END DSA PRIVATE KEY-----";
        let rule = make_rule(
            "secret.pem_dsa",
            &[r"-----BEGIN DSA PRIVATE KEY-----\n(?:.*\n)*?-----END DSA PRIVATE KEY-----"],
        );
        let finding = detect_multiline(text, &rule);
        assert!(finding.is_some(), "PEM DSA key should be detected");
    }

    #[test]
    fn pem_block_captures_full_range() {
        let text = "prefix\n-----BEGIN RSA PRIVATE KEY-----\nline1\nline2\n-----END RSA PRIVATE KEY-----\nsuffix";
        let rule = make_rule(
            "secret.pem",
            &[r"-----BEGIN RSA PRIVATE KEY-----\n(?:.*\n)*?-----END RSA PRIVATE KEY-----"],
        );
        let finding = detect_multiline(text, &rule).unwrap();
        let captured = &text[finding.start..finding.end];
        assert!(
            captured.starts_with("-----BEGIN RSA PRIVATE KEY-----"),
            "captured block should start with BEGIN marker, got: {captured:?}"
        );
        assert!(
            captured.ends_with("-----END RSA PRIVATE KEY-----"),
            "captured block should end with END marker, got: {captured:?}"
        );
        assert!(
            captured.contains("\nline1\n"),
            "captured block should contain all body lines"
        );
        assert!(
            captured.contains("\nline2\n"),
            "captured block should contain all body lines"
        );
    }

    #[test]
    fn detects_env_file_with_secrets() {
        let text = "DB_PASSWORD=secret123\nAPI_TOKEN=abc123xyz\nDB_HOST=localhost";
        let rule = make_rule(
            "secret.env_file",
            &[r"(?:^|\n)(?:DB_PASSWORD|API_TOKEN|SECRET_KEY|API_KEY|PASSWORD|TOKEN|SECRET)=.*\n?"],
        );
        let finding = detect_multiline(text, &rule);
        assert!(finding.is_some(), ".env with secrets should be detected");
        let f = finding.unwrap();
        assert_eq!(f.flag, "secret.env_file");
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let rule = make_rule(
            "secret.pem",
            &[r"-----BEGIN RSA PRIVATE KEY-----\n(?:.*\n)*?-----END RSA PRIVATE KEY-----"],
        );
        let finding = detect_multiline("just some normal text without any keys", &rule);
        assert!(finding.is_none(), "normal text should not trigger PEM detection");
    }

    #[test]
    fn no_detection_without_multiline_pattern() {
        let rule = make_rule("test.simple", &[r"sk-[A-Za-z0-9]{20,}"]);
        let finding = detect_multiline("sk-abcDEFghijklmnopqrstuvwxyz1234", &rule);
        assert!(
            finding.is_none(),
            "single-line patterns should not trigger multiline detection"
        );
    }

    #[test]
    fn detects_id_rsa_ssh_key() {
        let text = "some text\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\nmore text";
        let rule = make_rule(
            "secret.ssh_key",
            &[r"-----BEGIN OPENSSH PRIVATE KEY-----\n(?:.*\n)*?-----END OPENSSH PRIVATE KEY-----"],
        );
        let finding = detect_multiline(text, &rule);
        assert!(finding.is_some(), "SSH key should be detected");
    }

    #[test]
    fn multiline_pattern_detection() {
        assert!(is_multiline_pattern("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(is_multiline_pattern(r"line1\nline2"));
        assert!(is_multiline_pattern(r"foo\\n\\nbar"));
        assert!(!is_multiline_pattern(r"sk-[A-Za-z0-9]{20,}"));
        assert!(!is_multiline_pattern(r"\b\d{5}\b"));
    }

    #[test]
    fn pem_block_multi_line_body() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,1234\n\nMIIEpAIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----";
        let rule = make_rule(
            "secret.pem_encrypted",
            &[r"-----BEGIN RSA PRIVATE KEY-----\n(?:.*\n)*?-----END RSA PRIVATE KEY-----"],
        );
        let finding = detect_multiline(text, &rule);
        assert!(finding.is_some(), "encrypted PEM key should be detected");
        let captured = &text[finding.as_ref().unwrap().start..finding.unwrap().end];
        assert!(captured.contains("Proc-Type:"), "should capture headers");
        assert!(captured.contains("DEK-Info:"), "should capture DEK-Info");
    }
}
