//! Hybrid AC+regex compiled engine and builder.

use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::constraints::check_constraints;
use crate::rule::{Action, Category, Rule, Severity};
use crate::validator::ValidatorRegistry;

const MIN_PREFIX_LEN: usize = 2;

/// Extract a literal prefix from a regex pattern for Aho-Corasick prefiltering.
///
/// Returns `Some(prefix)` if the pattern starts with a literal substring of
/// length ≥ [`MIN_PREFIX_LEN`], or `None` if the pattern begins with a
/// regex metacharacter (class, group, anchor, quantifier, etc.).
#[must_use]
pub fn extract_prefix(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    let mut prefix = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if i + 1 >= bytes.len() {
                    break;
                }
                match bytes[i + 1] {
                    b'b' | b'B' => {
                        i += 2;
                    }
                    b'p' | b'P' | b'd' | b'D' | b'w' | b'W' | b's' | b'S' | b'h' | b'H' | b'v' | b'V' | b'n' | b'r'
                    | b't' | b'f' | b'e' | b'x' | b'u' | b'U' | b'A' | b'z' | b'Z' | b'R' | b'0' => {
                        break;
                    }
                    _ => {
                        prefix.push(bytes[i + 1] as char);
                        i += 2;
                    }
                }
            }
            b'(' | b')' | b'[' | b']' | b'.' | b'?' | b'*' | b'+' | b'|' | b'^' | b'$' | b'{' | b'}' => {
                break;
            }
            _ => {
                prefix.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    if prefix.len() >= MIN_PREFIX_LEN {
        Some(prefix)
    } else {
        None
    }
}

/// A pattern compiled as part of the hybrid engine, linked back to its rule.
#[derive(Debug)]
struct PatternEntry {
    rule_idx: usize,
}

/// Compiled hybrid engine: Aho-Corasick prefilter + regex for detailed matching.
#[derive(Debug)]
pub struct CompiledEngine {
    rules: Vec<Rule>,
    /// Aho-Corasick automaton over literal prefixes (presence prefilter only).
    ac: AhoCorasick,
    /// For each AC pattern (by index), the list of regex patterns that share
    /// that prefix. Each entry holds the compiled regex and the owning rule.
    prefixed_entries: Vec<Vec<(Regex, PatternEntry)>>,
    /// Unprefixed patterns compiled individually (regexes aligned with entries).
    unprefixed_regexes: Vec<Regex>,
    /// Pattern entries for each unprefixed pattern.
    unprefixed_entries: Vec<PatternEntry>,
    /// Validators used to filter out false positives.
    validators: ValidatorRegistry,
    /// Shannon entropy threshold for the generic entropy detector.
    entropy_threshold: f64,
    /// Optional payload-hash secret (HMAC-SHA256). When `None`, falls back to
    /// plain SHA-256 (see review P1-12).
    payload_secret: Option<Vec<u8>>,
}

/// Builder that compiles a set of rules into a [`CompiledEngine`].
#[derive(Debug, Default)]
pub struct EngineBuilder {
    rules: Vec<Rule>,
    /// Shannon entropy threshold for the entropy detector (default 4.0).
    entropy_threshold: f64,
    /// Optional payload-hash secret (HMAC-SHA256).
    payload_secret: Option<Vec<u8>>,
}

/// Default Shannon entropy threshold used by the generic entropy detector.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.0;

impl EngineBuilder {
    /// Create a new builder with the given rules.
    #[must_use]
    pub fn new(rules: &[Rule]) -> Self {
        Self {
            rules: rules.to_vec(),
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            payload_secret: None,
        }
    }

    /// Set the Shannon entropy threshold for the generic entropy detector.
    #[must_use]
    pub const fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    /// Enable HMAC-SHA256 payload hashing with the given secret. Without this,
    /// finding hashes use plain SHA-256 (review P1-12).
    #[must_use]
    pub fn with_payload_secret(mut self, secret: Vec<u8>) -> Self {
        self.payload_secret = Some(secret);
        self
    }

    /// Build and compile the hybrid engine.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern fails to compile.
    pub fn build(self) -> Result<CompiledEngine, String> {
        CompiledEngine::compile(self.rules, self.entropy_threshold, self.payload_secret)
    }
}

impl CompiledEngine {
    fn compile(mut rules: Vec<Rule>, entropy_threshold: f64, payload_secret: Option<Vec<u8>>) -> Result<Self, String> {
        // Normalize context_keywords to lowercase at compilation time (P0-1 fix).
        // This ensures case-insensitive matching without per-match overhead.
        for rule in &mut rules {
            for kw in &mut rule.context_keywords {
                *kw = kw.to_lowercase();
            }
        }

        let mut pattern_entries: Vec<(String, PatternEntry)> = Vec::new();
        for (rule_idx, rule) in rules.iter().enumerate() {
            for pat in &rule.patterns {
                pattern_entries.push((pat.clone(), PatternEntry { rule_idx }));
            }
        }

        let mut ac_patterns: Vec<Vec<u8>> = Vec::new();
        let mut prefix_to_ac_id: HashMap<String, usize> = HashMap::new();
        let mut prefixed_entries: Vec<Vec<(Regex, PatternEntry)>> = Vec::new();
        let mut unprefixed_regexes: Vec<Regex> = Vec::new();
        let mut unprefixed_entries: Vec<PatternEntry> = Vec::new();

        for (pat, entry) in &pattern_entries {
            let pe = PatternEntry {
                rule_idx: entry.rule_idx,
            };
            if let Some(prefix) = extract_prefix(pat) {
                let ac_id = *prefix_to_ac_id.entry(prefix.clone()).or_insert_with(|| {
                    let id = ac_patterns.len();
                    ac_patterns.push(prefix.as_bytes().to_vec());
                    prefixed_entries.push(Vec::new());
                    id
                });
                let regex = Regex::new(pat).map_err(|e| format!("Regex compile error for pattern '{pat}': {e}"))?;
                prefixed_entries[ac_id].push((regex, pe));
            } else {
                let regex = Regex::new(pat).map_err(|e| format!("Regex compile error for pattern '{pat}': {e}"))?;
                unprefixed_regexes.push(regex);
                unprefixed_entries.push(pe);
            }
        }

        let ac = AhoCorasick::builder()
            .build(&ac_patterns)
            .map_err(|e| format!("Aho-Corasick build error: {e}"))?;

        Ok(Self {
            rules,
            ac,
            prefixed_entries,
            unprefixed_regexes,
            unprefixed_entries,
            validators: ValidatorRegistry::new(),
            entropy_threshold,
            payload_secret,
        })
    }

    /// Scan the given text and return all findings.
    ///
    /// Corregido (review P0-4):
    /// - AC is only a *presence* prefilter: every regex under a present prefix
    ///   is evaluated on the **full text** with `find_iter`, so overlapping
    ///   prefixes (`sk-` vs `sk-ant-`) no longer shadow each other.
    /// - Every occurrence of a pattern is reported, not just the first.
    /// - Multiline blocks report every match per pattern.
    /// - Findings are deduplicated by (flag, start, end).
    #[must_use]
    pub fn scan(&self, text: &str) -> ScanOutput {
        self.scan_with_context(text, text)
    }

    /// Escanear `text` evaluando las constraints de contexto (contextKeywords,
    /// allowed examples) contra `context`.
    ///
    /// Fija la regresión de la revisión 2 (P0): al redactar JSON leaf a leaf,
    /// los keywords de contexto viven en otros campos. Este método permite
    /// escanear el valor de un leaf usando el body completo como contexto.
    #[must_use]
    pub fn scan_with_context(&self, text: &str, context: &str) -> ScanOutput {
        let mut findings: Vec<Finding> = Vec::new();
        let mut seen: HashSet<(String, usize, usize)> = HashSet::new();

        // Prefixed patterns: mark presence via AC, then full-text find_iter.
        // Overlapping match kind ensures every prefix at a position is marked
        // (e.g. both `sk-` and `sk-ant-`), fixing review P0-4a.
        let n_ac = self.ac.patterns_len();
        if n_ac > 0 {
            let mut present = vec![false; n_ac];
            for m in self.ac.find_overlapping_iter(text.as_bytes()) {
                let id = m.pattern().as_usize();
                if id < present.len() {
                    present[id] = true;
                }
            }
            for (ac_id, &is_present) in present.iter().enumerate() {
                if !is_present {
                    continue;
                }
                if let Some(group) = self.prefixed_entries.get(ac_id) {
                    for (regex, entry) in group {
                        for m in regex.find_iter(text) {
                            if let Some(f) =
                                self.make_finding(&self.rules[entry.rule_idx], text, context, m.start(), m.end())
                            {
                                if seen.insert((f.flag.clone(), f.start, f.end)) {
                                    findings.push(f);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Unprefixed patterns: find_iter over the full text per pattern.
        for (regex, entry) in self.unprefixed_regexes.iter().zip(self.unprefixed_entries.iter()) {
            for m in regex.find_iter(text) {
                if let Some(f) = self.make_finding(&self.rules[entry.rule_idx], text, context, m.start(), m.end()) {
                    if seen.insert((f.flag.clone(), f.start, f.end)) {
                        findings.push(f);
                    }
                }
            }
        }

        // Multiline blocks: every match per multiline pattern.
        for rule in &self.rules {
            for pattern in &rule.patterns {
                if !crate::multiline::is_multiline_pattern(pattern) {
                    continue;
                }
                let ml = format!("(?m){pattern}");
                if let Ok(re) = Regex::new(&ml) {
                    for m in re.find_iter(text) {
                        if let Some(f) = self.make_finding(rule, text, context, m.start(), m.end()) {
                            if seen.insert((f.flag.clone(), f.start, f.end)) {
                                findings.push(f);
                            }
                        }
                    }
                }
            }
        }

        // Generic entropy-based detection (virtual rule, always active). For
        // leaf scans (context != text) el vecino de keywords lo busca en el
        // propio valor, que es lo correcto para warn/redact por leaf.
        for f in crate::entropy::detect_near_keywords(text, self.entropy_threshold, self.payload_secret.as_deref()) {
            if seen.insert((f.flag.clone(), f.start, f.end)) {
                findings.push(f);
            }
        }

        // Compute overall action: most severe action from all findings.
        // With no findings the request is simply allowed (review P1-12).
        let action_overall = findings.iter().map(|f| f.action).max().unwrap_or(Action::Allow);

        ScanOutput {
            findings,
            action_overall,
        }
    }

    fn make_finding(&self, rule: &Rule, text: &str, context: &str, start: usize, end: usize) -> Option<Finding> {
        let raw_value = &text[start..end];
        let trimmed = raw_value.trim();
        if !check_constraints(rule, trimmed, context) {
            return None;
        }
        if !self.validators.all_pass(&rule.validators, trimmed) {
            return None;
        }
        let hashed = self.payload_hash(trimmed);

        Some(Finding {
            flag: rule.flag.clone(),
            category: rule.category,
            severity: rule.severity,
            action: rule.action,
            start,
            end,
            hashed_value: hashed,
        })
    }

    /// Hash a payload value, using HMAC-SHA256 when a secret is configured.
    #[must_use]
    fn payload_hash(&self, value: &str) -> String {
        self.payload_secret
            .as_ref()
            .map_or_else(|| hash_value(value), |secret| hmac_sha256_hex(secret, value.as_bytes()))
    }

    /// Number of rules loaded.
    #[must_use]
    pub const fn num_rules(&self) -> usize {
        self.rules.len()
    }

    /// Iterate over the compiled rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// One detected secret/PII value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Rule flag, e.g. `"secret.openai_api_key"`.
    pub flag: String,
    /// Detection category.
    pub category: Category,
    /// Severity.
    pub severity: Severity,
    /// Action configured for this rule.
    pub action: Action,
    /// Start byte offset in the scanned text.
    pub start: usize,
    /// End byte offset (exclusive).
    pub end: usize,
    /// SHA-256 hex digest of the matched value. **Never the raw value.**
    pub hashed_value: String,
}

/// Result of a scan operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutput {
    /// All findings discovered during the scan.
    pub findings: Vec<Finding>,
    /// Most severe action across all findings.
    pub action_overall: Action,
}

/// Compute the SHA-256 hex digest of a value.
#[must_use]
pub fn hash_value(value: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize().as_slice()))
}

/// The `hex` crate is not available, so we provide a minimal encoding function.
mod hex {
    /// Encode bytes as a lowercase hex string.
    #[must_use]
    pub(super) fn encode(bytes: &[u8]) -> String {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX_CHARS[(b >> 4) as usize] as char);
            out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encode_empty() {
            assert_eq!(encode(b""), "");
        }

        #[test]
        fn encode_known() {
            assert_eq!(encode(b"hello"), "68656c6c6f");
        }

        #[test]
        fn encode_ff() {
            assert_eq!(encode(&[0xff]), "ff");
        }
    }
}

const HMAC_BLOCK: usize = 64;

/// HMAC-SHA256 per RFC 2104, implemented over `sha2` (no extra crate needed).
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut k = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK];
    let mut opad = [0x5cu8; HMAC_BLOCK];
    for (i, kk) in k.iter().enumerate() {
        ipad[i] ^= kk;
        opad[i] ^= kk;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// HMAC-SHA256 hex digest prefixed with `hmac:`.
#[must_use]
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    format!("hmac:{}", hex::encode(&hmac_sha256(key, message)))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn make_rule_full(flag: &str, category: Category, severity: Severity, action: Action, patterns: &[&str]) -> Rule {
        Rule {
            flag: flag.to_string(),
            category,
            severity,
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
    fn extract_prefix_sk() {
        assert_eq!(extract_prefix(r"sk-[A-Za-z0-9]{20,}"), Some("sk-".to_string()));
    }

    #[test]
    fn extract_prefix_ak() {
        assert_eq!(extract_prefix(r"AKIA[0-9A-Z]{16}"), Some("AKIA".to_string()));
    }

    #[test]
    fn extract_prefix_none_for_class() {
        assert_eq!(extract_prefix(r"\d{5}"), None);
        assert_eq!(extract_prefix(r"[0-9a-f]{32}"), None);
        assert_eq!(extract_prefix(r"\bkey\b"), Some("key".to_string()));
    }

    #[test]
    fn compile_zero_rules() {
        let engine = EngineBuilder::new(&[]).build().unwrap();
        assert_eq!(engine.num_rules(), 0);
        let result = engine.scan("anything");
        assert!(result.findings.is_empty());
        assert_eq!(result.action_overall, Action::Allow);
    }

    #[test]
    fn compile_one_rule() {
        let rules = vec![make_rule("test.one", &["secret"], Action::Warn)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        assert_eq!(engine.num_rules(), 1);
    }

    #[test]
    fn compile_many_rules() {
        let rules = vec![
            make_rule("r1", &["foo"], Action::Warn),
            make_rule("r2", &["bar"], Action::Block),
            make_rule("r3", &["baz", "qux"], Action::Redact),
        ];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        assert_eq!(engine.num_rules(), 3);
    }

    #[test]
    fn scan_no_secrets() {
        let rules = vec![make_rule("test.secret", &[r"sk-[A-Za-z0-9]{20,}"], Action::Block)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("just some benign text");
        assert!(result.findings.is_empty());
        assert_eq!(result.action_overall, Action::Allow);
    }

    #[test]
    fn scan_detects_secret() {
        let rules = vec![make_rule("test.openai", &[r"sk-[A-Za-z0-9]{20,}"], Action::Block)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("api key: sk-abcDEFghijklmnopqrstuvwxyz1234");
        // 1 from regex + 1 from entropy (keyword "key" + high-entropy value)
        assert_eq!(result.findings.len(), 2);
        let regex_finding = result.findings.iter().find(|f| f.flag == "test.openai").unwrap();
        assert_eq!(regex_finding.action, Action::Block);
        let entropy_finding = result
            .findings
            .iter()
            .find(|f| f.flag == "entropy.high_entropy_secret")
            .unwrap();
        assert_eq!(entropy_finding.action, Action::Warn);
        // Hashed value should NOT be the raw value
        assert_ne!(result.findings[0].hashed_value, "sk-abcDEFghijklmnopqrstuvwxyz1234");
        assert!(result.findings[0].hashed_value.starts_with("sha256:"));
        assert_eq!(result.findings[0].hashed_value.len(), 64 + 7); // "sha256:" + 64 hex chars
    }

    #[test]
    fn finding_never_contains_raw_value() {
        let rules = vec![make_rule("test.raw", &[r"secret-value-\d+"], Action::Block)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("my secret-value-42 is here");
        assert_eq!(result.findings.len(), 1);
        assert_ne!(result.findings[0].hashed_value, "secret-value-42");
        assert!(!result.findings[0].hashed_value.contains("secret-value-42"));
    }

    #[test]
    fn action_per_rule_honoured() {
        let rules = vec![
            make_rule("test.warn", &["warning"], Action::Warn),
            make_rule("test.block", &["blocking"], Action::Block),
            make_rule("test.allow", &["allowing"], Action::Allow),
        ];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("warning and blocking and allowing");
        assert_eq!(result.findings.len(), 3);
        // Find the action for each finding
        let warn_finding = result.findings.iter().find(|f| f.flag == "test.warn").unwrap();
        assert_eq!(warn_finding.action, Action::Warn);
        let block_finding = result.findings.iter().find(|f| f.flag == "test.block").unwrap();
        assert_eq!(block_finding.action, Action::Block);
        let allow_finding = result.findings.iter().find(|f| f.flag == "test.allow").unwrap();
        assert_eq!(allow_finding.action, Action::Allow);
        // Overall action should be the most severe (Block > Warn > Allow)
        assert_eq!(result.action_overall, Action::Block);
    }

    #[test]
    fn scan_unprefixed_pattern() {
        let rules = vec![make_rule("test.zipcode", &[r"\b\d{5}\b"], Action::Warn)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("zip code 12345 here");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].flag, "test.zipcode");
    }

    #[test]
    fn scan_multiple_patterns_same_rule() {
        let rules = vec![make_rule_full(
            "test.multi",
            Category::Secrets,
            Severity::High,
            Action::Redact,
            &[r"sk-[A-Za-z0-9]{20,}", r"AKIA[0-9A-Z]{16}"],
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("sk-abcDEFghijklmnopqrstuvwxyz1234 and AKIA1234567890ABCDEF");
        assert_eq!(result.findings.len(), 2);
        for f in &result.findings {
            assert_eq!(f.flag, "test.multi");
            assert_eq!(f.action, Action::Redact);
        }
    }

    #[test]
    fn prefixed_and_unprefixed_mixed() {
        let rules = vec![
            make_rule("r.prefixed", &[r"sk-[A-Za-z0-9]{20,}"], Action::Warn),
            make_rule("r.unprefixed", &[r"\b\d{5}\b"], Action::Warn),
        ];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("sk-abcDEFghijklmnopqrstuvwxyz1234 and zip 12345");
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn hash_value_is_sha256() {
        let h = hash_value("hello");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 64 + 7);
        // Deterministic
        assert_eq!(hash_value("hello"), hash_value("hello"));
        assert_ne!(hash_value("hello"), hash_value("world"));
    }

    #[test]
    fn scan_output_action_overall_most_severe() {
        let rules = vec![
            make_rule("a", &["aaa"], Action::Allow),
            make_rule("b", &["bbb"], Action::Warn),
            make_rule("c", &["ccc"], Action::Block),
        ];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("aaa bbb ccc");
        // Block > Warn > Allow
        assert_eq!(result.action_overall, Action::Block);
    }

    #[test]
    fn scan_allow_rule_passes_through() {
        let rules = vec![make_rule("test.allow", &["allow-me"], Action::Allow)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("allow-me");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].action, Action::Allow);
        assert_eq!(result.action_overall, Action::Allow);
    }

    #[test]
    fn compile_invalid_regex_returns_error() {
        let rules = vec![make_rule("bad", &[r"[invalid"], Action::Warn)];
        let err = EngineBuilder::new(&rules).build().unwrap_err();
        assert!(err.contains("error") || err.contains("compile"), "got: {err}");
    }

    #[test]
    fn scan_text_with_no_match() {
        let rules = vec![make_rule("test.none", &[r"AAA"], Action::Warn)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("BBB CCC DDD");
        assert!(result.findings.is_empty());
        assert_eq!(result.action_overall, Action::Allow);
    }

    fn make_rule_with_validators(flag: &str, patterns: &[&str], validators: &[&str], action: Action) -> Rule {
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
            validators: validators.iter().map(std::string::ToString::to_string).collect(),
        }
    }

    #[test]
    fn scan_without_validators_passes_match() {
        // A rule without validators must keep the match (no filtering).
        let rules = vec![make_rule_with_validators(
            "card.plain",
            &[r"\b\d{13,19}\b"],
            &[],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("number 1234567812345678");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].flag, "card.plain");
    }

    #[test]
    fn scan_with_luhn_validator_keeps_valid_card() {
        let rules = vec![make_rule_with_validators(
            "card.luhn",
            &[r"\b\d{13,19}\b"],
            &["luhn"],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("card 4111111111111111 here");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].flag, "card.luhn");
    }

    #[test]
    fn scan_with_luhn_validator_discards_invalid_card() {
        let rules = vec![make_rule_with_validators(
            "card.luhn",
            &[r"\b\d{13,19}\b"],
            &["luhn"],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        // 1234567812345678 fails the Luhn checksum → finding must be dropped.
        let result = engine.scan("card 1234567812345678 here");
        assert!(result.findings.is_empty());
        assert_eq!(result.action_overall, Action::Allow);
    }

    #[test]
    fn scan_with_entropy_validator_keeps_high_entropy() {
        let rules = vec![make_rule_with_validators(
            "secret.high_entropy",
            &[r"[A-Za-z0-9]{30,}"],
            &["shannon-entropy>4.0"],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules)
            .with_entropy_threshold(999.0)
            .build()
            .unwrap();
        // 40 distinct chars → entropy ≈ log2(40) > 4.0
        let token = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0";
        let result = engine.scan(&format!("token {token}"));
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn scan_with_entropy_validator_discards_low_entropy() {
        let rules = vec![make_rule_with_validators(
            "secret.low_entropy",
            &[r"[A-Za-z0-9]{30,}"],
            &["shannon-entropy>4.0"],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_with_unknown_validator_fails_closed() {
        // Unknown validator names fail closed: the finding is dropped.
        let rules = vec![make_rule_with_validators(
            "t.unknown",
            &[r"abc"],
            &["nonexistent_validator"],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("abc");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_with_multiple_validators_requires_all() {
        // Pattern matches both numbers, but only the second passes Luhn → only one finding.
        let rules = vec![make_rule_with_validators(
            "card.luhn",
            &[r"\b\d{13,19}\b"],
            &["luhn"],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("4111111111111111 1234567812345678");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].hashed_value, hash_value("4111111111111111"));
    }

    // ─── Review P0-4 regressions ─────────────────────────────────────────

    #[test]
    fn overlapping_prefixes_both_detected() {
        // "sk-" shadows "sk-ant-" under AC standard matching; full-text find_iter
        // must still surface the Anthropic (critical) rule.
        let rules = vec![
            make_rule("secret.openai", &[r"\bsk-[A-Za-z0-9]{20,}\b"], Action::Block),
            make_rule("secret.anthropic", &[r"\bsk-ant-[A-Za-z0-9]{20,}\b"], Action::Block),
        ];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let text = "anthropic api key is sk-ant-Abcdefghijklmnopqrstuvwxyz123456";
        let result = engine.scan(text);
        assert!(
            result.findings.iter().any(|f| f.flag == "secret.anthropic"),
            "anthropic rule must fire with overlapping prefixes; got {:?}",
            result.findings.iter().map(|f| f.flag.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn multiple_occurrences_all_reported() {
        let rules = vec![make_rule(
            "pii.email",
            &[r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"],
            Action::Warn,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let result = engine.scan("escribe a juan@example.com o a maria@example.com");
        let emails = result.findings.iter().filter(|f| f.flag == "pii.email").count();
        assert_eq!(emails, 2, "both email occurrences must be reported");
    }

    #[test]
    fn multiple_multiline_blocks_reported() {
        let rules = vec![make_rule(
            "pem",
            &[r"-----BEGIN RSA PRIVATE KEY-----\n(?:.*\n)*?-----END RSA PRIVATE KEY-----"],
            Action::Block,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n  \n-----BEGIN RSA PRIVATE KEY-----\nBBBB\n-----END RSA PRIVATE KEY-----";
        let result = engine.scan(text);
        let pems = result.findings.iter().filter(|f| f.flag == "pem").count();
        assert_eq!(pems, 2, "both PEM blocks must be reported");
    }

    #[test]
    fn no_findings_yields_allow() {
        let rules = vec![make_rule("r", &["never-matches"], Action::Block)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        assert_eq!(engine.scan("hola mundo sin secretos").action_overall, Action::Allow);
    }

    #[test]
    fn hmac_sha256_rfc_vectors() {
        // RFC 4231 test vector 1: key = 0x0b x20, data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let digest = hmac_sha256(&key, data);
        let expected_hex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(super::hex::encode(&digest), expected_hex);
    }

    #[test]
    fn payload_secret_uses_hmac() {
        let rules = vec![make_rule("t", &["secret"], Action::Warn)];
        let engine = EngineBuilder::new(&rules)
            .with_payload_secret(b"local-org-key".to_vec())
            .build()
            .unwrap();
        let out = engine.scan("the secret value here");
        assert!(out.findings[0].hashed_value.starts_with("hmac:"));
    }

    #[test]
    fn payload_hash_plain_sha256_default() {
        let rules = vec![make_rule("t", &["secret"], Action::Warn)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let out = engine.scan("the secret value here");
        assert!(out.findings[0].hashed_value.starts_with("sha256:"));
    }
}
