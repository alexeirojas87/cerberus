//! Hybrid AC+regex compiled engine and builder.

use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::constraints::{check_constraints_simple, check_constraints_with_analyzer, ContextAnalyzer};
use crate::rule::{Action, Category, Rule, Severity};
use crate::validator::{payment_card_valid, ValidatorRegistry};

const MIN_PREFIX_LEN: usize = 2;

/// The shipped separated-PAN pattern has a byte-linear specialized matcher.
/// It remains a valid bounded regex (and is compiled at build time), while the
/// scan path avoids the regex crate's high constant-factor Unicode NFA for
/// dense NBSP/space separator runs.
const BOUNDED_PAYMENT_CARD_PATTERN: &str =
    "(?:\\+[0-9](?:(?:[ \u{a0}]{1,3}|[./-])?[0-9]){12,18}\\b|\\b[0-9](?:(?:[ \u{a0}]{1,3}|[./-])?[0-9]){12,18}\\b)";

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

/// Compile the one-way presence filter for contextual keywords.
fn compile_context_keyword_prefilter(rules: &[Rule]) -> Result<(Option<AhoCorasick>, bool), String> {
    let context_keywords = rules
        .iter()
        .flat_map(|rule| rule.context_keywords.iter())
        .filter(|keyword| !keyword.is_empty())
        .collect::<Vec<_>>();
    let has_context_keywords = !context_keywords.is_empty();
    let mut ascii_keywords = context_keywords
        .iter()
        .filter(|keyword| keyword.is_ascii())
        .map(|keyword| keyword.as_bytes())
        .collect::<Vec<_>>();
    ascii_keywords.sort_unstable();
    ascii_keywords.dedup();
    let prefilter = if ascii_keywords.is_empty() {
        None
    } else {
        Some(
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(ascii_keywords)
                .map_err(|e| format!("Context keyword prefilter build error: {e}"))?,
        )
    };
    Ok((prefilter, has_context_keywords))
}

/// Pattern list and id buckets appended to the merged presence automaton
/// after the literal prefixes, in single-pass order: entropy indicative
/// keywords, deduped non-empty ASCII contextual keywords (same collection
/// semantics as [`compile_context_keyword_prefilter`]), then the entropy
/// fold-to-ASCII source characters.
struct MergedPresenceBuckets {
    patterns: Vec<Vec<u8>>,
    entropy_ids: Vec<usize>,
    context_ids: Vec<usize>,
    fold_source_ids: Vec<usize>,
}

/// Keyword patterns appended to the merged presence automaton after the
/// literal prefixes, with their pattern ids (see [`MergedPresenceBuckets`]).
fn merged_presence_buckets(rules: &[Rule], start_id: usize) -> Result<MergedPresenceBuckets, String> {
    let mut patterns: Vec<Vec<u8>> = crate::entropy::EntropyDetector::keywords()
        .iter()
        .map(|keyword| keyword.as_bytes().to_vec())
        .collect();
    let entropy_ids: Vec<usize> = (start_id..start_id + patterns.len()).collect();

    let mut context_keywords = rules
        .iter()
        .flat_map(|rule| rule.context_keywords.iter())
        .filter(|keyword| !keyword.is_empty() && keyword.is_ascii())
        .cloned()
        .collect::<Vec<_>>();
    context_keywords.sort_unstable();
    context_keywords.dedup();
    let context_start = start_id + patterns.len();
    patterns.extend(context_keywords.iter().map(|keyword| keyword.as_bytes().to_vec()));
    let context_ids: Vec<usize> = (context_start..start_id + patterns.len()).collect();

    let (fold_patterns, fold_ids) = entropy_fold_source_bucket(start_id + patterns.len())?;
    patterns.extend(fold_patterns);

    Ok(MergedPresenceBuckets {
        patterns,
        entropy_ids,
        context_ids,
        fold_source_ids: fold_ids,
    })
}

/// Presence-bucket patterns for non-ASCII characters that Unicode simple case
/// folding makes matchable by the entropy keyword regex (attempt-6 repair of
/// the attempt-5 P1). A keyword regex match must contain either a plain ASCII
/// keyword byte sequence (caught by the keyword bucket) or at least one
/// fold-source character (caught here), so marking both buckets in the same
/// single pass keeps an automaton miss a sound absence proof for every
/// payload — ASCII and non-ASCII alike — without running the Unicode regex
/// unconditionally.
fn entropy_fold_source_bucket(start_id: usize) -> Result<(Vec<Vec<u8>>, Vec<usize>), String> {
    let patterns = crate::entropy::EntropyDetector::fold_to_ascii_source_patterns()?;
    let ids: Vec<usize> = (start_id..start_id + patterns.len()).collect();
    Ok((patterns, ids))
}

/// A pattern compiled as part of the hybrid engine, linked back to its rule.
#[derive(Debug)]
struct PatternEntry {
    rule_idx: usize,
}

#[derive(Debug)]
struct MultilineEntry {
    regex: Regex,
    pattern: PatternEntry,
    prefix_ac_id: Option<usize>,
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
    /// Bounded separated-PAN patterns handled by the byte-linear matcher.
    payment_card_entries: Vec<PatternEntry>,
    /// Multiline-mode regexes compiled once at engine build time.
    multiline_entries: Vec<MultilineEntry>,
    /// Generic entropy detector with its keyword regex compiled at build time.
    entropy_detector: crate::entropy::EntropyDetector,
    /// Validators used to filter out false positives.
    validators: ValidatorRegistry,
    /// Shannon entropy threshold for the generic entropy detector.
    entropy_threshold: f64,
    /// Optional payload-hash secret (HMAC-SHA256). When `None`, falls back to
    /// plain SHA-256 (see review P1-12).
    payload_secret: Option<Vec<u8>>,
    /// Presence-only prefilter over non-empty ASCII `contextKeywords`.
    ///
    /// A miss proves that an ASCII context cannot satisfy any contextual
    /// rule, allowing the scan to skip Unicode normalization and line maps.
    /// Non-ASCII contexts conservatively bypass this filter because Unicode
    /// lowercase expansion can change the byte representation.
    ///
    /// Only consulted when `context` is a different buffer than `text`; when
    /// they are the same buffer, the merged presence pass below already
    /// answers the context-keyword question.
    context_keyword_prefilter: Option<AhoCorasick>,
    /// Whether at least one rule has a non-empty contextual keyword.
    has_context_keywords: bool,
    /// Automaton pattern ids of the entropy indicative keywords. A single
    /// case-insensitive presence pass marks prefixes, entropy keywords and
    /// contextual keywords at once; these ids index the entropy bucket.
    entropy_keyword_ids: Vec<usize>,
    /// Automaton pattern ids of non-ASCII characters whose Unicode simple
    /// case folding is matchable by an ASCII keyword letter (see
    /// [`entropy_fold_source_bucket`]). Together with [`Self::entropy_keyword_ids`]
    /// this bucket makes the automaton miss a sound absence proof for the
    /// entropy regex on non-ASCII payloads too.
    entropy_fold_source_ids: Vec<usize>,
    /// Automaton pattern ids of non-empty ASCII contextual keywords (same
    /// collection and dedup semantics as [`compile_context_keyword_prefilter`]).
    context_keyword_ids: Vec<usize>,
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

        let validators = ValidatorRegistry::new();
        for rule in &rules {
            for validator in &rule.validators {
                if validators.get(validator).is_none() {
                    return Err(format!(
                        "Unknown validator '{validator}' configured for rule '{}'",
                        rule.flag
                    ));
                }
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
        let mut payment_card_entries: Vec<PatternEntry> = Vec::new();
        let mut multiline_entries: Vec<MultilineEntry> = Vec::new();

        for (pat, entry) in &pattern_entries {
            let pe = PatternEntry {
                rule_idx: entry.rule_idx,
            };
            let rule = &rules[entry.rule_idx];
            if pat == BOUNDED_PAYMENT_CARD_PATTERN && rule.validators.iter().any(|v| v == "payment-card") {
                // Compile once so malformed patterns still fail construction;
                // scanning uses the equivalent bounded byte matcher below.
                Regex::new(pat).map_err(|e| format!("Regex compile error for pattern '{pat}': {e}"))?;
                payment_card_entries.push(pe);
                continue;
            }
            if crate::multiline::is_multiline_pattern(pat) {
                let multiline_pattern = format!("(?m){pat}");
                let regex = Regex::new(&multiline_pattern)
                    .map_err(|e| format!("Multiline regex compile error for pattern '{pat}': {e}"))?;
                let prefix_ac_id = extract_prefix(pat).map(|prefix| {
                    *prefix_to_ac_id.entry(prefix.clone()).or_insert_with(|| {
                        let id = ac_patterns.len();
                        ac_patterns.push(prefix.as_bytes().to_vec());
                        prefixed_entries.push(Vec::new());
                        id
                    })
                });
                multiline_entries.push(MultilineEntry {
                    regex,
                    pattern: pe,
                    prefix_ac_id,
                });
                continue;
            }
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

        let entropy_detector = crate::entropy::EntropyDetector::compile()
            .map_err(|e| format!("Entropy keyword regex compile error: {e}"))?;

        let (context_keyword_prefilter, has_context_keywords) = compile_context_keyword_prefilter(&rules)?;

        // One case-insensitive automaton answers every presence question in a
        // single full-text pass: literal prefixes (prefixed and multiline
        // regex gates), entropy indicative keywords, contextual keywords and
        // the entropy fold-to-ASCII source characters. Presence proofs are
        // one-way — a miss proves absence, a hit may be a false positive that
        // the per-pattern regex or analyzer later rejects — so folding the
        // keyword sets into the prefix automaton can only skip more work,
        // never change findings. Scope: the keyword bucket alone is sound for
        // ASCII text; for non-ASCII text the Unicode-case-insensitive entropy
        // regex can match folded keyword spellings (U+017F, U+212A, …) that
        // the ASCII-only keyword bucket cannot see, so the fold-source bucket
        // below marks every such character and keeps the miss-proves-absence
        // property for all payloads. The context-analyzer decision keeps its
        // own `!context.is_ascii()` fallback for the same folding reason.
        let buckets = merged_presence_buckets(&rules, ac_patterns.len())?;
        ac_patterns.extend(buckets.patterns);

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&ac_patterns)
            .map_err(|e| format!("Aho-Corasick build error: {e}"))?;

        Ok(Self {
            rules,
            ac,
            prefixed_entries,
            unprefixed_regexes,
            unprefixed_entries,
            payment_card_entries,
            multiline_entries,
            entropy_detector,
            validators,
            entropy_threshold,
            payload_secret,
            context_keyword_prefilter,
            has_context_keywords,
            entropy_keyword_ids: buckets.entropy_ids,
            entropy_fold_source_ids: buckets.fold_source_ids,
            context_keyword_ids: buckets.context_ids,
        })
    }

    /// Scan the given text and return all findings.
    ///
    /// Fixed (review P0-4):
    /// - AC is only a *presence* prefilter: every regex under a present prefix
    ///   is evaluated on the **full text** with `find_iter`, so overlapping
    ///   prefixes (`sk-` vs `sk-ant-`) no longer shadow each other.
    /// - Every occurrence of a pattern is reported, not just the first.
    /// - Multiline blocks report every match per pattern.
    /// - Findings are deduplicated by (flag, start, end).
    #[must_use]
    pub fn scan(&self, text: &str) -> ScanOutput {
        // text and context are the same buffer: match offsets are valid
        // context offsets, so the same-line proximity window applies.
        self.scan_inner(text, text, true)
    }

    /// Scan `text` evaluating the context constraints (contextKeywords,
    /// allowed examples) against `context`.
    ///
    /// Fixes review 2 regression (P0): when redacting JSON leaf by leaf,
    /// context keywords live in other fields. This method allows scanning
    /// a leaf's value using the full body as context.
    #[must_use]
    pub fn scan_with_context(&self, text: &str, context: &str) -> ScanOutput {
        // Match offsets are relative to `text`, not `context`, so the
        // proximity window is undefined here; the keyword check falls back to
        // a word-boundary search over the whole context.
        self.scan_inner(text, context, false)
    }

    /// Scan a leaf value using a context analyzer prepared once by the caller.
    /// This is intended for structured bodies with many leaves sharing the
    /// same context; it avoids normalizing the full body once per leaf.
    #[must_use]
    pub fn scan_with_context_analyzer(&self, text: &str, analyzer: &ContextAnalyzer<'_>) -> ScanOutput {
        self.scan_inner_prepared(text, Some(analyzer), false)
    }

    /// Emit deduplicated findings for one rule over the given match spans.
    #[allow(clippy::too_many_arguments)]
    fn collect_rule_spans(
        &self,
        rule_idx: usize,
        spans: impl Iterator<Item = (usize, usize)>,
        text: &str,
        analyzer: Option<&ContextAnalyzer<'_>>,
        offsets_in_context: bool,
        seen: &mut HashSet<(String, usize, usize)>,
        findings: &mut Vec<Finding>,
    ) {
        // `None` means the compiled presence prefilter proved that no
        // contextual keyword can occur. Returning before consuming `spans`
        // also avoids running the owning regex.
        if !self.rules[rule_idx].context_keywords.is_empty() && analyzer.is_none() {
            return;
        }
        for (start, end) in spans {
            if let Some(f) = self.make_finding(&self.rules[rule_idx], text, analyzer, offsets_in_context, start, end) {
                if seen.insert((f.flag.clone(), f.start, f.end)) {
                    findings.push(f);
                }
            }
        }
    }

    #[must_use]
    fn scan_inner(&self, text: &str, context: &str, offsets_in_context: bool) -> ScanOutput {
        // Normalize the context at most ONCE per scan (fixes the R9-F1.2
        // perf quadratic: the old code did a full `context.to_lowercase()` per
        // match, making 100 KB phone-list payloads ~195 ms — 40× over budget).
        // For ASCII contexts, the compiled presence prefilter can prove that
        // no non-empty keyword occurs. Non-ASCII contexts always take the
        // conservative Unicode path because lowercase expansion can alter
        // bytes (for example, U+0130).
        //
        // One presence pass over the payload marks prefixes, entropy keywords
        // and — when `context` is the same buffer as `text` — contextual
        // keywords, so the analyzer decision reuses it instead of scanning a
        // second time.
        let presence = self.presence_scan(text);
        let analyzer = if !self.has_context_keywords {
            None
        } else if std::ptr::eq(text, context) {
            // Same decision as `context_keywords_may_match` answered from the
            // merged presence pass: a non-ASCII context conservatively builds
            // the analyzer (Unicode case-folding can alter bytes), while an
            // ASCII context needs a case-insensitive keyword hit. The bucket
            // only holds ASCII keywords, so when a rule has exclusively
            // non-ASCII keywords the ASCII-context answer stays `None`.
            if !context.is_ascii() || self.context_keyword_ids.iter().any(|&id| presence[id]) {
                Some(ContextAnalyzer::new(context))
            } else {
                None
            }
        } else if self.context_keywords_may_match(context) {
            Some(ContextAnalyzer::new(context))
        } else {
            None
        };
        self.scan_inner_prepared_with_presence(text, analyzer.as_ref(), offsets_in_context, &presence)
    }

    #[must_use]
    fn scan_inner_prepared(
        &self,
        text: &str,
        analyzer: Option<&ContextAnalyzer<'_>>,
        offsets_in_context: bool,
    ) -> ScanOutput {
        let presence = self.presence_scan(text);
        self.scan_inner_prepared_with_presence(text, analyzer, offsets_in_context, &presence)
    }

    /// One full-text overlapping pass marking every merged automaton pattern
    /// that occurs anywhere in `text`: literal prefixes, entropy keywords,
    /// contextual keywords and the entropy fold-to-ASCII source characters. A
    /// miss proves absence (a hit may be a false positive that the
    /// per-pattern regex or analyzer later rejects); the fold-source bucket
    /// is what keeps that property valid for the entropy regex on non-ASCII
    /// text, where Unicode case folding can hide a keyword from the
    /// ASCII-only keyword bucket (see the scan gate).
    fn presence_scan(&self, text: &str) -> Vec<bool> {
        let n_ac = self.ac.patterns_len();
        let mut present = vec![false; n_ac];
        if n_ac > 0 {
            for m in self.ac.find_overlapping_iter(text.as_bytes()) {
                let id = m.pattern().as_usize();
                if id < present.len() {
                    present[id] = true;
                }
            }
        }
        present
    }

    #[must_use]
    fn scan_inner_prepared_with_presence(
        &self,
        text: &str,
        analyzer: Option<&ContextAnalyzer<'_>>,
        offsets_in_context: bool,
        presence: &[bool],
    ) -> ScanOutput {
        let mut findings: Vec<Finding> = Vec::new();
        let mut seen: HashSet<(String, usize, usize)> = HashSet::new();

        // Prefixed patterns: presence was proven by the merged pass above,
        // then the full-text find_iter runs per present prefix. Overlapping
        // match kind ensures every prefix at a position is marked (e.g. both
        // `sk-` and `sk-ant-`), fixing review P0-4a.
        for (ac_id, &is_present) in presence.iter().enumerate() {
            if !is_present {
                continue;
            }
            if let Some(group) = self.prefixed_entries.get(ac_id) {
                for (regex, entry) in group {
                    self.collect_rule_spans(
                        entry.rule_idx,
                        regex.find_iter(text).map(|m| (m.start(), m.end())),
                        text,
                        analyzer,
                        offsets_in_context,
                        &mut seen,
                        &mut findings,
                    );
                }
            }
        }

        // Unprefixed patterns: find_iter over the full text per pattern.
        for (regex, entry) in self.unprefixed_regexes.iter().zip(self.unprefixed_entries.iter()) {
            let rule = &self.rules[entry.rule_idx];
            if !rule.context_keywords.is_empty() {
                let Some(analyzer) = analyzer else {
                    continue;
                };
                if !analyzer.keyword_anywhere(&rule.context_keywords) {
                    continue;
                }
            }
            self.collect_rule_spans(
                entry.rule_idx,
                regex.find_iter(text).map(|m| (m.start(), m.end())),
                text,
                analyzer,
                offsets_in_context,
                &mut seen,
                &mut findings,
            );
        }

        // The default separated-PAN matcher is byte-linear and partitions a
        // separator-connected run into complete issuer-valid PANs. This keeps
        // two cards on one line distinct and rejects an indivisible overlong
        // run instead of accepting a valid-looking prefix.
        if !self.payment_card_entries.is_empty() {
            let ranges = payment_card_candidate_ranges(text);
            for entry in &self.payment_card_entries {
                self.collect_rule_spans(
                    entry.rule_idx,
                    ranges.iter().copied(),
                    text,
                    analyzer,
                    offsets_in_context,
                    &mut seen,
                    &mut findings,
                );
            }
        }

        // Multiline blocks: every match per multiline pattern.
        for multiline in &self.multiline_entries {
            if multiline.prefix_ac_id.is_some_and(|id| !presence[id]) {
                continue;
            }
            self.collect_rule_spans(
                multiline.pattern.rule_idx,
                multiline.regex.find_iter(text).map(|m| (m.start(), m.end())),
                text,
                analyzer,
                offsets_in_context,
                &mut seen,
                &mut findings,
            );
        }

        // Generic entropy-based detection (virtual rule, always active). For
        // leaf scans (context != text) the neighboring keyword lookup searches
        // the value itself, which is correct for per-leaf warn/redact. The
        // merged presence pass already proved whether any indicative keyword
        // occurs, so the detector skips its own standalone prefilter.
        //
        // The automaton is ASCII-case-insensitive while the entropy keyword
        // regex is Unicode-case-insensitive (`(?i)`, entropy.rs): regex simple
        // case folding matches folded keyword spellings such as U+017F (ſ→s)
        // and U+212A (K→k) that the ASCII-only keyword bucket can never mark
        // present, so on its own a presence miss does not prove absence for
        // non-ASCII text (review 9 attempt 5, P1). The fold-source bucket
        // closes that hole soundly: every keyword regex match contains either
        // a plain ASCII keyword byte sequence (keyword bucket) or at least one
        // fold-to-ASCII character (fold-source bucket), both marked in the
        // same single pass. A miss on both buckets therefore proves the regex
        // cannot match anywhere, so skipping the detector cannot change
        // findings — while ASCII payloads keep the exact attempt-5 gate
        // (fold-source patterns consist solely of non-ASCII bytes and can
        // never match ASCII text) and non-ASCII payloads without folded
        // keyword spellings skip exactly like before.
        if self.entropy_keyword_ids.iter().any(|&id| presence[id])
            || self.entropy_fold_source_ids.iter().any(|&id| presence[id])
        {
            for f in self.entropy_detector.detect_near_keywords_proven(
                text,
                self.entropy_threshold,
                self.payload_secret.as_deref(),
            ) {
                if seen.insert((f.flag.clone(), f.start, f.end)) {
                    findings.push(f);
                }
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

    fn make_finding(
        &self,
        rule: &Rule,
        text: &str,
        analyzer: Option<&ContextAnalyzer<'_>>,
        offsets_in_context: bool,
        start: usize,
        end: usize,
    ) -> Option<Finding> {
        let raw_value = &text[start..end];
        let trimmed = raw_value.trim();
        if !rule.context_keywords.is_empty() {
            // `None` is a normal fast-path result: the presence prefilter
            // proved that no contextual rule can pass this scan.
            let analyzer = analyzer?;
            if !check_constraints_with_analyzer(rule, trimmed, analyzer, offsets_in_context, start, end) {
                return None;
            }
        } else if !check_constraints_simple(rule, trimmed) {
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

    /// Return whether a context analyzer could be needed for this scan.
    ///
    /// This is deliberately a one-way proof: false means no keyword can
    /// match; true may be a substring false positive that the analyzer later
    /// rejects using Unicode word boundaries and same-line proximity.
    fn context_keywords_may_match(&self, context: &str) -> bool {
        if !self.has_context_keywords {
            return false;
        }
        if !context.is_ascii() {
            return true;
        }
        self.context_keyword_prefilter
            .as_ref()
            .is_some_and(|prefilter| prefilter.is_match(context.as_bytes()))
    }

    /// Hash a payload value, using HMAC-SHA256 when a secret is configured.
    ///
    /// R9-16 (F5.2): every PRODUCT wiring passes a per-installation key, so
    /// the keyed branch is the product default. The unkeyed branch remains a
    /// library affordance for unit-test determinism only; the daemon, CLI and
    /// all engine snapshots are always built keyed (see `cerberus/src/audit_key.rs`).
    ///
    /// The HMAC input is domain-separated (`AUDIT_EVENT_HASH_DOMAIN`) so the
    /// same value hashed for events can never be correlated with a hash
    /// produced under another domain (break-glass, allowlist).
    #[must_use]
    fn payload_hash(&self, value: &str) -> String {
        self.payload_secret.as_ref().map_or_else(
            || hash_value(value),
            |secret| domain_hash(secret, AUDIT_EVENT_HASH_DOMAIN, value.as_bytes()),
        )
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

/// Return complete separated-PAN ranges without regex backtracking/NFA work.
///
/// A maximal run is split only when every digit belongs to a 13–19 digit,
/// issuer-valid PAN and adjacent PANs have an actual separator. Consequently,
/// a single overlong digit run is rejected, while two PANs separated on one
/// line are emitted independently.
fn payment_card_candidate_ranges(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    if !bytes.iter().any(u8::is_ascii_digit) {
        return ranges;
    }
    let mut run = SepRun::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        let plus = bytes[cursor] == b'+';
        let first_digit = if plus { cursor + 1 } else { cursor };
        if first_digit >= bytes.len() || !bytes[first_digit].is_ascii_digit() {
            cursor += 1;
            continue;
        }
        if !plus && cursor > 0 && text[..cursor].chars().next_back().is_some_and(regex_word_char) {
            cursor += 1;
            continue;
        }

        // Single byte-linear pass. Only recognized separators are recorded;
        // adjacent digits are counted between them, so runs below the 13-digit
        // PAN minimum never allocate and no per-digit position vector is ever
        // materialized (repair attempt 6 perf).
        run.reset();
        let mut digits_seen = 1usize;
        let mut end = first_digit + 1;
        loop {
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
                digits_seen += 1;
            }
            let Some(after_separator) = recognize_separator(bytes, end) else {
                break;
            };
            if after_separator >= bytes.len() || !bytes[after_separator].is_ascii_digit() {
                break;
            }
            run.push(SepGap {
                digits_before: digits_seen,
                prev_end: end,
                next_at: after_separator,
            });
            end = after_separator + 1;
            digits_seen += 1;
        }
        run.digit_count = digits_seen;
        run.end = end;
        let followed_by_word = text[run.end..].chars().next().is_some_and(regex_word_char);
        if run.digit_count >= 13 && !followed_by_word {
            partition_payment_card_run(text, cursor, &run, &mut ranges);
        }

        cursor = run.end.max(cursor + 1);
    }

    ranges
}

/// The regex crate's `\w` word class (`Alphabetic` ∪ `M` ∪ `Nd` ∪ `Pc` ∪
/// `Join_Control`), which the shipped bounded pattern's `\b` anchors are
/// defined over. `char::is_alphanumeric()` additionally accepts the No/Nl
/// number categories (`½` U+00BD, `²` U+00B2, circled digits) that `\w`
/// rejects, and misses combining marks, non-underscore connector punctuation
/// and `Join_Control` (repair attempt 7, SEC-2). ASCII input — the hot path —
/// resolves without the probe; non-ASCII consults a build-once `\w` regex so
/// the matcher shares the regex crate's Unicode tables exactly.
fn regex_word_char(character: char) -> bool {
    static WORD_CHAR: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    if character.is_ascii() {
        return character.is_ascii_alphanumeric() || character == '_';
    }
    let mut encoded = [0u8; 4];
    WORD_CHAR
        .get_or_init(|| Regex::new(r"\w").expect("regex crate \\w compiles"))
        .is_match(character.encode_utf8(&mut encoded))
}

/// A recognized separator joined to the next digit, locating it by the number
/// of run digits before it and its surrounding byte offsets.
#[derive(Clone, Copy)]
struct SepGap {
    /// Count of run digits located before this separator (the 0-based token
    /// index of the digit that follows it).
    digits_before: usize,
    /// Byte offset just after the digit preceding the separator.
    prev_end: usize,
    /// Byte offset of the digit following the separator.
    next_at: usize,
}

/// One separator-connected digit run: the separator gaps only, the total
/// digit count and the offset just after the last digit. Kept inline up to
/// `INLINE_SEPS` separators; denser runs spill into one reusable `Vec` whose
/// capacity persists across the runs of the same scan.
const INLINE_SEPS: usize = 16;

struct SepRun {
    inline: [SepGap; INLINE_SEPS],
    spill: Vec<SepGap>,
    len: usize,
    digit_count: usize,
    end: usize,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct PanChainScore {
    covered_digits: usize,
    sixteen_digit_segments: usize,
    aligned_group_separators: usize,
    segments: usize,
}

#[derive(Clone, Copy)]
struct PanChainState {
    score: PanChainScore,
    chain_start: usize,
    segment_start: usize,
    previous_end: Option<usize>,
}

impl SepRun {
    const fn new() -> Self {
        let filler = SepGap {
            digits_before: 0,
            prev_end: 0,
            next_at: 0,
        };
        Self {
            inline: [filler; INLINE_SEPS],
            spill: Vec::new(),
            len: 0,
            digit_count: 0,
            end: 0,
        }
    }

    fn reset(&mut self) {
        self.len = 0;
        self.spill.clear();
    }

    fn push(&mut self, gap: SepGap) {
        if self.len < INLINE_SEPS {
            self.inline[self.len] = gap;
        } else {
            self.spill.push(gap);
        }
        self.len += 1;
    }

    fn get(&self, index: usize) -> SepGap {
        if index < INLINE_SEPS {
            self.inline[index]
        } else {
            self.spill[index - INLINE_SEPS]
        }
    }
}

/// Recognize the optional PAN separator starting at `at`: one `.`, `/` or
/// `-`, or one to three space/NBSP characters (the shipped pattern class).
/// Returns the offset just past the separator, or `None` when absent.
fn recognize_separator(bytes: &[u8], at: usize) -> Option<usize> {
    if at < bytes.len() && matches!(bytes[at], b'.' | b'/' | b'-') {
        return Some(at + 1);
    }
    let mut after = at;
    let mut count = 0usize;
    while count < 3 && after < bytes.len() {
        if bytes[after] == b' ' {
            after += 1;
            count += 1;
        } else if bytes[after..].starts_with(&[0xc2, 0xa0]) {
            after += 2;
            count += 1;
        } else {
            break;
        }
    }
    if count == 0 {
        return None;
    }
    Some(after)
}

fn pan_segment_start(run_start: usize, run: &SepRun, node: usize) -> (usize, usize) {
    if node == 0 {
        (0, run_start)
    } else {
        let gap = run.get(node - 1);
        (gap.digits_before, gap.next_at)
    }
}

fn pan_segment_end(run: &SepRun, node: usize) -> (usize, usize) {
    if node == run.len + 1 {
        (run.digit_count, run.end)
    } else {
        let gap = run.get(node - 1);
        (gap.digits_before, gap.prev_end)
    }
}

fn pan_recovery_predecessor(
    run: &SepRun,
    start_node: usize,
    start_digit: usize,
    best: &[Option<PanChainState>],
) -> Option<usize> {
    (1..start_node)
        .rev()
        .take_while(|&node| start_digit - pan_segment_end(run, node).0 <= 19)
        .filter(|&node| start_digit - pan_segment_end(run, node).0 >= 13 && best[node].is_some())
        .max_by_key(|&node| best[node].expect("recovery predecessor is reachable").score)
}

fn coherent_fresh_suffix(start_node: usize, end_node: usize) -> bool {
    (start_node..end_node.saturating_sub(1)).next().is_none()
}

/// Partition a digit run into complete issuer-valid PAN segments.
///
/// Valid chains are computed left-to-right over separator boundaries. A chain
/// may start after an invalid prefix and may stop before a complete (13+ digit)
/// invalid suffix, but it may not silently discard a short tail. This mirrors
/// regex search while keeping `valid PAN + four digits` fail-closed. Competing
/// chains prefer the most covered digits, then conventional 16-digit/aligned
/// grouping, which prevents accidental Luhn-valid cross-card cuts.
fn partition_payment_card_run(text: &str, run_start: usize, run: &SepRun, ranges: &mut Vec<(usize, usize)>) {
    if run.digit_count <= 19 {
        push_payment_card_segment(text, run_start, run.end, run.digit_count, ranges);
        return;
    }

    // Node 0 is the run start; the last node is the run end.
    let final_node = run.len + 1;
    let mut best: Vec<Option<PanChainState>> = vec![None; final_node + 1];
    let mut any_reachable = false;

    for end_node in 1..=final_node {
        let (end_digit, end_byte) = pan_segment_end(run, end_node);
        if end_node != final_node && end_digit > 19 && !any_reachable {
            continue;
        }

        for start_node in (0..end_node).rev() {
            let (start_digit, start_byte) = pan_segment_start(run_start, run, start_node);
            let digit_length = end_digit - start_digit;
            if digit_length > 19 {
                break;
            }
            let recovery_predecessor = if start_node == 0 || best[start_node].is_some() || !any_reachable {
                None
            } else {
                pan_recovery_predecessor(run, start_node, start_digit, &best)
            };
            let previous_end = best[start_node].map(|_| start_node).or(recovery_predecessor);
            let fresh_suffix =
                end_node == final_node && start_digit >= 13 && coherent_fresh_suffix(start_node, end_node);
            if start_node != 0 && previous_end.is_none() && !fresh_suffix {
                continue;
            }
            if digit_length >= 13 && payment_card_valid(&text[start_byte..end_byte]) {
                let mut aligned_group_separators = 0usize;
                for gap_index in start_node..end_node.saturating_sub(1) {
                    let relative_digit = run.get(gap_index).digits_before - start_digit;
                    aligned_group_separators += usize::from(relative_digit.is_multiple_of(4));
                }
                let base = previous_end.map_or_else(PanChainScore::default, |node| {
                    best[node].expect("PAN predecessor is reachable").score
                });
                let score = PanChainScore {
                    covered_digits: base.covered_digits + digit_length,
                    sixteen_digit_segments: base.sixteen_digit_segments + usize::from(digit_length == 16),
                    aligned_group_separators: base.aligned_group_separators + aligned_group_separators,
                    segments: base.segments + 1,
                };
                if best[end_node].is_none_or(|state| score > state.score) {
                    best[end_node] = Some(PanChainState {
                        score,
                        chain_start: previous_end.map_or(start_node, |node| {
                            best[node].expect("PAN predecessor is reachable").chain_start
                        }),
                        segment_start: start_node,
                        previous_end,
                    });
                    any_reachable = true;
                }
            }
        }
    }

    // Reject short unmatched tails; a card-sized invalid suffix is independent.
    let Some((mut end_node, _)) = (1..=final_node)
        .filter(|&node| {
            let (end_digit, _) = pan_segment_end(run, node);
            let trailing_digits = run.digit_count - end_digit;
            trailing_digits == 0 || trailing_digits >= 13
        })
        .filter_map(|node| {
            best[node]
                .filter(|state| {
                    if state.chain_start == 0 {
                        return true;
                    }
                    if node != final_node {
                        return false;
                    }
                    // Recover suffixes only after a complete card-sized prefix.
                    run.get(state.chain_start - 1).digits_before >= 13
                })
                .map(|state| (node, state.score))
        })
        .max_by_key(|(_, score)| *score)
    else {
        return;
    };

    let first_new_range = ranges.len();
    loop {
        let state = best[end_node].expect("selected PAN chain node is reachable");
        let start_node = state.segment_start;
        let (_, start) = pan_segment_start(run_start, run, start_node);
        let (_, end) = pan_segment_end(run, end_node);
        ranges.push((start, end));
        let Some(previous_end) = state.previous_end else {
            break;
        };
        end_node = previous_end;
    }
    ranges[first_new_range..].reverse();
}

fn push_payment_card_segment(
    text: &str,
    start: usize,
    end: usize,
    digit_length: usize,
    ranges: &mut Vec<(usize, usize)>,
) {
    if !(13..=19).contains(&digit_length) {
        return;
    }
    if payment_card_valid(&text[start..end]) {
        ranges.push((start, end));
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

/// Domain separation prefix for audit EVENT hashes (findings' `hashed_values`).
///
/// R9-16 (F5.2): the versioned domain string is prepended (NUL-delimited) to
/// every HMAC input, so hashes from different subsystems can never be
/// correlated or transplanted between domains even under the same
/// installation key. The `v1` suffix is the hash-format version.
pub const AUDIT_EVENT_HASH_DOMAIN: &str = "cerberus:audit-event:v1";

/// Domain separation prefix for break-glass reason hashes (`bypass-hash:`).
///
/// Deliberately distinct from [`AUDIT_EVENT_HASH_DOMAIN`] and from the
/// allowlist fingerprint domain ([`ALLOWLIST_HASH_DOMAIN`], F6.3).
pub const BREAK_GLASS_HASH_DOMAIN: &str = "cerberus:break-glass:v1";

/// Domain separation prefix for FALSE-POSITIVE ALLOWLIST fingerprints
/// (R9-7/F6.3).
///
/// Reserved by F5 (`cerberus:allowlist:v1`) and introduced here by F6.3:
/// allowlist entries persisted by the control plane are
/// `HMAC-SHA256(installation_key, "cerberus:allowlist:v1" || 0x00 || value)`,
/// NEVER the raw secret value. Deliberately distinct at byte 10 from
/// [`AUDIT_EVENT_HASH_DOMAIN`] and [`BREAK_GLASS_HASH_DOMAIN`], so allowlist
/// digests can never be transplanted into (or out of) the other domains.
pub const ALLOWLIST_HASH_DOMAIN: &str = "cerberus:allowlist:v1";

/// Domain-separated keyed hash for audit material (R9-16, F5.2).
///
/// Computes `HMAC-SHA256(key, domain || 0x00 || message)` and returns it with
/// the `hmac:` prefix. The NUL delimiter prevents concatenation ambiguities.
#[must_use]
pub fn domain_hash(key: &[u8], domain: &str, message: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + 1 + message.len());
    input.extend_from_slice(domain.as_bytes());
    input.push(0);
    input.extend_from_slice(message);
    hmac_sha256_hex(key, &input)
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

    fn make_context_rule(flag: &str, pattern: &str, context_keywords: &[&str]) -> Rule {
        let mut rule = make_rule(flag, &[pattern], Action::Warn);
        rule.context_keywords = context_keywords.iter().map(ToString::to_string).collect();
        rule
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
    fn context_prefilter_ascii_case_insensitive_preserves_prefixed_and_unprefixed_rules() {
        let rules = vec![
            make_context_rule("context.prefixed", r"TOKEN-[0-9]{7}", &["phone"]),
            make_context_rule("context.unprefixed", r"[0-9]{7}", &["phone"]),
        ];
        let engine = EngineBuilder::new(&rules).build().unwrap();

        assert!(engine.context_keywords_may_match("PHONE TOKEN-1234567"));
        let result = engine.scan("PHONE TOKEN-1234567");
        assert!(result.findings.iter().any(|finding| finding.flag == "context.prefixed"));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.flag == "context.unprefixed"));

        let separate_context = engine.scan_with_context("TOKEN-1234567", "call the PHONE desk");
        assert!(separate_context
            .findings
            .iter()
            .any(|finding| finding.flag == "context.prefixed"));
    }

    #[test]
    fn context_prefilter_absence_skips_contextual_rules_and_preserves_plain_rules() {
        let rules = vec![
            make_context_rule("context.prefixed", r"TOKEN-[0-9]{7}", &["phone"]),
            make_context_rule("context.unprefixed", r"[0-9]{7}", &["phone"]),
            make_rule("plain.prefixed", &[r"TOKEN-[0-9]{7}"], Action::Warn),
        ];
        let engine = EngineBuilder::new(&rules).build().unwrap();

        assert!(!engine.context_keywords_may_match("ordinary TOKEN-1234567 prose"));
        let result = engine.scan("ordinary TOKEN-1234567 prose");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].flag, "plain.prefixed");
    }

    #[test]
    fn context_prefilter_substring_hit_still_enforces_boundaries_and_lines() {
        let rules = vec![make_context_rule("context.boundary", r"TOKEN-[0-9]{7}", &["phone"])];
        let engine = EngineBuilder::new(&rules).build().unwrap();

        // Presence filtering intentionally admits substring false positives;
        // the analyzer remains authoritative for boundaries and proximity.
        assert!(engine.context_keywords_may_match("megaphone TOKEN-1234567"));
        assert!(engine.scan("megaphone TOKEN-1234567").findings.is_empty());
        assert!(engine.scan("phone\nTOKEN-1234567").findings.is_empty());
    }

    #[test]
    fn context_prefilter_unicode_fallback_preserves_casefold_and_boundaries() {
        let rules = vec![make_context_rule("context.unicode", r"TOKEN-[0-9]{7}", &["ÉMAIL"])];
        let engine = EngineBuilder::new(&rules).build().unwrap();

        assert!(engine.context_keywords_may_match("ÉMAIL TOKEN-1234567"));
        assert_eq!(engine.scan("ÉMAIL TOKEN-1234567").findings.len(), 1);
        assert!(engine.scan("xÉMAILy TOKEN-1234567").findings.is_empty());
    }

    // ─── Attempt 6, P1 regression: Unicode-folded entropy keyword presence ──
    //
    // Review 9 attempt 5 (evidence/review9/f13-attempt5-security.md, V1/V4):
    // the merged presence automaton is ASCII-case-insensitive while the
    // entropy keyword regex is Unicode-case-insensitive, so folded keyword
    // spellings (U+017F ſ→s, U+212A K→k) pass the regex but never mark
    // presence. Base `fccd9e4` ran the entropy regex unconditionally and
    // detected these payloads; the attempt-5 gate skipped the detector. The
    // derived fold-to-ASCII source bucket restores that behavior; these tests
    // FAIL on attempt-5 code.

    #[test]
    fn entropy_presence_gate_unicode_casefold_longs_s_keyword_detected() {
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let text = format!("\u{017f}ecret={token}");
        assert!(!text.is_ascii(), "test payload must exercise the non-ASCII fallback");
        let engine = EngineBuilder::new(&[]).build().unwrap();
        let result = engine.scan(&text);
        assert_eq!(result.findings.len(), 1, "folded ſecret=… must still be detected");
        assert_eq!(result.findings[0].flag, "entropy.high_entropy_secret");
        assert_eq!(&text[result.findings[0].start..result.findings[0].end], token);
    }

    #[test]
    fn entropy_presence_gate_unicode_casefold_kelvin_sign_keyword_detected() {
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let text = format!("\u{212a}ey={token}");
        assert!(!text.is_ascii(), "test payload must exercise the non-ASCII fallback");
        let engine = EngineBuilder::new(&[]).build().unwrap();
        let result = engine.scan(&text);
        assert_eq!(result.findings.len(), 1, "folded <U+212A>ey=… must still be detected");
        assert_eq!(result.findings[0].flag, "entropy.high_entropy_secret");
        assert_eq!(&text[result.findings[0].start..result.findings[0].end], token);
    }

    #[test]
    fn entropy_fold_source_bucket_matches_regex_folding_tables_exactly() {
        // The bucket must stay DERIVED from the regex crate's folding tables,
        // never hand-extended: under the locked regex 1.13.1 / regex-syntax
        // 0.8.11, `(?i)` simple case folding matches exactly two non-ASCII
        // characters against ASCII keyword letters — U+017F (ſ→s) and
        // U+212A (K→k). Presentation-form letters (fullwidth, circled,
        // modifier), accents and ß/İ are NOT matchable and must stay outside
        // the bucket. If a regex upgrade ever widens the folding tables, the
        // bucket re-derives automatically and this exact-set assertion flags
        // the change for re-review.
        let sources = crate::entropy::EntropyDetector::fold_to_ascii_source_patterns().unwrap();
        let decoded: Vec<String> = sources
            .iter()
            .map(|pattern| String::from_utf8_lossy(pattern).into_owned())
            .collect();
        assert_eq!(decoded, ["\u{017f}", "\u{212a}"]);

        // Behavioral boundary: none of these spellings is matchable by the
        // keyword regex under the locked crate versions, so the engine must
        // not report them (and a sound presence bucket must not claim them).
        let engine = EngineBuilder::new(&[]).build().unwrap();
        for spelling in ["\u{ff33}ecret", "\u{24e2}ey", "\u{02e2}ecret", "ßecret", "İey", "éey"] {
            let text = format!("{spelling}=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE");
            assert!(
                engine.scan(&text).findings.is_empty(),
                "{spelling} must not fold-match a keyword under the locked regex"
            );
        }
    }

    #[test]
    fn entropy_presence_gate_ascii_keyword_control_detected() {
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let text = format!("password={token}");
        assert!(text.is_ascii(), "control payload must stay on the automaton gate");
        let engine = EngineBuilder::new(&[]).build().unwrap();
        let result = engine.scan(&text);
        assert_eq!(result.findings.len(), 1, "ASCII keyword control must keep detecting");
        assert_eq!(result.findings[0].flag, "entropy.high_entropy_secret");
        assert_eq!(&text[result.findings[0].start..result.findings[0].end], token);
    }

    #[test]
    fn entropy_presence_gate_unicode_casefold_detected_on_separate_context_leaf() {
        // The same gate funnels the JSON leaf path (context != text), so a
        // folded keyword inside a leaf value must be detected there too
        // (security review vector V4) with an ASCII context that the
        // automaton can legitimately judge.
        let token = "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let leaf = format!("\u{017f}ecret={token}");
        let context = "ordinary ascii review context prose";
        let engine = EngineBuilder::new(&[]).build().unwrap();
        let result = engine.scan_with_context(&leaf, context);
        assert_eq!(result.findings.len(), 1, "leaf path must detect the folded keyword");
        assert_eq!(result.findings[0].flag, "entropy.high_entropy_secret");
        assert_eq!(&leaf[result.findings[0].start..result.findings[0].end], token);

        // Analyzer-prepared variant (the per-leaf redaction hot path).
        let analyzer = ContextAnalyzer::new(context);
        let prepared = engine.scan_with_context_analyzer(&leaf, &analyzer);
        assert_eq!(prepared.findings.len(), 1, "analyzer leaf path must detect it too");
        assert_eq!(&leaf[prepared.findings[0].start..prepared.findings[0].end], token);
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
    fn build_with_unknown_validator_fails_closed_visibly() {
        let rules = vec![make_rule_with_validators(
            "t.unknown",
            &[r"abc"],
            &["nonexistent_validator"],
            Action::Warn,
        )];
        let error = EngineBuilder::new(&rules).build().unwrap_err();
        assert!(error.contains("Unknown validator 'nonexistent_validator'"));
        assert!(error.contains("t.unknown"));
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
        let result = engine.scan("write to juan@example.com or to maria@example.com");
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
    fn compiled_multiline_and_entropy_state_is_reused_across_scans() {
        let rules = vec![make_rule(
            "pem",
            &[
                r"-----BEGIN RSA PRIVATE KEY-----\n(?:.*\n)*?-----END RSA PRIVATE KEY-----",
                r"-----BEGIN EC PRIVATE KEY-----\n(?:.*\n)*?-----END EC PRIVATE KEY-----",
            ],
            Action::Block,
        )];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        assert_eq!(engine.multiline_entries.len(), 2);
        assert!(
            engine
                .multiline_entries
                .iter()
                .all(|entry| entry.prefix_ac_id.is_some()),
            "literal-prefixed multiline regexes must reuse the shared AC presence filter"
        );
        assert!(
            engine.prefixed_entries.iter().all(Vec::is_empty),
            "multiline regexes must not also be compiled into the regular prefixed scan path"
        );
        assert_eq!(engine.entropy_detector.compiled_pattern_count(), 1);

        let text = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n\
                    password=J8sK2m9xR4pL7vN3qW5tY1bH6fC0dE";
        let expected = engine.scan_with_context(text, text);
        assert!(expected.findings.iter().any(|finding| finding.flag == "pem"));
        assert!(expected
            .findings
            .iter()
            .any(|finding| finding.flag == "entropy.high_entropy_secret"));

        for _ in 0..32 {
            assert_eq!(engine.scan(text), expected);
            assert_eq!(engine.scan_with_context(text, text), expected);
        }

        assert_eq!(engine.multiline_entries.len(), 2);
        assert_eq!(engine.entropy_detector.compiled_pattern_count(), 1);
    }

    #[test]
    fn no_findings_yields_allow() {
        let rules = vec![make_rule("r", &["never-matches"], Action::Block)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        assert_eq!(engine.scan("hello world without secrets").action_overall, Action::Allow);
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
        // LIBRARY affordance only: the engine permits an unkeyed builder so
        // unit harnesses get deterministic digests. Every PRODUCT wiring
        // (daemon, CLI, snapshots) always passes the installation key —
        // see `cerberus/src/audit_key.rs` and the daemon wiring test.
        let rules = vec![make_rule("t", &["secret"], Action::Warn)];
        let engine = EngineBuilder::new(&rules).build().unwrap();
        let out = engine.scan("the secret value here");
        assert!(out.findings[0].hashed_value.starts_with("sha256:"));
    }

    // ─── R9-16 (F5.2): keyed default semantics ─────────────────────────────

    #[test]
    fn keyed_hash_is_deterministic_for_the_same_key() {
        let rules = vec![make_rule("t", &["secret"], Action::Warn)];
        let engine = EngineBuilder::new(&rules)
            .with_payload_secret(b"installation-key".to_vec())
            .build()
            .unwrap();
        let a = engine.scan("the secret value here").findings[0].hashed_value.clone();
        let b = EngineBuilder::new(&rules)
            .with_payload_secret(b"installation-key".to_vec())
            .build()
            .unwrap()
            .scan("the secret value here")
            .findings[0]
            .hashed_value
            .clone();
        assert_eq!(a, b, "same key + same value → identical hash");
        assert!(a.starts_with("hmac:"), "keyed hash format: {a:?}");
    }

    #[test]
    fn keyed_hash_differs_across_installation_keys() {
        let rules = vec![make_rule("t", &["secret"], Action::Warn)];
        let value = "the secret value here";
        let a = EngineBuilder::new(&rules)
            .with_payload_secret(b"key-a".to_vec())
            .build()
            .unwrap()
            .scan(value)
            .findings[0]
            .hashed_value
            .clone();
        let b = EngineBuilder::new(&rules)
            .with_payload_secret(b"key-b".to_vec())
            .build()
            .unwrap()
            .scan(value)
            .findings[0]
            .hashed_value
            .clone();
        assert_ne!(a, b, "a different installation key must yield a different hash");
        // And the keyed digest must not equal the plain SHA-256 (the R9-16
        // offline-recovery vector).
        assert_ne!(a, hash_value(value));
    }

    #[test]
    fn domain_hash_separates_event_and_break_glass_domains() {
        let key = b"installation-key".to_vec();
        let message = b"same-value";
        let event = domain_hash(&key, AUDIT_EVENT_HASH_DOMAIN, message);
        let bypass = domain_hash(&key, BREAK_GLASS_HASH_DOMAIN, message);
        let raw_hmac = hmac_sha256_hex(&key, message);
        assert_ne!(event, bypass, "distinct domains must produce distinct digests");
        assert_ne!(event, raw_hmac, "domain prefixes must change the digest");
        assert!(event.starts_with("hmac:"));
        assert!(bypass.starts_with("hmac:"));
        // Determinism of the domain construction itself.
        assert_eq!(event, domain_hash(&key, AUDIT_EVENT_HASH_DOMAIN, message));
        // NUL delimiter prevents concatenation ambiguity: ("ab", "c") and
        // ("a", "bc") must differ.
        assert_ne!(
            domain_hash(&key, "ab", b"c"),
            domain_hash(&key, "a", b"bc"),
            "domain/message boundary must be unambiguous"
        );
    }

    #[test]
    fn entropy_and_pattern_hashes_agree_under_one_key() {
        // The SAME secret value found by a pattern rule and by the entropy
        // analyzer must produce the SAME domain-separated hash (one scheme
        // across the whole engine; F5.2 "normalización estable").
        let rules = vec![make_rule("t", &["password"], Action::Warn)];
        let engine = EngineBuilder::new(&rules)
            .with_payload_secret(b"installation-key".to_vec())
            .build()
            .unwrap();
        let text = "the password is hunter2hunter2";
        for finding in engine.scan(text).findings {
            assert!(
                finding.hashed_value.starts_with("hmac:"),
                "every finding hash is keyed, got {}",
                finding.hashed_value
            );
        }
    }

    /// The optimized single-pass matcher must agree with the original
    /// materializing implementation (repair attempt 6 refactor guard): same
    /// ranges, same order, on structured random input and PAN fragments.
    #[test]
    fn pan_candidate_ranges_match_reference_implementation_on_random_inputs() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        macro_rules! rnd {
            ($m:expr) => {{
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((seed >> 33) as usize) % ($m as usize)
            }};
        }
        let alphabet = ['0', '1', '4', '5', '.', '/', '-', ' ', '\u{a0}', '+', 'x', '\n'];
        for trial in 0..5000 {
            let len = 1 + rnd!(64);
            let input: String = (0..len).map(|_| alphabet[rnd!(alphabet.len())]).collect();
            assert_eq!(
                payment_card_candidate_ranges(&input),
                reference_payment_card_candidate_ranges(&input),
                "trial {trial} input {input:?}"
            );
        }
        let fragments = [
            "4000.0566.5566.5556",
            "4111111111111111",
            "5500 0000 0000 0004",
            " ",
            "\u{a0}",
            "/",
            "-",
            "..",
            "+",
            "x",
            "\n",
            "4",
            "12345678901234567890",
            "4000.0566",
            "\u{00bd}",
            "\u{0301}",
        ];
        for trial in 0..5000 {
            let parts = 1 + rnd!(6);
            let mut input = String::new();
            for _ in 0..parts {
                input.push_str(fragments[rnd!(fragments.len())]);
            }
            assert_eq!(
                payment_card_candidate_ranges(&input),
                reference_payment_card_candidate_ranges(&input),
                "trial {trial} input {input:?}"
            );
        }
    }

    fn card_matcher_engine() -> CompiledEngine {
        let rules = vec![make_rule_with_validators(
            "pii.credit_card",
            &[BOUNDED_PAYMENT_CARD_PATTERN],
            &["payment-card"],
            Action::Redact,
        )];
        EngineBuilder::new(&rules).build().unwrap()
    }

    fn card_spans(engine: &CompiledEngine, text: &str) -> Vec<(usize, usize)> {
        engine
            .scan(text)
            .findings
            .iter()
            .map(|finding| (finding.start, finding.end))
            .collect()
    }

    #[test]
    fn regex_word_char_matches_regex_w_class() {
        for word in ['a', 'Z', '7', '_', 'é', '密', '\u{0301}', '\u{200d}', '\u{0660}', 'Ⅻ'] {
            assert!(regex_word_char(word), "{word:?} must be a regex \\w char");
        }
        for non_word in [' ', '.', '-', '\u{a0}', '\u{00bd}', '\u{00b2}', '\u{2460}', '\u{2028}'] {
            assert!(!regex_word_char(non_word), "{non_word:?} must not be a regex \\w char");
        }
    }

    #[test]
    fn mixed_separator_styles_within_one_pan_are_detected() {
        let engine = card_matcher_engine();
        assert_eq!(card_spans(&engine, "pay 4111 1111-1111.1111"), vec![(4, 23)]);
        assert_eq!(card_spans(&engine, "pay 4000.0566-5566 5556"), vec![(4, 23)]);
        assert_eq!(card_spans(&engine, "pay 4111\u{a0} 1111 1111\u{a0}1111"), vec![(4, 26)]);
    }

    #[test]
    fn adjacent_same_separator_style_pans_are_detected_separately() {
        let engine = card_matcher_engine();
        let payload = "4000 0566 5566 5556 5555 5555 5555 4444";
        assert_eq!(card_spans(&engine, payload), vec![(0, 19), (20, 39)]);
    }

    #[test]
    fn kind_change_splits_only_between_complete_pans() {
        let engine = card_matcher_engine();
        assert_eq!(
            card_spans(&engine, "4111-1111-1111-1111 4000.0566.5566.5556"),
            vec![(0, 19), (20, 39)]
        );
        assert_eq!(
            card_spans(&engine, "4111 1111-1111.1111 4111111111111111"),
            vec![(0, 19), (20, 36)]
        );
        let valid_invalid_valid = "4000 0566 5566 5556 1234 5678 1234 5678 5500 0000 0000 0004";
        assert_eq!(
            card_spans(&engine, valid_invalid_valid),
            vec![(0, 19), (40, 59)],
            "a complete invalid block must not suppress valid PANs on either side"
        );
        assert!(
            card_spans(&engine, "1111111111111 4444 9000000000007").is_empty(),
            "fragments must not combine into a fresh cross-boundary PAN suffix"
        );
        assert!(
            card_spans(&engine, "1111111111111 4444 900000000007").is_empty(),
            "aligned fragments must not combine into a fresh PAN suffix"
        );
        assert!(
            engine.scan("4111 1111-1111.1111 1111").findings.is_empty(),
            "a 20-digit mixed-style run must stay fail-closed (overlong rejection)"
        );
        assert!(
            engine.scan("4111-1111-1111-1111.4111").findings.is_empty(),
            "complete PAN + short tail stays fail-closed (attempt-5 overlong rejection)"
        );
    }

    #[test]
    fn no_category_boundary_chars_match_regex_word_class() {
        let engine = card_matcher_engine();
        assert_eq!(card_spans(&engine, "4111111111111111\u{00bd}"), vec![(0, 16)]);
        assert_eq!(card_spans(&engine, "\u{00bd}4111111111111111"), vec![(2, 18)]);
        assert_eq!(card_spans(&engine, "4111111111111111\u{00b2}"), vec![(0, 16)]);
        for glued in [
            "4111111111111111\u{0301}",
            "4111111111111111\u{200d}",
            "\u{0301}4111111111111111",
        ] {
            assert!(
                engine.scan(glued).findings.is_empty(),
                "combining mark / ZWJ is \\w: the \\b anchor must fail like the regex path: {glued:?}"
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn reference_payment_card_candidate_ranges(text: &str) -> Vec<(usize, usize)> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum SeparatorKind {
            AsciiWhitespace,
            NbspWhitespace,
            MixedWhitespace,
            Dot,
            Slash,
            Hyphen,
        }

        let bytes = text.as_bytes();
        let mut ranges = Vec::new();
        let mut cursor = 0;

        while cursor < bytes.len() {
            let plus = bytes[cursor] == b'+';
            let first_digit = if plus { cursor + 1 } else { cursor };
            if first_digit >= bytes.len() || !bytes[first_digit].is_ascii_digit() {
                cursor += 1;
                continue;
            }
            if !plus && cursor > 0 && text[..cursor].chars().next_back().is_some_and(regex_word_char) {
                cursor += 1;
                continue;
            }

            let mut digit_starts = vec![first_digit];
            let mut digit_ends = vec![first_digit + 1];
            let mut gaps: Vec<Option<SeparatorKind>> = Vec::new();
            let mut end = first_digit + 1;
            loop {
                if end < bytes.len() && bytes[end].is_ascii_digit() {
                    gaps.push(None);
                    digit_starts.push(end);
                    end += 1;
                    digit_ends.push(end);
                    continue;
                }

                let separator_start = end;
                let mut after_separator = end;
                let separator_kind;
                if after_separator < bytes.len() && matches!(bytes[after_separator], b'.' | b'/' | b'-') {
                    separator_kind = match bytes[after_separator] {
                        b'.' => SeparatorKind::Dot,
                        b'/' => SeparatorKind::Slash,
                        b'-' => SeparatorKind::Hyphen,
                        _ => unreachable!(),
                    };
                    after_separator += 1;
                } else {
                    let mut count = 0;
                    let mut saw_ascii_space = false;
                    let mut saw_nbsp = false;
                    while count < 3 && after_separator < bytes.len() {
                        if bytes[after_separator] == b' ' {
                            after_separator += 1;
                            count += 1;
                            saw_ascii_space = true;
                        } else if bytes[after_separator..].starts_with(&[0xc2, 0xa0]) {
                            after_separator += 2;
                            count += 1;
                            saw_nbsp = true;
                        } else {
                            break;
                        }
                    }
                    if count == 0 {
                        after_separator = separator_start;
                    }
                    separator_kind = if saw_nbsp {
                        if saw_ascii_space {
                            SeparatorKind::MixedWhitespace
                        } else {
                            SeparatorKind::NbspWhitespace
                        }
                    } else {
                        SeparatorKind::AsciiWhitespace
                    };
                }
                if after_separator == separator_start
                    || after_separator >= bytes.len()
                    || !bytes[after_separator].is_ascii_digit()
                {
                    break;
                }
                gaps.push(Some(separator_kind));
                digit_starts.push(after_separator);
                end = after_separator + 1;
                digit_ends.push(end);
            }

            let digit_count = digit_starts.len();
            let followed_by_word = text[end..].chars().next().is_some_and(regex_word_char);
            if digit_count >= 13 && !followed_by_word {
                let run_start = cursor;
                if digit_count <= 19 {
                    reference_push_payment_card_segment(
                        text,
                        run_start,
                        0,
                        digit_count,
                        &digit_starts,
                        &digit_ends,
                        &mut ranges,
                    );
                } else {
                    #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
                    struct ReferenceScore {
                        covered_digits: usize,
                        sixteen_digit_segments: usize,
                        aligned_group_separators: usize,
                        segments: usize,
                    }
                    #[derive(Clone, Copy)]
                    struct ReferenceState {
                        score: ReferenceScore,
                        chain_start: usize,
                        segment_start: usize,
                        previous_end: Option<usize>,
                    }
                    let mut best: Vec<Option<ReferenceState>> = vec![None; digit_count + 1];
                    for end_digit in 1..=digit_count {
                        if end_digit != digit_count && gaps[end_digit - 1].is_none() {
                            continue;
                        }
                        for start_digit in (0..end_digit).rev() {
                            let digit_length = end_digit - start_digit;
                            if digit_length > 19 {
                                break;
                            }
                            if digit_length < 13 || (start_digit != 0 && gaps[start_digit - 1].is_none()) {
                                continue;
                            }
                            let recovery_predecessor = if start_digit == 0 || best[start_digit].is_some() {
                                None
                            } else {
                                (1..start_digit)
                                    .rev()
                                    .take_while(|&prior_end| start_digit - prior_end <= 19)
                                    .filter(|&prior_end| start_digit - prior_end >= 13 && best[prior_end].is_some())
                                    .max_by_key(|&prior_end| {
                                        best[prior_end]
                                            .expect("reference recovery predecessor is reachable")
                                            .score
                                    })
                            };
                            let previous_end = best[start_digit].map(|_| start_digit).or(recovery_predecessor);
                            let coherent_suffix =
                                (start_digit..end_digit.saturating_sub(1)).all(|gap_index| gaps[gap_index].is_none());
                            let fresh_suffix = end_digit == digit_count && start_digit >= 13 && coherent_suffix;
                            if start_digit != 0 && previous_end.is_none() && !fresh_suffix {
                                continue;
                            }
                            let start = if start_digit == 0 {
                                run_start
                            } else {
                                digit_starts[start_digit]
                            };
                            let end = digit_ends[end_digit - 1];
                            if payment_card_valid(&text[start..end]) {
                                let aligned_group_separators = (start_digit..end_digit.saturating_sub(1))
                                    .filter(|&gap_index| {
                                        gaps[gap_index].is_some() && (gap_index + 1 - start_digit).is_multiple_of(4)
                                    })
                                    .count();
                                let base = previous_end.map_or_else(ReferenceScore::default, |prior_end| {
                                    best[prior_end].expect("reference predecessor is reachable").score
                                });
                                let score = ReferenceScore {
                                    covered_digits: base.covered_digits + digit_length,
                                    sixteen_digit_segments: base.sixteen_digit_segments
                                        + usize::from(digit_length == 16),
                                    aligned_group_separators: base.aligned_group_separators + aligned_group_separators,
                                    segments: base.segments + 1,
                                };
                                if best[end_digit].is_none_or(|state| score > state.score) {
                                    best[end_digit] = Some(ReferenceState {
                                        score,
                                        chain_start: previous_end.map_or(start_digit, |prior_end| {
                                            best[prior_end].expect("reference predecessor is reachable").chain_start
                                        }),
                                        segment_start: start_digit,
                                        previous_end,
                                    });
                                }
                            }
                        }
                    }

                    let selected = (1..=digit_count)
                        .filter(|&end_digit| {
                            let trailing_digits = digit_count - end_digit;
                            trailing_digits == 0 || trailing_digits >= 13
                        })
                        .filter_map(|end_digit| {
                            best[end_digit]
                                .filter(|state| {
                                    state.chain_start == 0 || (end_digit == digit_count && state.chain_start >= 13)
                                })
                                .map(|state| (end_digit, state.score))
                        })
                        .max_by_key(|(_, score)| *score);

                    if let Some((mut end_digit, _)) = selected {
                        let first_new_range = ranges.len();
                        loop {
                            let state = best[end_digit].expect("selected reference PAN node is reachable");
                            let start_digit = state.segment_start;
                            reference_push_payment_card_segment(
                                text,
                                run_start,
                                start_digit,
                                end_digit,
                                &digit_starts,
                                &digit_ends,
                                &mut ranges,
                            );
                            let Some(previous_end) = state.previous_end else {
                                break;
                            };
                            end_digit = previous_end;
                        }
                        ranges[first_new_range..].reverse();
                    }
                }
            }

            cursor = end.max(cursor + 1);
        }

        ranges
    }

    fn reference_push_payment_card_segment(
        text: &str,
        run_start: usize,
        start_digit: usize,
        end_digit: usize,
        digit_starts: &[usize],
        digit_ends: &[usize],
        ranges: &mut Vec<(usize, usize)>,
    ) {
        if !(13..=19).contains(&(end_digit - start_digit)) {
            return;
        }
        let start = if start_digit == 0 {
            run_start
        } else {
            digit_starts[start_digit]
        };
        let end = digit_ends[end_digit - 1];
        if payment_card_valid(&text[start..end]) {
            ranges.push((start, end));
        }
    }
}
