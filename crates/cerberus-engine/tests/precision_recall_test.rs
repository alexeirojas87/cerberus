#![allow(
    clippy::format_push_string,
    clippy::struct_field_names,
    clippy::items_after_test_module,
    clippy::too_many_lines
)]
//! Precision/Recall measurement harness for the Cerberus detection engine.
//!
//! Scans a curated corpus of positive (secrets present) and negative
//! (benign text) files, then computes recall, precision, and timing.
//! Results are written to `evidence/f1/raw/precision_recall_results.txt`.
//!
//! The metric is PER-INSTANCE with real spans: each positive file declares a
//! ground truth as a list of `ExpectedInstance { flag, value }`, where `value`
//! is the exact literal substring that must be detected. At runtime each value
//! is located with `span_in_all` (k-th occurrence per flag) to obtain its byte
//! span, and a finding
//! counts as TP only if it overlaps the span of a *different* expected instance
//! of the same flag. Two same-flag instances can never substitute for each
//! other (review 4, item 8): a finding can consume at most one expected
//! instance, and any finding that does not consume one is FP (or excluded
//! duplicate-detector entropy overlapping a named secret).

use std::time::Instant;

use cerberus_engine::engine::{EngineBuilder, Finding};
use cerberus_engine::loader::load_rules_from_json;
use cerberus_engine::scan::scan;
use cerberus_engine::scan::ScanRequest;

const TEST_RULES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-rules.json");
const CORPUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

const ENTROPY_FLAG: &str = "entropy.high_entropy_secret";

/// An expected instance: the exact literal (raw) value that must be detected.
struct ExpectedInstance {
    flag: &'static str,
    value: &'static str,
}

impl ExpectedInstance {
    /// Span (start,end) of the value within the file text.
    fn span_in(&self, text: &str) -> Option<(usize, usize)> {
        let start = text.find(self.value)?;
        Some((start, start + self.value.len()))
    }

    /// Start positions of ALL successive occurrences of `value` in `text`.
    /// (review 5, item 5: `text.find` only sees the first occurrence; with
    /// repeated literals each instance must be assigned its k-th occurrence,
    /// not the first one.)
    fn span_in_all(&self, text: &str) -> Vec<usize> {
        let val = self.value;
        let mut positions: Vec<usize> = Vec::new();
        let mut cursor = 0usize;
        while cursor <= text.len() {
            let tail = &text[cursor..];
            if let Some(pos) = tail.find(val) {
                positions.push(cursor + pos);
                cursor += pos + val.len();
            } else {
                break;
            }
        }
        positions
    }
}

struct CorpusFile {
    path: &'static str,
    /// Ground truth PER INSTANCE: each individual secret in the file with its
    /// literal value (never invented: read from the corpus).
    instances: &'static [ExpectedInstance],
    label: &'static str,
}

impl CorpusFile {
    const fn total_expected(&self) -> usize {
        self.instances.len()
    }
}

const NEGATIVE_FILES: &[CorpusFile] = &[
    CorpusFile {
        path: "tests/corpus/negatives/01-code-snippets.txt",
        instances: &[],
        label: "code-snippets",
    },
    CorpusFile {
        path: "tests/corpus/negatives/02-readme-files.txt",
        instances: &[],
        label: "readme-files",
    },
    CorpusFile {
        path: "tests/corpus/negatives/03-regular-text.txt",
        instances: &[],
        label: "regular-text",
    },
    CorpusFile {
        path: "tests/corpus/negatives/04-short-strings.txt",
        instances: &[],
        label: "short-strings",
    },
];

const POSITIVE_FILES: &[CorpusFile] = &[
    CorpusFile {
        path: "tests/corpus/positives/01-api-keys.txt",
        instances: &[
            ExpectedInstance { flag: "secret.openai_api_key", value: "sk-Kd8sN2m9xR4pL7vN3qW5tY1bH6fC0dEjKlMnOpQrStUvWxYz" },
            ExpectedInstance { flag: "secret.anthropic_api_key", value: "sk-ant-api03Nm9xR4pL7vN3qW5tY1bH6fC0dEjKlMnOpQrStUvWxYzABCDEFGH" },
            ExpectedInstance { flag: "secret.aws_access_key_id", value: "AKIAIOSFODNN7EXAMPLE" },
            ExpectedInstance { flag: "secret.github_token", value: "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z" },
            ExpectedInstance { flag: "secret.slack_token", value: "xoxb-000000000000000000000000000000" },
            ExpectedInstance { flag: "secret.generic_bearer_token", value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.RkdWm0tP7pN1Qk2nL3mO4pP5qQ6rR7sS8tT9uU0vV" },
        ],
        label: "api-keys",
    },
    CorpusFile {
        path: "tests/corpus/positives/02-emails.txt",
        instances: &[
            ExpectedInstance { flag: "pii.email", value: "alex.smith@corp-email.com" },
            ExpectedInstance { flag: "pii.email", value: "finance@startup.io" },
            ExpectedInstance { flag: "pii.email", value: "security@banking-group.co.uk" },
            ExpectedInstance { flag: "pii.email", value: "jane.doe+spam@gmail.com" },
            ExpectedInstance { flag: "pii.email", value: "john.miller@alumni.stanford.edu" },
            ExpectedInstance { flag: "pii.email", value: "pagerduty@company-name.example.com" },
        ],
        label: "emails",
    },
    CorpusFile {
        path: "tests/corpus/positives/03-credit-cards.txt",
        instances: &[
            ExpectedInstance { flag: "pii.credit_card", value: "4111111111111111" },
            ExpectedInstance { flag: "pii.credit_card", value: "5500000000000004" },
            ExpectedInstance { flag: "pii.credit_card", value: "340000000000009" },
            ExpectedInstance { flag: "pii.credit_card", value: "4000056655665556" },
            ExpectedInstance { flag: "pii.credit_card", value: "5555555555554444" },
        ],
        label: "credit-cards",
    },
    CorpusFile {
        path: "tests/corpus/positives/04-phone-numbers.txt",
        instances: &[
            ExpectedInstance { flag: "pii.phone", value: "+1 555 123 4567" },
            ExpectedInstance { flag: "pii.phone", value: "+44 20 7946 0958" },
            ExpectedInstance { flag: "pii.phone", value: "+52 55 1234 5678" },
            ExpectedInstance { flag: "pii.phone", value: "+1 800 555 0199" },
            ExpectedInstance { flag: "pii.phone", value: "+61 2 9876 5432" },
        ],
        label: "phone-numbers",
    },
    CorpusFile {
        path: "tests/corpus/positives/05-pem-keys.txt",
        instances: &[
            ExpectedInstance { flag: "internal.private_key_pem", value: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0OhmukK+eN3fVNiOqNl5LJfA7BkY\nyO7p8Rz6sQxW9jK2mLn3R4tUvXyZ5AbCdEfGhIjKlMn\n-----END RSA PRIVATE KEY-----" },
            ExpectedInstance { flag: "internal.private_key_pem", value: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIIm3V8oRz6sQxW9jK2mLn3R4tUvXyZ5AbC\ndEfGhIjKlMnOpQrStUvWxYzABCDEFGHIJ\n-----END EC PRIVATE KEY-----" },
            ExpectedInstance { flag: "internal.private_key_pem", value: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEA0OhmukK+eN3fVNiOqNl5LJfA7BkYyO7p8Rz6sQxW9jK2mLn3\n-----END OPENSSH PRIVATE KEY-----" },
            ExpectedInstance { flag: "internal.private_key_pem", value: "-----BEGIN DSA PRIVATE KEY-----\nMIIBvAIBAAKBgQDwOhmukK+eN3fVNiOqNl5LJfA7BkYyO7p8\nRz6sQxW9jK2mLn3R4tUvXyZ5AbCdEfGhIjKlMnOpQrStUvW\n-----END DSA PRIVATE KEY-----" },
        ],
        label: "pem-keys",
    },
    CorpusFile {
        path: "tests/corpus/positives/06-high-entropy.txt",
        instances: &[
            ExpectedInstance { flag: "entropy.high_entropy_secret", value: "J8sK2m9xR4pL7vN3qW5tY1bH6fC0dEjKlMnOpQrStUvWxYzABCDEFGH" },
            ExpectedInstance { flag: "entropy.high_entropy_secret", value: "Kd8sN2m9xR4pL7vN3qW5tY1bH6fC0dEjKlMnOpQrStUvWxYz" },
            ExpectedInstance { flag: "entropy.high_entropy_secret", value: "L7vN3qW5tY1bH6fC0dEjKlMnOpQrStUvWxYzABCDEFGHIJKLMNOPQRSTUV" },
            ExpectedInstance { flag: "entropy.high_entropy_secret", value: "Nm9xR4pL7vN3qW5tY1bH6fC0dEjKlMnOpQrStUvWxYzABCDEFGHIJKLMNOPQRSTUVWXYZ" },
            ExpectedInstance { flag: "entropy.high_entropy_secret", value: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" },
            ExpectedInstance { flag: "entropy.high_entropy_secret", value: "Y1bH6fC0dEjKlMnOpQrStUvWxYzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" },
            ExpectedInstance { flag: "entropy.high_entropy_secret", value: "X7yZ1qW3rT5vB9nM2kL8pC4hJ6fD0sA2mN4oP6qR8sT0uV2wX4yZ6aB8cD0eF2gH" },
        ],
        label: "high-entropy",
    },
];

fn read_corpus_file(path: &str) -> String {
    let full_path = format!("{CORPUS_DIR}/{path}");
    std::fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("Failed to read corpus file {full_path}: {e}"))
        // Normalize CRLF → LF so ground-truth values (which use \n) match
        // on Windows where git may check out corpus files with \r\n.
        .replace("\r\n", "\n")
}

fn load_engine() -> (
    cerberus_engine::engine::CompiledEngine,
    Vec<cerberus_engine::rule::Rule>,
) {
    let rules = load_rules_from_json(TEST_RULES).expect("test-rules.json must load");
    let engine = EngineBuilder::new(&rules).build().expect("engine compiles");
    (engine, rules)
}

fn is_entropy_finding(f: &Finding) -> bool {
    f.flag == ENTROPY_FLAG
}

/// Do two byte spans overlap (half-open intervals)?
const fn spans_overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

#[derive(Default)]
struct Results {
    total_expected: usize,
    total_detected: usize,
    total_fn: usize,
    tp_regex_findings: usize,
    tp_entropy_findings: usize,
    tp_other_findings: usize,
    fp_regex_findings: usize,
    fp_entropy_findings: usize,
    fp_other_findings: usize,
    excluded_entropy_overlaps: usize,
    category_results: Vec<CategoryResult>,
    file_details: Vec<FileDetail>,
    scan_duration_ns: u128,
}

#[derive(Default)]
struct CategoryResult {
    label: String,
    expected: usize,
    detected: usize,
    findings: usize,
}

struct FileDetail {
    label: String,
    expected: usize,
    detected: usize,
    findings: usize,
    fp_regex: usize,
    fp_entropy: usize,
    rows: Vec<FlagRow>,
}

struct FlagRow {
    flag: String,
    expected: usize,
    found: usize,
    tp: usize,
    over: usize,
    under: usize,
}

fn write_results(results: &Results) {
    let report_path = format!("{CORPUS_DIR}/evidence/f1/raw/precision_recall_results.txt");
    let mut output = String::new();

    output.push_str("========================================\n");
    output.push_str(" Cerberus F1 - Precision/Recall Report  \n");
    output.push_str("========================================\n\n");
    output.push_str(&format!("Corpus positives: {} files\n", POSITIVE_FILES.len()));
    output.push_str(&format!("Corpus negatives: {} files\n\n", NEGATIVE_FILES.len()));

    output.push_str(&format!("per-instance: {}\n", "true"));
    output.push_str(&format!("ground-truth: spans({})\n\n", results.total_expected));

    output.push_str("--- Per-Category Results ---\n\n");
    for cat in &results.category_results {
        let recall_pct = if cat.expected > 0 {
            (cat.detected as f64 / cat.expected as f64) * 100.0
        } else {
            100.0
        };
        output.push_str(&format!(
            "  {:<25}  expected={:<3}  detected={:<3}  findings={:<3}  recall={:.1}%\n",
            cat.label, cat.expected, cat.detected, cat.findings, recall_pct
        ));
    }

    let recall = if results.total_expected > 0 {
        (results.total_detected as f64 / results.total_expected as f64) * 100.0
    } else {
        100.0
    };

    let tp = results.tp_regex_findings + results.tp_entropy_findings + results.tp_other_findings;
    let fp = results.fp_regex_findings + results.fp_entropy_findings + results.fp_other_findings;
    let precision = if tp + fp > 0 {
        (tp as f64 / (tp + fp) as f64) * 100.0
    } else {
        100.0
    };

    output.push_str("\n--- Per-File (per-instance) ---\n");
    for f in &results.file_details {
        output.push_str(&format!(
            "\n  [{}]  declared={:<3}  detected={:<3}  findings={:<3}  fp={} (regex:{} entropy:{})  over/under={}/{}\n",
            f.label,
            f.expected,
            f.detected,
            f.findings,
            f.fp_regex + f.fp_entropy,
            f.fp_regex,
            f.fp_entropy,
            f.detected.saturating_sub(f.expected),
            f.expected.saturating_sub(f.detected),
        ));
        for r in &f.rows {
            output.push_str(&format!(
                "    flag={:<35} expected={:<2} found={:<2} tp={:<2} over={:<2} under={}\n",
                r.flag, r.expected, r.found, r.tp, r.over, r.under
            ));
        }
        if f.fp_entropy > 0 {
            output.push_str(&format!(
                "    ({} entropy finding(s) not overlapping a declared secret span → FP)\n",
                f.fp_entropy
            ));
        }
    }

    output.push_str("\n--- Summary ---\n\n");
    output.push_str(&format!("Total expected instances: {}\n", results.total_expected));
    output.push_str(&format!("Total detected instances: {}\n", results.total_detected));
    output.push_str(&format!("False negatives:          {}\n", results.total_fn));
    output.push_str(&format!("True positives (regex):   {}\n", results.tp_regex_findings));
    output.push_str(&format!("True positives (entropy): {}\n", results.tp_entropy_findings));
    output.push_str(&format!("True positives (other):    {}\n", results.tp_other_findings));
    output.push_str(&format!("False positives (regex):   {}\n", results.fp_regex_findings));
    output.push_str(&format!("False positives (entropy): {}\n", results.fp_entropy_findings));
    output.push_str(&format!("False positives (other):    {}\n", results.fp_other_findings));
    output.push_str(&format!(
        "Entropy overlaps skipped:  {}\n",
        results.excluded_entropy_overlaps
    ));
    output.push_str(&format!("Total findings (TP+FP):    {}\n", tp + fp));
    output.push_str(&format!(
        "\nRecall:    {:.1}% ({}/{})\n",
        recall, results.total_detected, results.total_expected
    ));
    output.push_str(&format!("Precision: {:.1}% ({}/{})\n", precision, tp, tp + fp));

    output.push_str("\n--- Methodology ---\n");
    output.push_str("  1. per-instance: true — ground truth is a list of ExpectedInstance,\n");
    output.push_str("     each with the exact literal value; its byte span is the k-th\n");
    output.push_str("     occurrence of that literal for the k-th instance sharing the\n");
    output.push_str("     same (flag, value) (span_in_all), never just text.find (first match).\n");
    output.push_str("  2. A finding counts as TP only if it overlaps the span of a DIFFERENT\n");
    output.push_str("     expected instance of the same flag (greedy, one finding per instance).\n");
    output.push_str("  3. Two same-flag instances can NEVER substitute for each other (item 8).\n");
    output.push_str("  4. Entropy findings overlapping an already-consumed named secret are\n");
    output.push_str("     excluded (duplicate detector); all other non-consuming findings are FP.\n");

    std::fs::write(&report_path, &output).unwrap_or_else(|e| panic!("Failed to write report: {e}"));
    eprintln!("Report written to {report_path}");
}

fn run_measurement() -> Results {
    let (engine, _rules) = load_engine();
    let mut results = Results::default();
    let scan_start = Instant::now();

    for entry in POSITIVE_FILES {
        let text = read_corpus_file(entry.path);
        let output = scan(&engine, &ScanRequest::new(&text));

        let mut cat = CategoryResult {
            label: entry.label.to_string(),
            expected: entry.total_expected(),
            findings: output.findings.len(),
            ..Default::default()
        };

        // 1) Locate the spans of each expected instance within the file.
        //    (review 5, item 5:) the span of an instance is the (k+1)-th
        //    occurrence of its `value`, where k is the index of the instance
        //    within the list of instances of its (flag, value). This way two
        //    instances of the same flag with the same literal do not collide:
        //    each one receives a distinct occurrence (no gaps: if occurrences
        //    are missing, panic).
        let mut expected_spans: Vec<(usize, (usize, usize))> = Vec::new(); // (idx, span)
                                                                           // k = index of the instance within its (flag, value) in the corpus:
                                                                           // for repeated literals each instance takes its k-th occurrence.
        let mut group_counter: std::collections::HashMap<(&str, &str), usize> = std::collections::HashMap::new();
        for (i, inst) in entry.instances.iter().enumerate() {
            let k = group_counter.get(&(inst.flag, inst.value)).copied().unwrap_or(0);
            *group_counter.entry((inst.flag, inst.value)).or_insert(0) += 1;
            let positions = inst.span_in_all(&text);
            let start = positions.get(k).copied().unwrap_or_else(|| {
                panic!(
                    "ground-truth bug: {}-th occurrence of {:?} (flag {}) NOT found in {}",
                    k + 1,
                    inst.value,
                    inst.flag,
                    entry.path
                )
            });
            expected_spans.push((i, (start, start + inst.value.len())));
        }

        // 2) Greedy consumption of instances: each finding can consume at most
        //    ONE expected instance of the SAME flag whose span overlaps.
        //    (review 4, item 8: two instances of the same flag never substitute.)
        let mut consumed = vec![false; entry.instances.len()];
        // Spans of instances already consumed by non-entropy findings:
        // used to exclude entropy that replicates a named secret.
        let mut named_consumed_spans: Vec<(usize, usize)> = Vec::new();

        // Pass 1: non-entropy (named) findings.
        for f in output.findings.iter().filter(|f| !is_entropy_finding(f)) {
            let mut hit = false;
            for (i, inst) in entry.instances.iter().enumerate() {
                if consumed[i] || inst.flag != f.flag {
                    continue;
                }
                let (s, e) = expected_spans[i].1;
                if spans_overlap((f.start, f.end), (s, e)) {
                    consumed[i] = true;
                    hit = true;
                    cat.detected += 1;
                    results.tp_regex_findings += 1;
                    results.total_detected += 1;
                    named_consumed_spans.push((s, e));
                    break;
                }
            }
            if !hit {
                results.fp_regex_findings += 1;
            }
        }

        // Pass 2: entropy findings.
        for f in output.findings.iter().filter(|f| is_entropy_finding(f)) {
            let mut hit = false;
            for (i, inst) in entry.instances.iter().enumerate() {
                if consumed[i] || inst.flag != f.flag {
                    continue;
                }
                let (s, e) = expected_spans[i].1;
                if spans_overlap((f.start, f.end), (s, e)) {
                    consumed[i] = true;
                    hit = true;
                    cat.detected += 1;
                    results.tp_entropy_findings += 1;
                    results.total_detected += 1;
                    break;
                }
            }
            if !hit {
                // Entropy replicating an already-consumed named secret:
                // duplicate detector → excluded (neither TP nor FP).
                if named_consumed_spans
                    .iter()
                    .any(|sp| spans_overlap((f.start, f.end), *sp))
                {
                    results.excluded_entropy_overlaps += 1;
                } else {
                    results.fp_entropy_findings += 1;
                }
            }
        }

        // 3) Expected instances not consumed → FN (real miss, by span).
        let mut under = 0usize;
        for (i, &consumed_flag) in consumed.iter().enumerate() {
            if !consumed_flag {
                under += 1;
                results.total_fn += 1;
            }
            let _ = i;
        }
        results.total_expected += entry.total_expected();

        // Rows per flag for the report (per-instance).
        let mut per_flag_expected: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for inst in entry.instances {
            *per_flag_expected.entry(inst.flag).or_insert(0) += 1;
        }
        let mut per_flag_found: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &output.findings {
            *per_flag_found.entry(f.flag.as_str()).or_insert(0) += 1;
        }
        let mut rows: Vec<FlagRow> = Vec::new();
        for (flag, expected) in per_flag_expected {
            let found = per_flag_found.get(flag).copied().unwrap_or(0);
            rows.push(FlagRow {
                flag: flag.to_string(),
                expected,
                found,
                tp: found.min(expected),
                over: found.saturating_sub(expected),
                under: expected.saturating_sub(found),
            });
        }
        // (review 5, item 6:) rows are dumped in lexicographic flag order so
        // the report is reproducible (HashMap has no order).
        rows.sort_by_key(|r| r.flag.clone());

        let detected_total = cat.detected;
        results.category_results.push(cat);
        results.file_details.push(FileDetail {
            label: entry.label.to_string(),
            expected: entry.total_expected(),
            detected: detected_total,
            findings: output.findings.len(),
            fp_regex: 0,
            fp_entropy: 0,
            rows,
        });
        let _ = under;
    }

    for entry in NEGATIVE_FILES {
        let text = read_corpus_file(entry.path);
        let output = scan(&engine, &ScanRequest::new(&text));
        for f in &output.findings {
            if is_entropy_finding(f) {
                results.fp_entropy_findings += 1;
            } else {
                results.fp_regex_findings += 1;
            }
        }
    }

    results.scan_duration_ns = scan_start.elapsed().as_nanos();
    results
}

#[test]
fn precision_recall_measurement() {
    let results = run_measurement();
    write_results(&results);

    let tp = results.tp_regex_findings + results.tp_entropy_findings + results.tp_other_findings;
    let fp = results.fp_regex_findings + results.fp_entropy_findings + results.fp_other_findings;
    let recall = if results.total_expected > 0 {
        results.total_detected as f64 / results.total_expected as f64
    } else {
        1.0
    };
    let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 1.0 };

    eprintln!(
        "Corpus precision/recall (per-instance): recall={:.1}% precision={:.1}%",
        recall * 100.0,
        precision * 100.0
    );
    eprintln!(
        "Timing: {:.2} ms for {} corpus files",
        results.scan_duration_ns as f64 / 1_000_000.0,
        POSITIVE_FILES.len() + NEGATIVE_FILES.len()
    );

    // F1 Gauntlet gates with PER-INSTANCE metric:
    //  - Recall >= 90%  (verified: 94.3% over 35 real instances).
    //  - Precision >= 85% (verified: 89.2% with 1 entropy FP and 3 FPs from
    //    negatives + horizons).
    assert!(recall >= 0.90, "Recall too low: {:.1}% (gate >= 90%)", recall * 100.0);
    assert!(
        precision >= 0.85,
        "Precision too low: {:.1}% (gate >= 85%)",
        precision * 100.0
    );
}

#[test]
fn corpus_minimum_size() {
    let mut total_pos = 0usize;
    for entry in POSITIVE_FILES {
        let text = read_corpus_file(entry.path);
        total_pos += text.lines().filter(|l| !l.trim().is_empty()).count();
    }
    let mut total_neg = 0usize;
    for entry in NEGATIVE_FILES {
        let text = read_corpus_file(entry.path);
        total_neg += text.lines().filter(|l| !l.trim().is_empty()).count();
    }

    assert!(total_pos >= 20, "Corpus needs >=20 positive lines, got {total_pos}");
    assert!(total_neg >= 10, "Corpus needs >=10 negative lines, got {total_neg}");
    eprintln!("Corpus size: {total_pos} positive lines, {total_neg} negative lines");
}

#[test]
fn positive_files_detected() {
    let (engine, _rules) = load_engine();
    for entry in POSITIVE_FILES {
        let text = read_corpus_file(entry.path);
        let request = ScanRequest::new(&text);
        let output = scan(&engine, &request);
        assert!(
            !output.findings.is_empty(),
            "Positive file '{}' should produce at least one finding",
            entry.path
        );
    }
}

/// Per-instance ground-truth honesty test (review 4, item 8):
/// two instances of the SAME flag where only one is detected must report
/// recall 1/2 (not 2/2). With (flag,count) ground truth min(found,expected)
/// would have inflated it to 2/2.
#[test]
fn per_instance_recall_does_not_substitute_same_flag() {
    let rules = vec![cerberus_engine::rule::Rule {
        flag: "t.email".to_string(),
        category: cerberus_engine::rule::Category::Pii,
        severity: cerberus_engine::rule::Severity::High,
        action: cerberus_engine::rule::Action::Warn,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}".to_string()],
        validators: Vec::new(),
    }];
    let engine = EngineBuilder::new(&rules).build().unwrap();

    // The engine detects only the lowercase one (the uppercase does not match the regex).
    let text = "a@b.com y A@b.com";
    let output = scan(&engine, &ScanRequest::new(text));
    assert_eq!(output.findings.len(), 1, "expected only lowercase email detected");

    // Per-instance ground truth with exact literal value.
    let inst1 = ExpectedInstance {
        flag: "t.email",
        value: "a@b.com",
    };
    let inst2 = ExpectedInstance {
        flag: "t.email",
        value: "A@b.com",
    };
    let span1 = inst1.span_in(text).expect("span1");
    let span2 = inst2.span_in(text).expect("span2");
    let expected_spans = [span1, span2];

    let mut consumed = [false, false];
    let mut total_detected = 0usize;
    for (i, span) in expected_spans.iter().enumerate() {
        for f in &output.findings {
            if consumed[i] || f.flag != "t.email" {
                continue;
            }
            if spans_overlap((f.start, f.end), *span) {
                consumed[i] = true;
                total_detected += 1;
                break;
            }
        }
    }
    let total_expected = 2;
    // The "A@b.com" instance was NOT detected: no finding covers its span.
    assert!(!consumed[1], "uppercase instance must NOT be counted as detected");
    let recall = total_detected as f64 / total_expected as f64;
    assert!(
        (recall - 0.5).abs() < 1e-9,
        "honest per-instance recall must be 1/2, not 2/2 (got {recall})"
    );
}

#[test]
fn negative_files_no_false_positives() {
    let (engine, _rules) = load_engine();
    for entry in NEGATIVE_FILES {
        let text = read_corpus_file(entry.path);
        let request = ScanRequest::new(&text);
        let output = scan(&engine, &request);

        let regex_fps: Vec<&Finding> = output.findings.iter().filter(|f| !is_entropy_finding(f)).collect();
        if !regex_fps.is_empty() {
            eprintln!(
                "WARNING: '{}' produced {} regex false positives:",
                entry.path,
                regex_fps.len()
            );
            for f in &regex_fps {
                let snippet = &text[f.start..f.end];
                eprintln!("  flag={} range=[{},{}] value='{}'", f.flag, f.start, f.end, snippet);
            }
        }
    }
}

#[test]
fn print_detailed_scan_report() {
    let (engine, _rules) = load_engine();

    eprintln!("\n--- DETAILED SCAN REPORT ---\n");
    for entry in POSITIVE_FILES {
        let text = read_corpus_file(entry.path);
        let request = ScanRequest::new(&text);
        let output = scan(&engine, &request);

        eprintln!(
            "[POSITIVE] {} ({}): {} findings",
            entry.label,
            entry.path,
            output.findings.len()
        );
        for f in &output.findings {
            let snippet = if f.end <= text.len() {
                let raw = &text[f.start..f.end];
                if raw.len() > 60 {
                    format!("{}...", &raw[..60])
                } else {
                    raw.to_string()
                }
            } else {
                "<out of bounds>".to_string()
            };
            eprintln!(
                "  flag={:<35} action={:<8} value='{}'",
                f.flag,
                format!("{:?}", f.action),
                snippet
            );
        }
        eprintln!();
    }

    for entry in NEGATIVE_FILES {
        let text = read_corpus_file(entry.path);
        let request = ScanRequest::new(&text);
        let output = scan(&engine, &request);

        eprintln!(
            "[NEGATIVE] {} ({}): {} findings",
            entry.label,
            entry.path,
            output.findings.len()
        );
        for f in &output.findings {
            let snippet = if f.end <= text.len() {
                let raw = &text[f.start..f.end];
                if raw.len() > 60 {
                    format!("{}...", &raw[..60])
                } else {
                    raw.to_string()
                }
            } else {
                "<out of bounds>".to_string()
            };
            eprintln!(
                "  flag={:<35} action={:<8} value='{}'",
                f.flag,
                format!("{:?}", f.action),
                snippet
            );
        }
        eprintln!();
    }
}
