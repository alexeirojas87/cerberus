//! Integration tests for the rule-loader: JSON/YAML loading, engine
//! compilation and end-to-end scanning against the bundled `test-rules.json`.
//! Also covers constraints integration in the engine pipeline.

use cerberus_engine::engine::EngineBuilder;
use cerberus_engine::loader::{load_rules_from_json, load_rules_from_str, load_rules_from_yaml};
use cerberus_engine::rule::{Action, Category, Rule, Severity};
use cerberus_engine::scan::{scan, ScanRequest};

fn make_rule(
    flag: &str,
    patterns: &[&str],
    min_length: Option<usize>,
    max_length: Option<usize>,
    allowed_examples: &[&str],
    context_keywords: &[&str],
    action: Action,
) -> Rule {
    Rule {
        flag: flag.to_string(),
        category: Category::Secrets,
        severity: Severity::High,
        action,
        hash_normalization: None,
        context_keywords: context_keywords.iter().map(std::string::ToString::to_string).collect(),
        min_length,
        max_length,
        allowed_examples: allowed_examples.iter().map(std::string::ToString::to_string).collect(),
        patterns: patterns.iter().map(std::string::ToString::to_string).collect(),
        validators: Vec::new(),
    }
}

const TEST_RULES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-rules.json");

fn load_test_rules() -> Vec<cerberus_engine::rule::Rule> {
    load_rules_from_json(TEST_RULES).expect("test-rules.json must load")
}

#[test]
fn test_rules_file_loads_with_expected_count() {
    let rules = load_test_rules();
    assert!(rules.len() >= 10, "expected >=10 rules, got {}", rules.len());
}

#[test]
fn rules_have_all_required_fields() {
    for rule in load_test_rules() {
        assert!(!rule.flag.is_empty(), "every rule needs a flag");
        assert!(
            !rule.patterns.is_empty(),
            "rule {} must have at least one pattern",
            rule.flag
        );
    }
}

#[test]
fn actions_are_honoured_per_rule() {
    let rules = load_test_rules();
    assert!(rules.iter().any(|r| r.action == Action::Block));
    assert!(rules.iter().any(|r| r.action == Action::Redact));
    assert!(rules.iter().any(|r| r.action == Action::Warn));
}

#[test]
fn categories_are_present() {
    let rules = load_test_rules();
    assert!(rules.iter().any(|r| r.category == Category::Secrets));
    assert!(rules.iter().any(|r| r.category == Category::Pii));
    assert!(rules.iter().any(|r| r.category == Category::InternalCode));
}

#[test]
fn yaml_load_matches_json_behavior() {
    let yaml = "- flag: secret.openai_api_key\n  category: secrets\n  severity: critical\n  action: block\n  patterns: ['\\bsk-[A-Za-z0-9]{20,}\\b']\n";
    let rules = load_rules_from_yaml_str(yaml).expect("yaml parse");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].flag, "secret.openai_api_key");
    assert_eq!(rules[0].action, Action::Block);
}

fn load_rules_from_yaml_str(yaml: &str) -> Result<Vec<cerberus_engine::rule::Rule>, String> {
    // Reuse the YAML parsing path via a temp file to exercise load_rules_from_yaml.
    let path = std::env::temp_dir().join("cerberus_loader_yaml_test.yaml");
    std::fs::write(&path, yaml).map_err(|e| e.to_string())?;
    let result = load_rules_from_yaml(&path).map_err(|e| e.to_string());
    std::fs::remove_file(&path).ok();
    result
}

#[test]
fn engine_compiles_from_loaded_rules() {
    let rules = load_test_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine compiles");
    assert_eq!(engine.num_rules(), rules.len());
}

#[test]
fn scan_finds_openai_key() {
    let rules = load_test_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine compiles");
    let req = ScanRequest::new("my openai api key is sk-abcDEFghijklmnopqrstuvwxyz123456 and nothing else")
        .with_metadata("tool", "claude-code");
    let result = scan(&engine, &req);
    let openai = result.findings.iter().find(|f| f.flag == "secret.openai_api_key");
    assert!(openai.is_some(), "should flag an OpenAI-style key");
    let f = openai.expect("present");
    assert_eq!(f.action, Action::Block);
    assert_ne!(f.hashed_value, "sk-abcDEFghijklmnopqrstuvwxyz123456");
    assert!(f.hashed_value.starts_with("sha256:"));
}

#[test]
fn scan_finds_email_as_pii() {
    let rules = load_test_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine compiles");
    let req = ScanRequest::new("contact me at jane.doe@example.org please");
    let result = scan(&engine, &req);
    let email = result.findings.iter().find(|f| f.flag == "pii.email");
    assert!(email.is_some(), "should flag an email");
    assert_eq!(email.expect("present").action, Action::Warn);
}

#[test]
fn allowed_examples_do_not_fire() {
    // The openai rule allows "sk-AllowedExampleABCDEFGHIJKLMNOPQRSTUVWXYZ"
    // which DOES match the pattern \bsk-[A-Za-z0-9]{20,}\b and exceeds
    // minLength 20. Constraints (allowedExamples) must discard it.
    let rules = load_test_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine compiles");
    let req = ScanRequest::new("my openai key is sk-AllowedExampleABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let result = scan(&engine, &req);
    let openai = result.findings.iter().find(|f| f.flag == "secret.openai_api_key");
    // Allowed example must not fire.
    assert!(openai.is_none());
}

#[test]
fn generic_scan_request_has_no_domain_fields() {
    // The request is text + metadata only; metadata carries domain labels.
    let rules = load_test_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine compiles");
    let req = ScanRequest::new("nothing sensitive")
        .with_metadata("tool", "codex")
        .with_metadata("provider", "anthropic");
    let result = scan(&engine, &req);
    assert!(result.findings.is_empty());
    assert_eq!(req.metadata.len(), 2);
}

#[test]
fn malformed_json_returns_clear_error() {
    let err = load_rules_from_str("{ not json").unwrap_err();
    assert!(err.to_string().contains("invalid rules JSON"));
}

// ---------------------------------------------------------------------------
// Adversarial: constraints integration in the engine pipeline
// ---------------------------------------------------------------------------

#[test]
fn no_constraints_always_passes_in_engine() {
    let rule = make_rule("test.none", &[r"anything"], None, None, &[], &[], Action::Warn);
    let engine = EngineBuilder::new(&[rule]).build().expect("engine compiles");
    let req = ScanRequest::new("this contains anything you want");
    let result = scan(&engine, &req);
    assert_eq!(result.findings.len(), 1, "no constraints → match must pass");
}

#[test]
fn combined_minlength_and_contextkeywords_in_engine() {
    let rule = make_rule(
        "test.combined",
        &[r"\btoken-[A-Za-z0-9]+\b"],
        Some(10),
        None,
        &[],
        &["secret"],
        Action::Block,
    );
    let engine = EngineBuilder::new(&[rule]).build().expect("engine compiles");

    let req = ScanRequest::new("my secret token-ABCDEFGHIJ");
    let result = scan(&engine, &req);
    assert_eq!(result.findings.len(), 1, "both conditions met → must find");

    let req = ScanRequest::new("my secret token-AB");
    let result = scan(&engine, &req);
    assert!(
        result.findings.is_empty(),
        "short value must be discarded even with keyword"
    );

    let req = ScanRequest::new("no keyword here token-ABCDEFGHIJ");
    let result = scan(&engine, &req);
    assert!(result.findings.is_empty(), "no keyword → must discard");
}

#[test]
fn empty_context_vs_keyword_context() {
    let rule = make_rule(
        "test.context",
        &[r"\bsk-[A-Za-z0-9]+\b"],
        None,
        None,
        &[],
        &["api"],
        Action::Warn,
    );
    let engine = EngineBuilder::new(&[rule]).build().expect("engine compiles");

    let req = ScanRequest::new("sk-ABCDEF");
    let result = scan(&engine, &req);
    assert!(result.findings.is_empty(), "empty context → must discard");

    let req = ScanRequest::new("my api key is sk-ABCDEF");
    let result = scan(&engine, &req);
    assert_eq!(result.findings.len(), 1, "context with keyword → must pass");
}

#[test]
fn allowed_examples_minlength_min_wins() {
    let rule = make_rule(
        "test.min_wins",
        &[r"\bshort\b"],
        Some(20),
        None,
        &["short"],
        &[],
        Action::Warn,
    );
    let engine = EngineBuilder::new(&[rule]).build().expect("engine compiles");
    let req = ScanRequest::new("short");
    let result = scan(&engine, &req);
    assert!(result.findings.is_empty(), "minLength must win over allowedExamples");
}
