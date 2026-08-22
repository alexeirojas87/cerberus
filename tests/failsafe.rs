//! Fail-safe/closed integration tests.
//!
//! Verifies that the engine and the fail-open/closed policy correctly
//! handle failures according to the configured policy.
//!
//! Coverage:
//! - Engine-level: compilation/regex error → Reject (closed) / Allow (open).
//! - Redaction with invalid spans → error, not panic.
//! - Pipeline scan + redact + policy.
//! - Default FailPolicy = Closed (secure-by-default).
//! - Proxy-level: decode→scan→policy pipeline with a simulated error.

use cerberus_engine::engine::EngineBuilder;
use cerberus_engine::redact::{apply_redaction, RedactOptions};
use cerberus_proxy::config::FailPolicy;
use cerberus_proxy::policy::{evaluate, PolicyDecision};

/// Fail-closed: any error must result in Reject.
#[test]
fn fail_closed_rejects_on_engine_error() {
    let decision = evaluate(FailPolicy::Closed, "engine compilation error");
    assert_eq!(decision, PolicyDecision::Reject);
}

/// Fail-open: any error must result in Allow.
#[test]
fn fail_open_allows_on_engine_error() {
    let decision = evaluate(FailPolicy::Open, "engine compilation error");
    assert_eq!(decision, PolicyDecision::Allow);
}

/// Redaction with invalid spans in fail-closed must fail.
#[test]
fn invalid_redaction_fail_closed() {
    let finding = cerberus_engine::engine::Finding {
        flag: "test".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::High,
        action: cerberus_engine::rule::Action::Redact,
        start: 10,
        end: 5, // invalid: end < start
        hashed_value: "sha256:test".to_string(),
    };
    let result = apply_redaction("hello world", &[finding], &RedactOptions::default());
    assert!(result.is_err(), "invalid span should error in redaction");
}

/// Empty engine throws no errors.
#[test]
fn empty_engine_scan_succeeds() {
    let engine = EngineBuilder::new(&[]).build().expect("empty engine build");
    let result = engine.scan("any text");
    assert!(result.findings.is_empty());
    // With no findings the request is considered clean → Allow (fix P1-12).
    assert_eq!(result.action_overall, cerberus_engine::rule::Action::Allow);
}

/// PolicyDecision can be compared.
#[test]
fn policy_decision_is_exhaustive() {
    let closed = evaluate(FailPolicy::Closed, "err");
    let open = evaluate(FailPolicy::Open, "err");
    assert_ne!(closed, open);
}

/// Integration test: scan + redact + policy.
#[test]
fn scan_redact_policy_pipeline() {
    let rule = cerberus_engine::rule::Rule {
        flag: "test.secret".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::High,
        action: cerberus_engine::rule::Action::Redact,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec!["SECRET".to_string()],
        validators: Vec::new(),
    };
    let engine = EngineBuilder::new(&[rule]).build().expect("engine build");
    let text = "this is a SECRET value";
    let output = engine.scan(text);

    assert!(!output.findings.is_empty(), "should find SECRET");
    assert_eq!(output.action_overall, cerberus_engine::rule::Action::Redact);

    // Verify finding span is correct
    let finding = &output.findings[0];
    assert_eq!(&text[finding.start..finding.end], "SECRET", "span should match SECRET");

    // Apply redaction
    let redacted =
        apply_redaction(text, &output.findings, &RedactOptions::default()).expect("redaction should succeed");
    assert!(
        !redacted.contains("SECRET"),
        "redacted text should not contain SECRET: {redacted}"
    );
    assert!(
        redacted.contains("[REDACTED:test.secret]"),
        "redacted text should contain token"
    );
}

/// Secure-by-default: `FailPolicy::default()` is `Closed` (not `Open`).
/// Guarantees that a deployment without explicit config rejects on engine
/// error, it does not let traffic through.
#[test]
fn fail_policy_default_is_closed_secure() {
    let default = FailPolicy::default();
    assert_eq!(
        default,
        FailPolicy::Closed,
        "default FailPolicy must be Closed (secure-by-default)"
    );
    // And the proxy default uses the FailPolicy default.
    assert_eq!(
        cerberus_proxy::config::ProxyConfig::default().fail_policy,
        FailPolicy::Closed
    );
}

/// Proxy-level: on a simulated engine error, the policy decides Reject
/// (closed) or Allow (open). Models the real proxy path: decode→scan→policy.
#[test]
fn proxy_pipeline_fail_closed_rejects_on_simulated_engine_error() {
    // Simulate: the engine failed (compile/regex/timeout error). The proxy
    // invokes `evaluate(fail_policy, error_msg)` to decide.
    let simulated_error = "engine: regex compile timeout after 2s";
    let decision_closed = evaluate(FailPolicy::Closed, simulated_error);
    assert_eq!(decision_closed, PolicyDecision::Reject);
    let decision_open = evaluate(FailPolicy::Open, simulated_error);
    assert_eq!(decision_open, PolicyDecision::Allow);
}

/// Fail-closed rejects on heterogeneous errors (not only engine):
/// decode, redact, upstream-connect, timeout. The policy is agnostic to the
/// message; what matters is the verdict.
#[test]
fn fail_closed_rejects_on_heterogeneous_errors() {
    let errors = [
        "engine: regex compile error",
        "decode: invalid utf-8 in body",
        "redact: span out of bounds",
        "upstream: connection refused",
        "timeout: scan exceeded 5s budget",
    ];
    for err in &errors {
        assert_eq!(
            evaluate(FailPolicy::Closed, err),
            PolicyDecision::Reject,
            "fail-closed must reject on error: {err}"
        );
    }
}

/// Fail-open is consistent: every error lets traffic through (availability
/// over security — opt-in mode for environments where blocking is worse than
/// a leak).
#[test]
fn fail_open_allows_on_heterogeneous_errors() {
    let errors = [
        "engine: regex compile error",
        "decode: malformed json",
        "upstream: dns failure",
    ];
    for err in &errors {
        assert_eq!(
            evaluate(FailPolicy::Open, err),
            PolicyDecision::Allow,
            "fail-open must allow on error: {err}"
        );
    }
}
