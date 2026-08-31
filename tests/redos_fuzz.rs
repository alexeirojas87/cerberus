//! ReDoS fuzzing — verifies that no pattern causes catastrophic backtracking.
//!
//! Fuzzing over the **real default pack** (15 rules, source
//! `cerberus_packs::default_pack::DEFAULT_PACK_JSON`) — not over an inline
//! copy. This covers acceptance criterion F9:
//! "redos-fuzz(all packs)".
//!
//! The Rust `regex` crate uses a linear-time engine (RE2-like), so ReDoS is
//! theoretically impossible. We verify that every pattern in the real pack
//! compiles and matches in predictable time against inputs designed to cause
//! catastrophic backtracking in vulnerable engines, including multiline
//! patterns (PEM / id_rsa / .env).

use std::time::{Duration, Instant};

use cerberus_engine::engine::EngineBuilder;
use cerberus_engine::loader::load_rules_from_str;
use cerberus_engine::rule::Rule;
use cerberus_packs::default_pack::DEFAULT_PACK_JSON;

/// Maximum time allowed per scan. Generous margin for loaded CI runners —
/// the ReDoS guard is that the scan stays linear, not that it hits a
/// specific millisecond budget.
const MAX_SCAN_TIME_MS: u64 = 250;

/// Load all rules from the real default pack (15 rules).
fn load_all_rules() -> Vec<Rule> {
    load_rules_from_str(DEFAULT_PACK_JSON).unwrap_or_else(|e| panic!("default pack must parse: {e:?}"))
}

/// Generate classic adversarial backtracking payload.
fn backtracking_payload(length: usize) -> String {
    "a".repeat(length)
}

/// Test that no pattern in the real pack causes a slow scan.
#[test]
fn redos_fuzz_short_payloads() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    let payloads = vec![
        backtracking_payload(100),
        backtracking_payload(1_000),
        backtracking_payload(10_000),
    ];

    for payload in &payloads {
        let start = Instant::now();
        let result = engine.scan(payload);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
            "scan took {}ms for payload len={}: {:?}",
            elapsed.as_millis(),
            payload.len(),
            result.findings,
        );
    }
}

/// Test each pattern in the real pack individually against adversarial input.
#[test]
fn redos_fuzz_each_pattern() {
    let rules = load_all_rules();
    for rule in &rules {
        for pattern in &rule.patterns {
            let re = regex::Regex::new(pattern)
                .unwrap_or_else(|_| panic!("pattern '{}' (flag {}) failed to compile", pattern, rule.flag));
            let adversarial = format!("{}{}", "a".repeat(5_000), "!");
            let start = Instant::now();
            let _ = re.find(&adversarial);
            let elapsed = start.elapsed();
            assert!(
                elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
                "pattern '{}' (flag {}) took {}ms on adversarial input",
                pattern,
                rule.flag,
                elapsed.as_millis(),
            );
        }
    }
}

/// Test that the engine does not hang on empty payloads.
#[test]
fn redos_fuzz_empty_input() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    let start = Instant::now();
    let result = engine.scan("");
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_millis(MAX_SCAN_TIME_MS));
    assert!(result.findings.is_empty());
}

/// Test payloads with special regex characters.
#[test]
fn redos_fuzz_special_chars() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    let special = vec![
        "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "\\\\\\\\",
        "[[[[[[",
        "((((((",
        "......",
        "*****?",
        "|||||",
    ];

    for payload in &special {
        let start = Instant::now();
        let _ = engine.scan(payload);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
            "scan took {}ms for special payload '{}'",
            elapsed.as_millis(),
            payload,
        );
    }
}

/// Adversarial multiline: a truncated/malformed PEM block that would tempt
/// the multiline pattern to consume the entire input. Must finish in linear time.
#[test]
fn redos_fuzz_malformed_pem_multiline() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");

    // BEGIN block without END — the multiline pattern attempts to match the
    // entire input; on not finding END, it must fail fast (not linear-explosive).
    let truncated_pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{}", "A".repeat(10_000));
    let start = Instant::now();
    let result = engine.scan(&truncated_pem);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "malformed PEM scan took {}ms",
        elapsed.as_millis(),
    );
    // Without END, it must not produce a spurious finding.
    assert!(
        result.findings.iter().all(|f| f.flag != "secret.pem_private_key"),
        "truncated PEM should not spuriously match pem_private_key: {:?}",
        result.findings
    );

    // Many nested BEGIN blocks (pathological case for multiline regex).
    let nested = format!(
        "{}{}",
        "-----BEGIN PRIVATE KEY-----\n".repeat(100),
        "garbage data\n".repeat(5_000)
    );
    let start = Instant::now();
    let _result = engine.scan(&nested);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "nested BEGIN scan took {}ms",
        elapsed.as_millis(),
    );
}

/// Adversarial .env: many long `KEY=value` lines — the multiline pattern
/// `(?m)^...=.{10,}` must not degrade with large input.
#[test]
fn redos_fuzz_env_block_large() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");

    let mut body = String::with_capacity(50_000);
    for i in 0..5_000 {
        body.push_str(&format!("OPENAI_API_KEY={}\n", "a".repeat(20)));
        let _ = i;
    }
    let start = Instant::now();
    let result = engine.scan(&body);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "large .env scan took {}ms",
        elapsed.as_millis(),
    );
    assert!(
        !result.findings.is_empty(),
        "large .env should trigger env_block finding"
    );
}

/// Adversarial: key with a valid prefix but an explosively long suffix to
/// test the bounded quantifier `{20,}` of the openai pattern.
#[test]
fn redos_fuzz_long_suffix_after_prefix() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");

    // "sk-" + 100k chars: the pattern `\\bsk-[A-Za-z0-9]{20,}\\b` must scan
    // in linear time. The `maxLength=128` constraint may discard the finding
    // (correct anti-FP); here we only verify latency, not the match.
    let payload = format!("openai api key sk-{}", "a".repeat(100_000));
    let start = Instant::now();
    let _result = engine.scan(&payload);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "long suffix scan took {}ms",
        elapsed.as_millis(),
    );

    // A key within bounds (maxLength 128) with a context keyword must
    // produce a finding — confirms that the setup is valid and the engine detects.
    let valid_payload = format!("openai api key sk-{}", "a".repeat(30));
    let result = engine.scan(&valid_payload);
    assert!(
        !result.findings.is_empty(),
        "valid-length openai key with context keyword should match"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_all_rules_returns_default_pack() {
        let rules = load_all_rules();
        assert!(!rules.is_empty(), "default pack should load at least one rule");
        // The default pack has 15 rules; we allow growth.
        assert!(
            rules.len() >= 15,
            "default pack should have >=15 rules, got {}",
            rules.len()
        );
    }
}

/// Repair attempt 5 (HIGH-1): every entropy keyword × multibyte filler lengths
/// that straddle the 200-byte near-keyword window edge must scan without a
/// panic and in linear time. The previous window slice panicked on
/// non-char-boundary byte indices.
#[test]
fn redos_fuzz_multibyte_entropy_window_straddle() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    let keywords = ["password", "key", "token", "secret", "auth", "hash", "salt", "private"];
    let fillers = ['é', '€', '密', '🎉'];
    for kw in keywords {
        for filler in fillers {
            // Sweep filler sizes so the window edge lands inside every
            // possible position of a multi-byte character.
            for rep in 55..=75 {
                let payload = format!("{kw}={}x", filler.to_string().repeat(rep));
                let start = Instant::now();
                let _ = engine.scan(&payload);
                assert!(
                    start.elapsed() < Duration::from_millis(MAX_SCAN_TIME_MS),
                    "multibyte straddle scan slow for kw={kw} filler={filler} rep={rep}"
                );
            }
        }
    }
}

/// Repair attempt 5 (perf blocker 2): keyword-dense phone-list payloads must
/// stay linear (previously ~40–130× over the p99 budget at 50–100 KB).
#[test]
fn redos_fuzz_keyword_dense_phone_list_linear() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    for size_kb in [50usize, 100, 200] {
        let mut payload = String::with_capacity(size_kb * 1024);
        while payload.len() < size_kb * 1024 {
            payload.push_str("phone 1234567\n");
        }
        let start = Instant::now();
        let result = engine.scan(&payload);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
            "{}KB keyword-dense phone list took {}ms (quadratic regression?)",
            size_kb,
            elapsed.as_millis(),
        );
        assert!(result.findings.iter().any(|f| f.flag == "pii.phone_number"));
    }
}

/// Repair attempt 5 (MED-2): generalized PAN separator classes must not widen
/// the regex into pathological matching.
#[test]
fn redos_fuzz_separated_pan_classes() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    for payload in [
        format!("card {}", "4.".repeat(50_000)),
        format!("card {}", "4/".repeat(50_000)),
        format!("card {}", "4\u{a0}".repeat(10_000)),
        format!("card {}", "4000.0566.5566.5556.".repeat(500)),
    ] {
        let start = Instant::now();
        let _ = engine.scan(&payload);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
            "separator-class fuzz payload took {}ms",
            elapsed.as_millis(),
        );
    }
}
