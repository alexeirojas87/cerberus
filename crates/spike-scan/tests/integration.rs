#![allow(missing_docs)]

use std::path::PathBuf;
use std::process::Command;

fn find_binary() -> PathBuf {
    let candidates = ["CARGO_BIN_EXE_spike_scan", "CARGO_BIN_EXE_spike-scan"];
    for var in &candidates {
        if let Some(path) = std::env::var_os(var) {
            return PathBuf::from(path);
        }
    }
    PathBuf::from("target/debug/spike-scan")
}

fn run_binary(args: &[&str]) -> (serde_json::Value, String, String) {
    let bin = find_binary();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to run spike-scan binary");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("output should be valid JSON, got: {stdout}"));

    (parsed, stdout, stderr)
}

#[test]
fn patterns_generate_correct_count() {
    let (pats, _exs) = spike_scan::patterns::generate(50);
    assert_eq!(pats.len(), 50);
}

#[test]
fn patterns_all_non_empty() {
    let (pats, exs) = spike_scan::patterns::generate(100);
    assert!(pats.iter().all(|p| !p.is_empty()));
    assert!(exs.iter().all(|e| !e.is_empty()));
}

#[test]
fn binary_runs_with_minimal_flags() {
    let (parsed, _, stderr) = run_binary(&["--patterns", "10", "--payload-size", "1", "--iterations", "5"]);

    assert!(parsed["patterns"].as_i64() == Some(10), "stderr: {stderr}");
    assert_eq!(parsed["engine"].as_str(), Some("hybrid"));
    assert!(parsed["hybrid"]["scan_p50_ms"].as_f64().is_some());
    assert!(
        parsed["hybrid"]["matches_found"].as_i64().unwrap_or(0) > 0,
        "expected at least 1 match in payload with embedded patterns"
    );
}

#[test]
fn binary_handles_zero_patterns() {
    let (parsed, _, _) = run_binary(&["--patterns", "0", "--payload-size", "1", "--iterations", "5"]);

    assert_eq!(parsed["patterns"].as_i64(), Some(0));
    assert_eq!(parsed["engine"].as_str(), Some("hybrid"));
    assert_eq!(
        parsed["hybrid"]["matches_found"].as_i64(),
        Some(0),
        "0 patterns should yield 0 matches"
    );
    assert!(parsed["hybrid"]["scan_p50_ms"].as_f64().is_some());
}

#[test]
fn binary_handles_zero_payload() {
    let (parsed, _, _) = run_binary(&["--patterns", "10", "--payload-size", "0", "--iterations", "5"]);

    assert_eq!(parsed["engine"].as_str(), Some("hybrid"));
    assert_eq!(parsed["payload_size_kb"].as_i64(), Some(0));
    assert_eq!(
        parsed["hybrid"]["throughput_mbps"].as_f64(),
        Some(0.0),
        "0-byte payload should yield 0 throughput"
    );
    assert!(parsed["hybrid"]["matches_found"].as_i64().is_some());
}

#[test]
fn binary_uses_defaults_when_no_flags() {
    let (parsed, _, _) = run_binary(&[]);

    assert_eq!(parsed["patterns"].as_i64(), Some(300), "default patterns should be 300");
    assert!(
        parsed["payload_size_kb"].as_i64().unwrap_or(0) >= 99,
        "default payload should be ~100 KB, got {:?}",
        parsed["payload_size_kb"]
    );
    assert_eq!(
        parsed["iterations"].as_i64(),
        Some(1000),
        "default iterations should be 1000"
    );
    assert_eq!(
        parsed["engine"].as_str(),
        Some("hybrid"),
        "default engine should be hybrid"
    );
    assert!(parsed["hybrid"]["scan_p50_ms"].as_f64().is_some());
    assert!(parsed["hybrid"]["matches_found"].as_i64().unwrap_or(0) > 0);
}

#[test]
fn json_schema_complete() {
    let (parsed, _, _) = run_binary(&["--patterns", "10", "--payload-size", "1", "--iterations", "5"]);

    let required_top = ["patterns", "payload_size_kb", "iterations", "engine", "hybrid"];
    for key in &required_top {
        assert!(parsed.get(*key).is_some(), "missing top-level key: {key}");
    }

    let engine = &parsed["hybrid"];
    let required_engine = [
        "compile_ms",
        "scan_p50_ms",
        "scan_p99_ms",
        "throughput_mbps",
        "matches_found",
    ];
    for key in &required_engine {
        assert!(engine.get(*key).is_some(), "missing engine key: {key}");
    }

    assert!(parsed["hybrid"]["compile_ms"].as_f64().is_some());
    assert!(parsed["hybrid"]["scan_p50_ms"].as_f64().is_some());
    assert!(parsed["hybrid"]["scan_p99_ms"].as_f64().is_some());
    assert!(parsed["hybrid"]["throughput_mbps"].as_f64().is_some());
    assert!(parsed["hybrid"]["matches_found"].as_i64().is_some());
}

#[test]
fn binary_with_regex_engine() {
    let (parsed, _, _) = run_binary(&[
        "--engine",
        "regex",
        "--patterns",
        "5",
        "--payload-size",
        "1",
        "--iterations",
        "5",
    ]);

    assert_eq!(parsed["engine"].as_str(), Some("regex"));
    assert!(parsed["regex"]["scan_p50_ms"].as_f64().is_some());
    assert!(parsed["regex"]["matches_found"].as_i64().unwrap_or(0) > 0);
}
