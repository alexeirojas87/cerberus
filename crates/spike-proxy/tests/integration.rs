#![allow(missing_docs)]

use std::net::{Ipv4Addr, SocketAddr};

use spike_proxy::bench::run_bench;
use spike_proxy::proxy::{spawn_proxy, spawn_upstream};

fn local_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[tokio::test]
async fn proxy_forwards_request_and_upstream_responds() {
    let (upstream, _u) = spawn_upstream(local_addr(0)).await.unwrap();
    let (proxy, _p) = spawn_proxy(local_addr(0), upstream).await.unwrap();
    let client = reqwest::Client::new();
    let url = format!("http://{proxy}/v1/messages");
    let body = r#"{"prompt":"hello cerberus"}"#;
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["method"], "POST");
    assert_eq!(json["path"], "/v1/messages");
    assert_eq!(json["body_len"], body.len());
}

#[tokio::test]
async fn proxy_preserves_custom_header() {
    let (upstream, _u) = spawn_upstream(local_addr(0)).await.unwrap();
    let (proxy, _p) = spawn_proxy(local_addr(0), upstream).await.unwrap();
    let client = reqwest::Client::new();
    let url = format!("http://{proxy}/test/header");
    let resp = client
        .post(&url)
        .header("x-test-header", "cerberus-spike")
        .body("body")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["test_header"], "cerberus-spike");
}

#[tokio::test]
async fn bench_produces_valid_result() {
    let res = run_bench(1, 100).await.unwrap();
    assert_eq!(res.payload_kb, 1);
    assert_eq!(res.iterations, 100);
    assert!(res.direct.p50_ms >= 0.0);
    assert!(res.proxy.p99_ms >= 0.0);
    assert!(res.overhead_percentile_p99_ms >= 0.0);
}

#[test]
fn binary_bench_outputs_valid_json() {
    let bin = {
        let mut found = None;
        for var in ["CARGO_BIN_EXE_spike_proxy", "CARGO_BIN_EXE_spike-proxy"] {
            if let Some(v) = std::env::var_os(var) {
                found = Some(std::path::PathBuf::from(v));
                break;
            }
        }
        found.unwrap_or_else(|| {
            let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.pop();
            p.pop();
            p.push("target/debug/spike-proxy");
            p
        })
    };
    let out = std::process::Command::new(&bin)
        .args(["--bench", "--payload-kb", "1", "--iterations", "50"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("invalid JSON output: {stdout}"));
    assert_eq!(json["payload_kb"], 1);
    assert!(json["direct"]["p50_ms"].as_f64().is_some());
    assert!(json["direct"]["p99_ms"].as_f64().is_some());
    assert!(json["proxy"]["p50_ms"].as_f64().is_some());
    assert!(json["proxy"]["p99_ms"].as_f64().is_some());
    assert!(json["overhead"]["p50_ms"].as_f64().is_some());
    assert!(json["overhead"]["p99_ms"].as_f64().is_some());
    assert!(json["overhead_percentile_p99_ms"].as_f64().is_some());
}
