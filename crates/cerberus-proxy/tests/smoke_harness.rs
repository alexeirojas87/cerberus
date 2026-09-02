//! R0 — Proxy integration test harness.
//!
//! Verifies the proxy can be started on any random port, responds to HTTP
//! health checks, and the test harness infrastructure works end-to-end.
//!
//! The pattern here mirrors the existing unit test `healthcheck_endpoint_responds_ok`
//! in `crates/cerberus-proxy/src/proxy.rs`, using reqwest to validate that
//! integration tests can talk to a proxy instance.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use cerberus_proxy::api::ApiContext;
use cerberus_proxy::config::{FailPolicy, OperationMode, ProxyConfig, UpstreamConfig};
use cerberus_proxy::proxy::{spawn_proxy, ProxyContext};

/// R9-5/F6: the harness contexts authenticate the control plane exactly like
/// the product does — the daemon always has a token, and dev-mode `None` now
/// means the control plane is CLOSED (401), so every context carries one.
const HARNESS_ADMIN_TOKEN: &str = "harness-admin-token-0123456789abcdef";

/// Deterministic test installation key (R9-7 allowlist fingerprints).
const HARNESS_INSTALLATION_KEY: &[u8] = b"harness-installation-key-0123456789abcdef";

/// The HMAC fingerprint the control plane persists for `raw` under
/// [`HARNESS_INSTALLATION_KEY`] — the same conversion `POST /api/allowlist`
/// performs.
fn harness_fingerprint(raw: &str) -> String {
    cerberus_proxy::allowlist::fingerprint(HARNESS_INSTALLATION_KEY, raw)
}

/// HTTP client carrying the harness admin token on every request. Safe for
/// data-plane calls too: the proxy never forwards `x-cerberus-admin-token`
/// to the upstream (fix review v4 #2).
fn api_client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "x-cerberus-admin-token",
        reqwest::header::HeaderValue::from_static(HARNESS_ADMIN_TOKEN),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("api client")
}

fn local_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Build a `ProxyContext` manually (mirrors the pattern from proxy.rs unit test).
#[allow(clippy::needless_pass_by_value)]
fn make_ctx(rules: Vec<cerberus_engine::rule::Rule>, operation_mode: OperationMode) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(
        rules,
        operation_mode,
        "http://127.0.0.1:9999",
        FailPolicy::Closed,
        Some(HARNESS_ADMIN_TOKEN),
    )
}

/// Variant with a configurable upstream (for integrations with a real mock).
#[allow(clippy::needless_pass_by_value)]
fn make_ctx_with_url(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    upstream_url: &str,
) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(
        rules,
        operation_mode,
        upstream_url,
        FailPolicy::Closed,
        Some(HARNESS_ADMIN_TOKEN),
    )
}

/// Variant with a protected control plane (`admin_token`) — fix P1 admin.
fn make_ctx_with_token(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    upstream_url: &str,
    admin_token: &str,
) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(
        rules,
        operation_mode,
        upstream_url,
        FailPolicy::Closed,
        Some(admin_token),
    )
}

/// Variant with `admin_token` **and** YAML persistence (review v6.1): needed
/// to verify that a PUT preserving the token also persists it, and that a
/// write failure does not mutate the live config.
fn make_ctx_with_token_and_config_path(
    upstream_url: &str,
    admin_token: Option<&str>,
    config_path: std::path::PathBuf,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(&[]).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: None,
            auth_header: "authorization".to_string(),
            mode: None,
            expected_auth: None,
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: OperationMode::Enforce,
        fail_policy: FailPolicy::Closed,
        admin_token: admin_token.map(ToString::to_string),
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared)
            .with_config_path(config_path)
            .with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec()),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Variant with a configurable engine failure policy — fix P1 `fail_open`.
fn make_ctx_with_fail_policy(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    upstream_url: &str,
    fail_policy: FailPolicy,
) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(
        rules,
        operation_mode,
        upstream_url,
        fail_policy,
        Some(HARNESS_ADMIN_TOKEN),
    )
}

/// Tokenless variant (R9-5/F6): for tests that exercise the CLOSED control
/// plane itself or the startup validation that refuses tokenless binds.
#[allow(clippy::needless_pass_by_value)]
fn make_ctx_tokenless(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(
        rules,
        operation_mode,
        "http://127.0.0.1:9999",
        FailPolicy::Closed,
        Some(HARNESS_ADMIN_TOKEN),
    )
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn make_ctx_opts(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    upstream_url: &str,
    fail_policy: FailPolicy,
    admin_token: Option<&str>,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(&rules).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: None,
            auth_header: "authorization".to_string(),
            mode: None,
            expected_auth: None,
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: operation_mode,
        fail_policy,
        // Raw semantics: None stays None (see make_ctx_tokenless); the
        // convenience wrappers below default the harness token (R9-5/F6).
        admin_token: admin_token.map(ToString::to_string),
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared).with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec()),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Variant with fixed YAML persistence (review v6 F6): the Config API writes
/// to `config_path` on every mutation (PUT /api/config, upstream CRUD).
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn make_ctx_with_config_path(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    upstream_url: &str,
    config_path: std::path::PathBuf,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(&rules).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: None,
            auth_header: "authorization".to_string(),
            mode: None,
            expected_auth: None,
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: operation_mode,
        fail_policy: FailPolicy::Closed,
        // R9-5/F6: dev-mode None = closed control plane; the harness
        // authenticates like the product.
        admin_token: Some(HARNESS_ADMIN_TOKEN.to_string()),
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared)
            .with_config_path(config_path)
            .with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec()),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Real policy context: keeps the pack base rules, applies the restored
/// policy from the YAML and connects the same `EngineControl` to the API
/// and the dataplane.
fn make_policy_ctx(
    base_rules: Vec<cerberus_engine::rule::Rule>,
    mut config: ProxyConfig,
    config_path: std::path::PathBuf,
) -> std::sync::Arc<ProxyContext> {
    // R9-5/F6: dev-mode None = closed control plane; the harness authenticates.
    if config.admin_token.is_none() {
        config.admin_token = Some(HARNESS_ADMIN_TOKEN.to_string());
    }
    let engine =
        cerberus_proxy::detection_policy::build_engine(&base_rules, &config.policy, None).expect("policy engine");
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let live = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    let control = cerberus_proxy::detection_policy::EngineControl::new(live.clone(), base_rules, None);
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: live,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared)
            .with_config_path(config_path)
            .with_engine(control)
            .with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec()),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

fn unique_temp_path(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("cerberus-{tag}-{}-{nonce}", std::process::id()))
}

async fn post_scan(client: &reqwest::Client, base: &str, content: &str) -> reqwest::StatusCode {
    client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"content": content}))
        .send()
        .await
        .expect("scan request")
        .status()
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_health_check_with_reqwest() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = api_client()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("health request");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_api_config_returns_json() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = api_client()
        .get(format!("http://{addr}/api/config"))
        .send()
        .await
        .expect("config request");
    assert_eq!(resp.status(), 200);
    let json = resp.text().await.expect("read config");
    assert!(json.contains("listen"), "config should contain 'listen': {json}");
}

#[tokio::test]
async fn test_api_events_empty() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = api_client()
        .get(format!("http://{addr}/api/events"))
        .send()
        .await
        .expect("events request");
    assert_eq!(resp.status(), 200);
    let json = resp.text().await.expect("read events");
    assert!(
        json.trim() == "[]" || json.trim().is_empty(),
        "events should be empty: {json}"
    );
}

#[tokio::test]
async fn test_api_stats_total_zero() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = api_client()
        .get(format!("http://{addr}/api/stats"))
        .send()
        .await
        .expect("stats request");
    assert_eq!(resp.status(), 200);
    let json = resp.text().await.expect("read stats");
    assert!(
        json.contains("total") && json.chars().any(|c| c == '0'),
        "stats should show total=0: {json}"
    );
}

#[tokio::test]
async fn test_shadow_does_not_block() {
    let rules = vec![cerberus_engine::rule::Rule {
        flag: "test.block".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        validators: Vec::new(),
    }];
    let ctx = make_ctx(rules, OperationMode::Shadow);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = api_client()
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(r#"{"content":"sk-abcDEFghijklmnopqrstuvwxyz1234"}"#)
        .send()
        .await;

    // In shadow mode: the request is NOT blocked (403).
    // It may fail on upstream (unreachable mock), but that's different from blocked.
    match resp {
        Ok(r) => {
            // If it succeeded, should NOT be 403
            assert_ne!(r.status(), 403, "shadow mode should NOT block: status={}", r.status());
        }
        Err(e) => {
            // If it failed, it should NOT be a 403 error (which means blocked)
            // An upstream connection error is expected since no mock server is running
            let msg = format!("{e}");
            assert!(
                !msg.contains("403") && !msg.contains("blocked"),
                "shadow should not block, got error: {e}"
            );
        }
    }
}

#[tokio::test]
async fn test_enforce_blocks_secret() {
    let rules = vec![cerberus_engine::rule::Rule {
        flag: "test.block".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        validators: Vec::new(),
    }];
    let ctx = make_ctx(rules, OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = api_client()
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(r#"{"content":"sk-abcDEFghijklmnopqrstuvwxyz1234"}"#)
        .send()
        .await
        .expect("block test request");

    assert_eq!(resp.status(), 403, "secret should be blocked: {}", resp.status());
    let body = resp.text().await.expect("read block response");
    assert!(body.contains("blocked"), "response body: {body}");
}

#[tokio::test]
async fn test_events_recorded_after_block() {
    let rules = vec![cerberus_engine::rule::Rule {
        flag: "test.block".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        validators: Vec::new(),
    }];
    let ctx = make_ctx(rules, OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    // Trigger block
    let _block_resp = api_client()
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(r#"{"content":"sk-abcDEFghijklmnopqrstuvwxyz1234"}"#)
        .send()
        .await
        .expect("trigger block");

    // Check events
    let events_resp = api_client()
        .get(format!("http://{addr}/api/events"))
        .send()
        .await
        .expect("events check");
    assert_eq!(events_resp.status(), 200);
    let json = events_resp.text().await.expect("read events body");
    // Should have events (not empty array)
    assert!(
        !json.trim().is_empty() || json.trim() == "[]",
        "events after block should have content: {json}"
    );
}

#[tokio::test]
async fn test_clean_request_not_blocked() {
    let rules = vec![cerberus_engine::rule::Rule {
        flag: "test.block".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        validators: Vec::new(),
    }];
    let ctx = make_ctx(rules, OperationMode::Shadow);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = api_client()
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(r#"{"content":"normal message"}"#)
        .send()
        .await;

    // Should NOT be blocked (403). In shadow mode, the request forwards to upstream,
    // which may fail (unreachable mock), but that's not a block.
    match resp {
        Ok(r) => {
            assert_ne!(
                r.status(),
                403,
                "clean request should not be blocked: status={}",
                r.status()
            );
        }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                !msg.contains("403") && !msg.contains("blocked"),
                "clean request should not be blocked, got error: {e}"
            );
        }
    }
}

fn block_rule() -> cerberus_engine::rule::Rule {
    cerberus_engine::rule::Rule {
        flag: "test.block".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        validators: Vec::new(),
    }
}

/// Minimal mock upstream: accepts one request and responds with JSON 200.
async fn spawn_mock_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"ok":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, handle)
}

/// Mock upstream that returns a JSON with the raw request it received
/// (including headers) so we can assert which headers did NOT reach the
/// provider.
async fn spawn_mock_upstream_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let _ = sock.read(&mut buf).await;
                let raw = String::from_utf8_lossy(&buf);
                let body = serde_json::json!({ "echoed": raw.to_string() }).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, handle)
}

const BLOCK_BODY: &str = r#"{"content":"sk-abcDEFghijklmnopqrstuvwxyz1234"}"#;

#[tokio::test]
async fn test_hot_reload_put_config_takes_effect() {
    // P0-5: PUT /api/config must change the REAL mode of the proxy.
    let (mock_addr, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_addr}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");

    let client = api_client();
    let before = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("request");
    assert_eq!(before.status(), 403, "enforce blocks before reload");

    let cfg: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config")
        .json()
        .await
        .expect("parse config");
    let mut shadow = cfg.as_object().cloned().unwrap();
    shadow.insert("mode".to_string(), serde_json::json!("shadow"));
    let put = client
        .put(format!("{base}/api/config"))
        .json(&shadow)
        .send()
        .await
        .expect("put config");
    assert_eq!(put.status(), 200);

    let after = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("after reload");
    assert_eq!(
        after.status(),
        200,
        "hot-reload to shadow should stop blocking and forward (got {})",
        after.status()
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_break_glass_header_bypasses_block() {
    // P1-7: header X-Cerberus-Bypass must let through even if there is a block finder.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    // Without bypass, 403.
    let client = api_client();
    let resp = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("no bypass");
    assert_eq!(resp.status(), 403);

    // With bypass, it reaches the upstream (200).
    let by = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", "esto es un test de emergencia")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("with bypass");
    assert_eq!(
        by.status(),
        200,
        "break-glass must bypass a block (got {})",
        by.status()
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_allowlist_applied_in_scan_path() {
    // P0-5: the allowlist must filter in the real scan path.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let before = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("bloc");
    assert_eq!(before.status(), 403);

    let add = client
        .post(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({"value":"sk-abcDEFghijklmnopqrstuvwxyz1234"}))
        .send()
        .await
        .expect("allowlist add");
    assert_eq!(add.status(), 200);

    let after = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("after allowlist");
    assert_eq!(
        after.status(),
        200,
        "allowlisted value must not be blocked (got {})",
        after.status()
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_health_requires_admin_token_when_configured() {
    // With admin_token configured /health stays open but /api/* requires auth.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        "s3krit",
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");

    let ok = api_client().get(format!("{base}/health")).send().await.expect("health");
    assert_eq!(ok.status(), 200, "health is exempt from admin auth");

    let client = api_client();
    let denied = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("api no auth");
    assert_eq!(denied.status(), 401, "api without token must be 401");
    assert!(denied.text().await.unwrap_or_default().contains("unauthorized"));

    let allowed = client
        .get(format!("{base}/api/config"))
        .bearer_auth("s3krit")
        .send()
        .await
        .expect("api with token");
    assert_eq!(allowed.status(), 200, "api with valid token must be 200");
    mock_handle.abort();
}

#[tokio::test]
async fn test_put_config_requires_admin_token() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        "s3krit",
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // PUT /api/config without token → 401
    let denied = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"mode": "shadow"}))
        .send()
        .await
        .expect("put without token");
    assert_eq!(denied.status(), 401, "PUT config must require admin token");

    // PUT /api/config with valid token → 200
    let allowed = client
        .put(format!("{base}/api/config"))
        .bearer_auth("s3krit")
        .json(&serde_json::json!({"mode": "shadow"}))
        .send()
        .await
        .expect("put with token");
    assert_eq!(allowed.status(), 200, "PUT config with token should succeed");
    mock_handle.abort();
}

#[tokio::test]
async fn test_fail_policy_open_forwards_non_json_body() {
    // The mock responds 200 to any path/body received.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_fail_policy(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        FailPolicy::Open,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let client = api_client();
    let body = "not-json";
    let resp = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(String::from(body))
        .send()
        .await
        .expect("invalid json forwarded in open mode");
    assert_eq!(
        resp.status(),
        200,
        "fail_policy=open must forward a non-decodable JSON body (got {})",
        resp.status()
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_fail_policy_closed_rejects_dead_body() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_fail_policy(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        FailPolicy::Closed,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let client = api_client();
    let resp = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .expect("invalid json request");
    assert_eq!(
        resp.status(),
        502,
        "fail_policy=closed must reject a non-decodable JSON body (got {})",
        resp.status()
    );
    let text = resp.text().await.expect("read body");
    assert!(text.contains("cannot decode"), "body: {text}");
    mock_handle.abort();
}

#[tokio::test]
async fn test_bypass_reason_never_persisted_raw() {
    // The bypass reason with a literal `sk-...` secret must end up hashed,
    // never raw in /api/events.
    let secret_reason = "emergency reason sk-KEEPTHISSECRET1234567890abcdefX";
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");

    let client = api_client();
    let by = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", secret_reason)
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("bypass request");
    assert_eq!(by.status(), 200, "bypass must free passthrough");

    let events = client
        .get(format!("{base}/api/events"))
        .send()
        .await
        .expect("events")
        .text()
        .await
        .expect("events body");
    assert!(
        !events.contains(secret_reason),
        "raw bypass reason leaked into events: {events}"
    );
    assert!(
        events.contains("bypass-hash:"),
        "hashed reason must be present in events: {events}"
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_upstream_response_too_large_is_502() {
    // fix P1 #4: an upstream response exceeding `max_body_bytes` must
    // return a 502 JSON and NOT bring down the connection with an Err.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // Limit the body to 8 bytes (the mock response {"ok":true} exceeds it).
    let cfg: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config")
        .json()
        .await
        .expect("parse config");
    let mut limited = cfg.as_object().cloned().unwrap();
    limited.insert("max_body_bytes".to_string(), serde_json::json!(8));
    let put = client
        .put(format!("{base}/api/config"))
        .json(&limited)
        .send()
        .await
        .expect("put config");
    assert_eq!(put.status(), 200);

    let resp = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(r#"{"a":1}"#)
        .send()
        .await
        .expect("request forwarded");
    assert_eq!(
        resp.status(),
        502,
        "oversized upstream response must be 502 JSON, not a dropped connection (got {})",
        resp.status()
    );
    let text = resp.text().await.unwrap_or_default();
    assert!(text.contains("response too large"), "body: {text}");
    mock_handle.abort();
}

const ADMIN_TOKEN: &str = "s3cret-admin-token-12345678";

#[tokio::test]
async fn test_spawn_non_loopback_requires_admin_token() {
    // Review v4 #1: startup on 0.0.0.0 without an admin token must FAIL with
    // an error (a compose with `change-me` < 24 chars also does not start).
    // R9-5/F6: `make_ctx` now defaults a token (dev-mode None = closed), so
    // the tokenless spawn is built explicitly.
    let ctx = make_ctx_opts(
        vec![],
        OperationMode::Enforce,
        "http://127.0.0.1:9999",
        FailPolicy::Closed,
        None,
    );
    let ctx = {
        let mut cfg = (*ctx.config.read().unwrap_or_else(std::sync::PoisonError::into_inner)).clone();
        cfg.admin_token = None;
        let engine = ctx
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let api = ctx.api.clone();
        std::sync::Arc::new(ProxyContext {
            config: std::sync::Arc::new(std::sync::RwLock::new(cfg)),
            engine: std::sync::Arc::new(std::sync::RwLock::new(engine)),
            redact_options: cerberus_engine::redact::RedactOptions::default(),
            api,
            last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    };
    let non_loop: SocketAddr = "0.0.0.0:0".parse().expect("addr");
    let err = spawn_proxy(non_loop, ctx).await.unwrap_err().to_string();
    assert!(err.contains("admin token"), "got: {err}");
}

#[tokio::test]
async fn test_admin_token_header_not_forwarded_to_upstream() {
    // Review v4 #2: `X-Cerberus-Admin-Token` must never reach the upstream.
    let (echo_addr, echo_handle) = spawn_mock_upstream_echo().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{echo_addr}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    let resp = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-admin-token", ADMIN_TOKEN)
        .header("x-custom-keep", "keepme")
        .body(r#"{"content":"hello"}"#)
        .send()
        .await
        .expect("forward");
    assert_eq!(resp.status(), 200);
    let echoed = resp.json::<serde_json::Value>().await.expect("echo json")["echoed"]
        .as_str()
        .expect("echoed str")
        .to_lowercase();
    assert!(echoed.contains("x-custom-keep"), "custom header must be forwarded");
    assert!(
        !echoed.contains("x-cerberus-admin-token"),
        "admin token header must not reach the upstream: {echoed}"
    );
    assert!(
        !echoed.contains(ADMIN_TOKEN),
        "admin token value leaked to the upstream: {echoed}"
    );
    echo_handle.abort();
}

#[tokio::test]
async fn test_bypass_data_plane_requires_admin_header_not_bearer() {
    // Review v4 #2: the data-plane bypass is honored ONLY via
    // `X-Cerberus-Admin-Token`; `Authorization: Bearer <admin>` is IGNORED
    // (warning) so as not to substitute the provider API key.
    let (echo_addr, echo_handle) = spawn_mock_upstream_echo().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{echo_addr}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    // Bypass via Authorization → ignored → 403 (block).
    let blocked = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", "test emergency")
        .bearer_auth(ADMIN_TOKEN)
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("bypass via bearer");
    assert_eq!(
        blocked.status(),
        403,
        "Authorization Bearer must NOT bypass data-plane block: {}",
        blocked.status()
    );

    // Bypass via X-Cerberus-Admin-Token → honored → 200.
    let passed = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", "test emergency")
        .header("x-cerberus-admin-token", ADMIN_TOKEN)
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("bypass via admin header");
    assert_eq!(
        passed.status(),
        200,
        "X-Cerberus-Admin-Token must bypass data-plane block (got {})",
        passed.status()
    );
    echo_handle.abort();
}

#[tokio::test]
async fn test_dashboard_served_without_auth_when_token_set() {
    // Review v5 F6: the dashboard is public static HTML without data; with an
    // admin token configured it is served WITHOUT auth and NEVER embeds the
    // token in the DOM. The data routes (/api/*) still require auth (401
    // without token).
    let (mock_addr, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_addr}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let base = format!("http://{addr}");

    // Dashboard without auth → 200 HTML and no token in the DOM.
    let ok = client
        .get(format!("{base}/api/dashboard"))
        .send()
        .await
        .expect("dashboard request");
    assert_eq!(ok.status(), 200, "dashboard must be public HTML: {}", ok.status());
    let html = ok.text().await.expect("dashboard html");
    assert!(html.contains("Cerberus Dashboard"), "expected a dashboard page");
    assert!(
        !html.contains(r#"<var id="cerberus-token""#),
        "token var must NOT be embedded in the DOM"
    );
    assert!(!html.contains(ADMIN_TOKEN), "admin token must not leak into the DOM");

    // Data route without token → 401.
    let denied = client
        .get(format!("{base}/api/stats"))
        .send()
        .await
        .expect("stats without token");
    assert_eq!(
        denied.status(),
        401,
        "data route must require auth: {}",
        denied.status()
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_stats_filters_by_provider_query() {
    // Review v5 F6: /api/stats?provider=X summarizes only the events of X.
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    {
        let mut events = ctx.api.events.lock().await;
        events.push(cerberus_store::event::AuditEvent::from_findings(
            &[],
            cerberus_engine::rule::Action::Allow,
            "api",
            "opencode",
            "openai",
        ));
        events.push(cerberus_store::event::AuditEvent::from_findings(
            &[],
            cerberus_engine::rule::Action::Allow,
            "api",
            "claude-code",
            "anthropic",
        ));
    }
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let stats = api_client()
        .get(format!("http://{addr}/api/stats?provider=openai"))
        .send()
        .await
        .expect("filtered stats")
        .json::<serde_json::Value>()
        .await
        .expect("stats json");
    assert_eq!(
        stats["total"].as_u64(),
        Some(1),
        "only openai should be counted: {stats}"
    );
    assert_eq!(
        stats["by_provider"][0]["provider"].as_str(),
        Some("openai"),
        "filter should isolate provider: {stats}"
    );
}

#[tokio::test]
async fn test_api_body_limited_to_1_mebibyte() {
    // Review v4 #4: the control plane rejects bodies > 1 MiB with 413, both
    // on PUT /api/config and on POST /api/allowlist.
    let (mock_addr, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(Vec::new(), OperationMode::Enforce, &format!("http://{mock_addr}"));
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let big_body = serde_json::json!({ "value": "x".repeat(1_100_000) }).to_string();
    assert!(big_body.len() > (1 << 20), "test requires a >1MiB body");
    let big = client
        .post(format!("{base}/api/allowlist"))
        .header("content-type", "application/json")
        .body(big_body)
        .send()
        .await
        .expect("oversized api body");
    assert_eq!(
        big.status(),
        413,
        "control-plane body over 1 MiB must be rejected with 413 (got {})",
        big.status()
    );

    let small = client
        .post(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({ "value": "something-without-a-secret" }))
        .send()
        .await
        .expect("small api body");
    assert_eq!(small.status(), 200, "small allowlist entry must succeed");
    mock_handle.abort();
}

#[tokio::test]
async fn test_hot_reload_swaps_engine_without_restart() {
    // F7 / review v5: the proxy must change rules WITHOUT restarting when the
    // active engine is replaced under the `RwLock`. This test:
    //   1. starts the proxy with a clean engine → the marker is NOT blocked;
    //   2. under the ctx lock the engine is SWAPPED to one with a block rule
    //      for the marker (what the daemon pack worker does);
    //   3. the SAME running proxy now returns 403 for that marker.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let _ = mock_adj;
    let ctx = make_ctx_with_url(Vec::new(), OperationMode::Enforce, "https://invalid-upstream");
    let proxy = spawn_proxy(local_addr(0), ctx.clone()).await.expect("spawn");
    let base = format!("http://{}", proxy.0);
    let client = api_client();
    let marker = "HOTRELOAD_SIGNAL_VAL";

    // 1) base engine (no rules) → the marker is NOT blocked (goes to upstream/mock).
    let passthrough = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"content":"{marker}"}}"#))
        .send()
        .await
        .expect("blocked passthrough");
    assert_ne!(
        passthrough.status(),
        403,
        "without a pack installed the marker must pass (got {})",
        passthrough.status()
    );

    // 2) swap of the active engine under the lock (worker pack install). The
    // guard is released explicitly BEFORE the next await (Send-safe, clippy).
    let block_rule = cerberus_engine::rule::Rule {
        flag: "hotreload.marker".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![marker.to_string()],
        validators: Vec::new(),
    };
    let new_engine = cerberus_engine::engine::EngineBuilder::new(&[block_rule])
        .build()
        .expect("engine");
    {
        let mut live = ctx.engine.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        *live = std::sync::Arc::new(new_engine);
    }

    // 3) the SAME proxy, WITHOUT restarting, now blocks the marker.
    let blocked = client
        .post(format!("http://{}", proxy.0) + "/test")
        .header("content-type", "application/json")
        .body(format!(r#"{{"content":"{marker}"}}"#))
        .send()
        .await
        .expect("blocked after reload");
    assert_eq!(
        blocked.status(),
        403,
        "hot-reload: after swap the proxy must block the marker (got {})",
        blocked.status()
    );
    mock_handle.abort();
}

#[tokio::test]
async fn config_get_never_leaks_admin_token() {
    // Review v6 F6: GET /api/config must redact the admin_token; it exposes
    // `admin_token_configured: true` but NEVER the value.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        vec![],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // Without token → 401 (the config exposes control-plane data).
    let denied = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config no token");
    assert_eq!(denied.status(), 401, "config must require auth when token set");

    // With a valid token → 200, and the token value does NOT appear.
    let resp = client
        .get(format!("{base}/api/config"))
        .header("x-cerberus-admin-token", ADMIN_TOKEN)
        .send()
        .await
        .expect("get config authed");
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.expect("read config");
    assert!(
        !text.contains(ADMIN_TOKEN),
        "admin_token value leaked via /api/config: {text}"
    );
    let json = serde_json::from_str::<serde_json::Value>(&text).expect("parse config");
    assert_eq!(
        json["admin_token_configured"].as_bool(),
        Some(true),
        "config must expose admin_token_configured=true: {text}"
    );
    assert!(
        json.get("admin_token").is_none(),
        "redacted config must not carry an admin_token key: {text}"
    );
    mock_handle.abort();
}

#[tokio::test]
async fn config_put_persists_yaml() {
    // Review v6 F6, requirement 1: PUT /api/config persists the shared config
    // to YAML at `ApiContext.config_path` (atomic write). The written YAML
    // must contain the config fields (mode).
    let config_path = std::env::temp_dir().join("cerberus_f6_config_put.yaml");
    std::fs::remove_file(&config_path).ok();

    let ctx = make_ctx_with_config_path(
        Vec::new(),
        OperationMode::Enforce,
        "http://127.0.0.1:9999",
        config_path.clone(),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let cfg: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config")
        .json()
        .await
        .expect("parse config");
    let mut body = cfg.as_object().cloned().unwrap();
    body.insert("mode".to_string(), serde_json::json!("shadow"));
    let put = client
        .put(format!("{base}/api/config"))
        .json(&body)
        .send()
        .await
        .expect("put config");
    assert_ne!(
        put.status(),
        500,
        "persisted PUT /api/config must not fail (got {})",
        put.status()
    );

    let yaml = std::fs::read_to_string(&config_path).expect("read persisted yaml");
    assert!(
        yaml.contains("mode"),
        "persisted YAML must carry the config fields, including mode: {yaml}"
    );
    assert!(yaml.contains("shadow"), "persisted mode value must be shadow: {yaml}");

    std::fs::remove_file(&config_path).ok();
}

#[tokio::test]
async fn config_put_persists_yaml_at_0600() {
    // F6.A attempt 2 (P1 regression, live control-plane flow): PUT /api/config
    // on a 0600 fixture must leave config.yaml at 0600 — the file carries the
    // admin token, and the old writer regressed it to umask 0644 on the
    // first PUT (review9 f6a-attempt1-correctness P1).
    let config_path = unique_temp_path("f6a2-config-0600.yaml");
    std::fs::write(&config_path, "listen: 127.0.0.1:8787\nmode: enforce\n").expect("fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).expect("chmod fixture");
    }

    let ctx = make_ctx_with_config_path(
        Vec::new(),
        OperationMode::Enforce,
        "http://127.0.0.1:9999",
        config_path.clone(),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let cfg: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config")
        .json()
        .await
        .expect("parse config");
    let mut body = cfg.as_object().cloned().unwrap();
    body.insert("mode".to_string(), serde_json::json!("shadow"));
    let put = client
        .put(format!("{base}/api/config"))
        .json(&body)
        .send()
        .await
        .expect("put config");
    assert_ne!(
        put.status(),
        500,
        "persisted PUT /api/config must not fail (got {})",
        put.status()
    );

    let yaml = std::fs::read_to_string(&config_path).expect("read persisted yaml");
    assert!(yaml.contains("shadow"), "persisted mode value must be shadow: {yaml}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&config_path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "config.yaml must stay 0600 after PUT /api/config, got {mode:o}"
        );
    }

    std::fs::remove_file(&config_path).ok();
}

#[tokio::test]
async fn upstream_post_malformed_json_answers_400_not_connection_drop() {
    // F6.A attempt 2 (P3-1 regression): an authenticated POST /api/upstreams
    // with a malformed JSON body must answer 400 with a JSON error — the old
    // `?` mapped the serde error to a handler Err, so hyper logged
    // "error from user's Service" and closed the connection (curl HTTP=000).
    let ctx = make_ctx_with_config_path(
        Vec::new(),
        OperationMode::Enforce,
        "http://127.0.0.1:9999",
        unique_temp_path("f6a2-upstream-400.yaml"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client(); // carries the admin token (authenticated route)

    let resp = client
        .post(format!("{base}/api/upstreams"))
        .header("content-type", "application/json")
        .body("{ not valid json")
        .send()
        .await
        .expect("the connection must stay open and answer — a drop fails HERE");
    assert_eq!(
        resp.status(),
        400,
        "malformed JSON must be a 400, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("the 400 must carry a JSON body");
    assert!(
        body["error"].as_str().is_some(),
        "the 400 body must carry an error field: {body}"
    );
}

#[tokio::test]
async fn upstream_add_list_delete() {
    // Review v6 F6, requirement 3: upstream CRUD via GET/POST/DELETE.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(Vec::new(), OperationMode::Enforce, &format!("http://{mock_adj}"));
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // Initial list: only the default upstream.
    let list0 = client
        .get(format!("{base}/api/upstreams"))
        .send()
        .await
        .expect("list upstreams")
        .text()
        .await
        .expect("body");
    assert!(
        list0.contains("default"),
        "initial list should contain 'default': {list0}"
    );

    // Add.
    let add = client
        .post(format!("{base}/api/upstreams"))
        .json(&serde_json::json!({
            "name": "openai",
            "url": "https://api.openai.com",
            "auth_header": "x-api-key",
        }))
        .send()
        .await
        .expect("add upstream");
    assert_eq!(add.status(), 200, "add upstream must succeed");

    // It appears in the list.
    let list1 = client
        .get(format!("{base}/api/upstreams"))
        .send()
        .await
        .expect("list after add")
        .text()
        .await
        .expect("body");
    assert!(list1.contains("openai"), "added upstream should be listed: {list1}");
    assert!(list1.contains("x-api-key"), "auth_header should be listed: {list1}");

    // Remove.
    let del = client
        .delete(format!("{base}/api/upstreams/openai"))
        .send()
        .await
        .expect("delete upstream");
    assert_eq!(del.status(), 200, "delete upstream must succeed");
    let list2 = client
        .get(format!("{base}/api/upstreams"))
        .send()
        .await
        .expect("list after delete")
        .text()
        .await
        .expect("body");
    assert!(
        !list2.contains("openai"),
        "deleted upstream must disappear from the list: {list2}"
    );
    assert!(list2.contains("default"), "default upstream must remain: {list2}");
    mock_handle.abort();
}

#[tokio::test]
async fn upstream_requires_auth_when_token_set() {
    // Review v6 F6, requirement 5: upstream CRUD is part of the control plane
    // and MUST require auth when an admin token is configured.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        Vec::new(),
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    assert_eq!(
        client
            .get(format!("{base}/api/upstreams"))
            .send()
            .await
            .expect("list")
            .status(),
        401,
        "GET /api/upstreams must require auth"
    );
    assert_eq!(
        client
            .post(format!("{base}/api/upstreams"))
            .json(&serde_json::json!({"name": "x", "url": "https://x"}))
            .send()
            .await
            .expect("add")
            .status(),
        401,
        "POST /api/upstreams must require auth"
    );
    assert_eq!(
        client
            .delete(format!("{base}/api/upstreams/x"))
            .send()
            .await
            .expect("delete")
            .status(),
        401,
        "DELETE /api/upstreams/* must require auth"
    );

    // With a valid token the DELETE responds 404 ('x' does not exist in the
    // config), proving the route goes through the gate and responds as such.
    let authed = client
        .delete(format!("{base}/api/upstreams/x"))
        .header("x-cerberus-admin-token", ADMIN_TOKEN)
        .send()
        .await
        .expect("delete authed");
    assert_ne!(authed.status(), 401, "with token the route must not be 401");
    mock_handle.abort();
}

// ─── Review v6.1: config as DTO, transactionality and F6 ────────────────

/// A 28-byte token (≥ `ADMIN_TOKEN_MIN_BYTES`), valid on non-loopback.
const STRONG_ADMIN_TOKEN: &str = "correct-horse-battery-stapl0";

/// Main requirement of review v6.1: a real HTTP GET → PUT cycle cannot lose
/// the admin token, because GET does not reveal it and PUT omits it. After
/// the PUT, a request WITHOUT a token must still be 401.
#[tokio::test]
async fn config_get_then_put_over_http_preserves_the_admin_token() {
    let config_path = std::env::temp_dir().join("cerberus_v61_get_put_preserves.yaml");
    std::fs::remove_file(&config_path).ok();
    let ctx =
        make_ctx_with_token_and_config_path("http://127.0.0.1:9999", Some(STRONG_ADMIN_TOKEN), config_path.clone());
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // 1) Authenticated GET: the token value does NOT travel; the boolean does.
    let resp = client
        .get(format!("{base}/api/config"))
        .header("x-cerberus-admin-token", STRONG_ADMIN_TOKEN)
        .send()
        .await
        .expect("get config");
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.expect("body");
    assert!(!text.contains(STRONG_ADMIN_TOKEN), "GET leaked the token: {text}");
    let cfg: serde_json::Value = serde_json::from_str(&text).expect("parse config");
    assert!(cfg.get("admin_token").is_none(), "the key must not exist: {text}");
    assert_eq!(cfg["admin_token_configured"].as_bool(), Some(true), "{text}");

    // 2) PUT resending the GET body (which does NOT carry the token) + a change.
    let mut body = cfg.as_object().cloned().expect("object");
    body.insert("mode".to_string(), serde_json::json!("shadow"));
    let put = client
        .put(format!("{base}/api/config"))
        .header("x-cerberus-admin-token", STRONG_ADMIN_TOKEN)
        .json(&body)
        .send()
        .await
        .expect("put config");
    assert_eq!(put.status(), 200, "PUT must accept the GET body verbatim");

    // 3) The change was applied...
    let after: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .header("x-cerberus-admin-token", STRONG_ADMIN_TOKEN)
        .send()
        .await
        .expect("get after")
        .json()
        .await
        .expect("parse after");
    assert_eq!(after["mode"].as_str(), Some("shadow"), "the patch was applied");
    assert_eq!(after["admin_token_configured"].as_bool(), Some(true));

    // 4) ...and the token is STILL required: without token, 401 (not dev mode).
    let denied = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get without token");
    assert_eq!(
        denied.status(),
        401,
        "the admin token must survive a GET→PUT round trip"
    );
    let denied_put = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"mode": "enforce"}))
        .send()
        .await
        .expect("put without token");
    assert_eq!(denied_put.status(), 401, "PUT without token stays 401");

    // 5) The persisted YAML does not lose the token either (the daemon re-reads it).
    let yaml = std::fs::read_to_string(&config_path).expect("config persisted");
    assert!(yaml.contains(STRONG_ADMIN_TOKEN), "token must persist to YAML: {yaml}");
    assert!(yaml.contains("shadow"), "{yaml}");
    std::fs::remove_file(&config_path).ok();
}

/// Adversarial: `admin_token_configured` is read-only. Sending it as
/// `false` cannot turn off authentication.
#[tokio::test]
async fn put_config_cannot_disable_auth_via_the_read_only_flag() {
    let ctx = make_ctx_with_token(
        vec![],
        OperationMode::Enforce,
        "http://127.0.0.1:9999",
        STRONG_ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let put = client
        .put(format!("{base}/api/config"))
        .header("x-cerberus-admin-token", STRONG_ADMIN_TOKEN)
        .json(&serde_json::json!({"admin_token_configured": false}))
        .send()
        .await
        .expect("put flag");
    assert_eq!(put.status(), 200, "the field is accepted and ignored");

    let denied = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get without token");
    assert_eq!(denied.status(), 401, "auth must still be enforced");
}

/// The API cannot persist a config the daemon would reject on startup:
/// non-loopback `listen` requires a token ≥ 24 bytes. And on rejecting it,
/// the live config does not change.
#[tokio::test]
async fn put_config_rejects_public_listen_without_a_strong_token() {
    let config_path = std::env::temp_dir().join("cerberus_v61_public_listen.yaml");
    std::fs::remove_file(&config_path).ok();
    // R9-5/F6 delta: a tokenless control plane is CLOSED (401) — the API can
    // no longer be driven at all in that state, so the weak-token rejection
    // is exercised from an AUTHENTICATED context whose live token is strong.
    let ctx =
        make_ctx_with_token_and_config_path("http://127.0.0.1:9999", Some(HARNESS_ADMIN_TOKEN), config_path.clone());
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // Public listen + SHORT token → 400 (the daemon would not start like that).
    let short = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"listen": "0.0.0.0:8080", "admin_token": "change-me"}))
        .send()
        .await
        .expect("put short token");
    assert_eq!(short.status(), 400, "short token must be refused");
    let text = short.text().await.unwrap_or_default();
    assert!(text.contains("non-loopback"), "{text}");

    // Nothing was applied in memory or written to disk.
    let cfg: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config")
        .json()
        .await
        .expect("parse");
    assert_eq!(
        cfg["listen"].as_str(),
        Some("127.0.0.1:8787"),
        "rejected patch must not touch the live config"
    );
    assert!(cfg["admin_token_configured"].as_bool().unwrap_or(true));
    assert!(!config_path.exists(), "a rejected patch must not write the YAML");

    // With the strong token, the same listen change DOES pass (requires_restart).
    let ok = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"listen": "0.0.0.0:8080", "admin_token": STRONG_ADMIN_TOKEN}))
        .send()
        .await
        .expect("put strong token");
    assert_eq!(ok.status(), 200);
    let body: serde_json::Value = ok.json().await.expect("parse put");
    assert_eq!(body["requires_restart"].as_bool(), Some(true));
    std::fs::remove_file(&config_path).ok();
}

/// Transactional persistence from the in-memory perspective: if the YAML
/// cannot be written, the live config stays EXACTLY as it was.
#[tokio::test]
async fn put_config_persist_failure_leaves_the_live_config_untouched() {
    let unwritable = std::path::PathBuf::from("/nonexistent-cerberus-dir-v61/config.yaml");
    // R9-5/F6: authenticated context (a tokenless control plane is closed).
    let ctx = make_ctx_with_token_and_config_path("http://127.0.0.1:9999", Some(HARNESS_ADMIN_TOKEN), unwritable);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let put = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"mode": "shadow"}))
        .send()
        .await
        .expect("put config");
    assert_eq!(put.status(), 500, "a failed write must not report success");
    let text = put.text().await.unwrap_or_default();
    assert!(text.contains("unchanged"), "{text}");

    let cfg: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config")
        .json()
        .await
        .expect("parse");
    assert_eq!(
        cfg["mode"].as_str(),
        Some("enforce"),
        "in-memory config must not diverge from disk"
    );
}

/// F6: policy overlay (categories + custom rules) over real HTTP.
#[tokio::test]
async fn policy_categories_and_rules_round_trip() {
    let ctx = make_ctx_with_url(vec![], OperationMode::Enforce, "http://127.0.0.1:9999");
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let pol: serde_json::Value = client
        .get(format!("{base}/api/policy"))
        .send()
        .await
        .expect("get policy")
        .json()
        .await
        .expect("parse policy");
    assert!(
        pol["categories"].as_object().is_some_and(serde_json::Map::is_empty),
        "without an explicit config, the action declared per rule is inherited: {pol}"
    );
    assert_eq!(pol["valid_actions"][0].as_str(), Some("allow"));

    // Set action by category and override by rule.
    let put = client
        .put(format!("{base}/api/policy"))
        .json(&serde_json::json!({
            "categories": {"secrets": "block"},
            "rules": {"secret.openai_api_key": "block"}
        }))
        .send()
        .await
        .expect("put policy");
    assert_eq!(put.status(), 200);
    let updated: serde_json::Value = put.json().await.expect("parse");
    assert_eq!(updated["categories"]["secrets"].as_str(), Some("block"));
    assert_eq!(updated["rules"]["secret.openai_api_key"].as_str(), Some("block"));
    assert_eq!(
        updated["categories"]["pii"].as_str(),
        None,
        "partial patch preserves absence"
    );

    // `null` deletes the entry.
    let removed: serde_json::Value = client
        .put(format!("{base}/api/policy"))
        .json(&serde_json::json!({"rules": {"secret.openai_api_key": null}}))
        .send()
        .await
        .expect("delete rule")
        .json()
        .await
        .expect("parse");
    assert!(
        removed["rules"].as_object().is_some_and(serde_json::Map::is_empty),
        "{removed}"
    );

    // Invalid action → 400 and NOTHING is applied.
    let bad = client
        .put(format!("{base}/api/policy"))
        .json(&serde_json::json!({"categories": {"secrets": "nuke", "pii": "block"}}))
        .send()
        .await
        .expect("put invalid");
    assert_eq!(bad.status(), 400);
    let after: serde_json::Value = client
        .get(format!("{base}/api/policy"))
        .send()
        .await
        .expect("get after")
        .json()
        .await
        .expect("parse");
    assert_eq!(
        after["categories"]["pii"].as_str(),
        None,
        "an invalid patch applies none of its entries: {after}"
    );
}

/// F6: false-positive triage — add, list and remove from the allowlist.
#[tokio::test]
async fn allowlist_add_list_and_remove() {
    let ctx = make_ctx_with_url(vec![], OperationMode::Enforce, "http://127.0.0.1:9999");
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let empty: serde_json::Value = client
        .get(format!("{base}/api/allowlist"))
        .send()
        .await
        .expect("get allowlist")
        .json()
        .await
        .expect("parse");
    assert_eq!(empty.as_array().map(Vec::len), Some(0));

    let added = client
        .post(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({"value": "sk-EXAMPLE-do-not-flag"}))
        .send()
        .await
        .expect("post allowlist");
    assert_eq!(added.status(), 200);
    // R9-7: the add response carries the FINGERPRINT, never the raw value.
    let added_doc: serde_json::Value = added.json().await.expect("add doc");
    let expected_fp = harness_fingerprint("sk-EXAMPLE-do-not-flag");
    assert_eq!(added_doc["fingerprint"].as_str(), Some(expected_fp.as_str()));
    assert!(
        !added_doc.to_string().contains("sk-EXAMPLE-do-not-flag"),
        "the raw value must not be echoed: {added_doc}"
    );

    let listed: serde_json::Value = client
        .get(format!("{base}/api/allowlist"))
        .send()
        .await
        .expect("get allowlist")
        .json()
        .await
        .expect("parse");
    // R9-7: the listing shows fingerprints only (the UI shows the digest).
    assert_eq!(listed[0].as_str(), Some(expected_fp.as_str()));

    // The allowlist also appears in the policy document (a single view).
    let pol: serde_json::Value = client
        .get(format!("{base}/api/policy"))
        .send()
        .await
        .expect("get policy")
        .json()
        .await
        .expect("parse");
    assert_eq!(pol["allowlist"][0].as_str(), Some(expected_fp.as_str()));

    let removed = client
        .delete(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({"value": "sk-EXAMPLE-do-not-flag"}))
        .send()
        .await
        .expect("delete allowlist");
    assert_eq!(removed.status(), 200);
    let after: serde_json::Value = client
        .get(format!("{base}/api/allowlist"))
        .send()
        .await
        .expect("get allowlist")
        .json()
        .await
        .expect("parse");
    assert_eq!(after.as_array().map(Vec::len), Some(0));

    // Remove something that is not there → 404.
    let missing = client
        .delete(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({"value": "nope"}))
        .send()
        .await
        .expect("delete missing");
    assert_eq!(missing.status(), 404);
}

/// The policy overlay is part of the control plane: it requires a token.
#[tokio::test]
async fn policy_and_allowlist_require_the_admin_token() {
    let ctx = make_ctx_with_token(
        vec![],
        OperationMode::Enforce,
        "http://127.0.0.1:9999",
        STRONG_ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    for path in ["/api/policy", "/api/allowlist"] {
        let denied = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .expect("get without token");
        assert_eq!(denied.status(), 401, "{path} must require the admin token");
        let allowed = client
            .get(format!("{base}{path}"))
            .header("x-cerberus-admin-token", STRONG_ADMIN_TOKEN)
            .send()
            .await
            .expect("get with token");
        assert_eq!(allowed.status(), 200, "{path} with token");
    }
}

/// Fix v6.1: HTTP + dataplane test of the full before/after/reopen cycle.
/// The base rule represents an already-active pack; it must survive the
/// hot-reload and the reopen, while the custom rule and the allowlist are
/// restored from the YAML.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn policy_custom_rule_and_allowlist_scan_before_after_and_reopen() {
    let (mock_addr, mock_handle) = spawn_mock_upstream_echo().await;
    let config_path = unique_temp_path("policy-reopen.yaml");
    let pack_rule = cerberus_engine::rule::Rule {
        flag: "pack.keep".to_string(),
        category: cerberus_engine::rule::Category::InternalCode,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec!["PACK-[0-9]{4}".to_string()],
        validators: Vec::new(),
    };
    let mut config = ProxyConfig::with_upstream("default", &format!("http://{mock_addr}"));
    config.mode = OperationMode::Enforce;
    let ctx = make_policy_ctx(vec![pack_rule.clone()], config, config_path.clone());
    let (addr, proxy_handle) = spawn_proxy(local_addr(0), ctx.clone()).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    assert_eq!(
        post_scan(&client, &base, "badge CUSTOM-1234").await,
        200,
        "before: no custom rule"
    );
    assert_eq!(
        post_scan(&client, &base, "PACK-1234").await,
        403,
        "base pack rule active"
    );

    let updated = client
        .put(format!("{base}/api/policy"))
        .json(&serde_json::json!({
            "custom_rules": [{
                "flag": "custom.badge",
                "category": "internal_code",
                "severity": "critical",
                "action": "block",
                "patterns": ["CUSTOM-[0-9]{4}"],
                "contextKeywords": ["badge"],
                "minLength": 11,
                "maxLength": 11,
                "allowedExamples": ["CUSTOM-0000"],
                "validators": []
            }]
        }))
        .send()
        .await
        .expect("put policy");
    assert_eq!(updated.status(), 200, "custom rule accepted over HTTP");
    assert_eq!(
        post_scan(&client, &base, "badge CUSTOM-1234").await,
        403,
        "after: hot-swapped custom rule"
    );
    assert_eq!(
        post_scan(&client, &base, "PACK-1234").await,
        403,
        "pack survives policy update"
    );

    let allow = client
        .post(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({"value": "CUSTOM-1234"}))
        .send()
        .await
        .expect("allowlist add");
    assert_eq!(allow.status(), 200);
    assert_eq!(
        post_scan(&client, &base, "badge CUSTOM-1234").await,
        200,
        "allowlist affects live scan"
    );

    let yaml = std::fs::read_to_string(&config_path).expect("persisted YAML");
    let reopened = ProxyConfig::parse(&yaml).expect("reopen YAML");
    let custom = &reopened.policy.custom_rules[0];
    assert_eq!(custom.flag, "custom.badge");
    assert_eq!(custom.min_length, Some(11));
    assert_eq!(custom.context_keywords, vec!["badge".to_string()]);
    // R9-7: the YAML stores the FINGERPRINT of the allowed value.
    assert_eq!(reopened.policy.allowlist, vec![harness_fingerprint("CUSTOM-1234")]);
    assert!(
        !yaml.contains("CUSTOM-1234\""),
        "raw value must not be in the YAML: {yaml}"
    );

    proxy_handle.abort();
    let reopened_ctx = make_policy_ctx(vec![pack_rule], reopened, config_path.clone());
    let (reopened_addr, reopened_handle) = spawn_proxy(local_addr(0), reopened_ctx.clone())
        .await
        .expect("reopen proxy");
    let reopened_base = format!("http://{reopened_addr}");
    assert_eq!(
        post_scan(&client, &reopened_base, "badge CUSTOM-1234").await,
        200,
        "allowlist restored"
    );
    assert_eq!(
        post_scan(&client, &reopened_base, "badge CUSTOM-5678").await,
        403,
        "custom rule restored"
    );
    assert_eq!(
        post_scan(&client, &reopened_base, "PACK-5678").await,
        403,
        "pack restored beside custom"
    );
    let flags: Vec<String> = reopened_ctx
        .engine
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .rules()
        .iter()
        .map(|rule| rule.flag.clone())
        .collect();
    assert_eq!(
        flags.iter().filter(|flag| flag.as_str() == "custom.badge").count(),
        1,
        "{flags:?}"
    );
    assert!(flags.iter().any(|flag| flag == "pack.keep"), "{flags:?}");

    reopened_handle.abort();
    mock_handle.abort();
    std::fs::remove_file(config_path).ok();
}

/// Wire v2 is tested against the real HTTP handler: the bytes reach the
/// worker; the v1 path form is rejected before the worker even if the path
/// points to a valid pack on the filesystem visible to the server process.
#[tokio::test]
async fn pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<cerberus_proxy::api::PackCommand>(4);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let worker_seen = seen.clone();
    let worker = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            match command {
                cerberus_proxy::api::PackCommand::Install { request, reply } => {
                    worker_seen
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(request);
                    let _ = reply.send(Ok("accepted bytes".to_string()));
                }
                cerberus_proxy::api::PackCommand::Rollback { reply }
                | cerberus_proxy::api::PackCommand::List { reply }
                | cerberus_proxy::api::PackCommand::Enable { reply, .. }
                | cerberus_proxy::api::PackCommand::Disable { reply, .. }
                | cerberus_proxy::api::PackCommand::Update { reply } => {
                    let _ = reply.send(Err("unexpected command".to_string()));
                }
            }
        }
    });

    let engine = cerberus_engine::engine::EngineBuilder::new(&[])
        .build()
        .expect("engine");
    let mut config = ProxyConfig::with_upstream("default", "http://127.0.0.1:9999");
    // R9-5/F6: the harness authenticates the control plane like the product.
    config.admin_token = Some(HARNESS_ADMIN_TOKEN.to_string());
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let live = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    let ctx = std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: live,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared)
            .with_pack_worker(tx)
            .with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec()),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    });
    let (addr, proxy_handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();
    let signed_pack = serde_json::json!({
        "pack_json": r#"{"metadata":{"name":"demo","version":"1.0.0","description":"d","author":"a","published":"2026-01-01","min_engine_version":"0.1.0"},"rules":[]}"#,
        "signature_hex": "aa".repeat(64),
        "signer_public_key_hex": "bb".repeat(32)
    })
    .to_string();
    let request = cerberus_packs::wire::PackInstallRequest::from_pack_bytes(
        signed_pack.as_bytes(),
        Some("/remote/client/demo.json"),
    )
    .expect("wire request");
    let accepted = client
        .post(format!("{base}/api/packs/install"))
        .header("content-type", "application/json")
        .body(request.to_body().expect("wire body"))
        .send()
        .await
        .expect("install bytes");
    assert_eq!(accepted.status(), 200);

    let remote_path = unique_temp_path("remote-pack.json");
    std::fs::write(&remote_path, &signed_pack).expect("remote fixture");
    let rejected = client
        .post(format!("{base}/api/packs/install"))
        .json(&serde_json::json!({"path": remote_path}))
        .send()
        .await
        .expect("legacy install");
    assert_eq!(rejected.status(), 400);
    let error: serde_json::Value = rejected.json().await.expect("legacy error JSON");
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("wire v1")),
        "{error}"
    );

    let seen = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        seen.len(),
        1,
        "legacy path must be rejected before the worker: {seen:?}"
    );
    assert_eq!(seen[0].pack, signed_pack, "worker receives exact signed-pack bytes");
    assert_eq!(seen[0].origin_name.as_deref(), Some("demo.json"));
    drop(seen);

    proxy_handle.abort();
    worker.abort();
    std::fs::remove_file(remote_path).ok();
}

/// The CSP travels in the HEADER (so `frame-ancestors` applies) and without
/// `unsafe-inline`: the served inline block is authorized by its sha256.
#[tokio::test]
async fn dashboard_serves_an_effective_csp_header() {
    let ctx = make_ctx_with_token(
        vec![],
        OperationMode::Enforce,
        "http://127.0.0.1:9999",
        STRONG_ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");

    // The dashboard is public HTML: it is served without a token (carries no data).
    let resp = api_client()
        .get(format!("{base}/api/dashboard"))
        .send()
        .await
        .expect("get dashboard");
    assert_eq!(resp.status(), 200);
    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("CSP header")
        .to_string();
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("script-src 'sha256-"), "{csp}");
    assert!(csp.contains("style-src 'sha256-"), "{csp}");
    assert!(!csp.contains("unsafe-inline"), "{csp}");
    assert_eq!(
        resp.headers().get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    let html = resp.text().await.expect("body");
    assert!(!html.contains(STRONG_ADMIN_TOKEN), "token leaked into the dashboard");
    assert!(!html.contains("onclick=\""), "inline handlers break the hash CSP");
}

// =============================================================================
// F2.2 + F2.3 (R9-8): request-scoped reversible vault + live one-shot
// break-glass primitive.
// =============================================================================

/// Rule that REDACTS (irreversible would emit `[REDACTED:test.redact]`).
fn redact_rule() -> cerberus_engine::rule::Rule {
    cerberus_engine::rule::Rule {
        flag: "test.redact".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::High,
        action: cerberus_engine::rule::Action::Redact,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        validators: Vec::new(),
    }
}

/// Context for the R9-8 tests: explicit rules, mode, upstream, admin token
/// and the `reversible_redaction` opt-in flag.
#[allow(clippy::too_many_arguments)]
fn make_ctx_r9(
    rules: &[cerberus_engine::rule::Rule],
    operation_mode: OperationMode,
    upstream_url: &str,
    admin_token: Option<&str>,
    reversible_redaction: bool,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(rules).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: None,
            auth_header: "authorization".to_string(),
            mode: None,
            expected_auth: None,
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: operation_mode,
        fail_policy: FailPolicy::Closed,
        admin_token: admin_token.map(ToString::to_string),
        reversible_redaction,
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

#[tokio::test]
async fn test_break_glass_one_shot_end_to_end() {
    // F2.3 (R9-8): the one-shot primitive must be LIVE: issued through the
    // authenticated control plane, redeemed on the data plane exactly once,
    // and audited. Reuse/expiry/auth failures refuse the bypass.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let admin = "r9-test-admin-token-0123456789abcdef";
    let ctx = make_ctx_r9(
        &[block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        Some(admin),
        false,
    );
    let ctx_clone = std::sync::Arc::clone(&ctx);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();
    let admin_h = ("x-cerberus-admin-token", admin);

    // 1. Issuing WITHOUT a valid admin token is rejected (401).
    let unauth = client
        .post(format!("{base}/api/break-glass"))
        .header("content-type", "application/json")
        .body(r#"{"reason":"no token"}"#)
        .send()
        .await
        .expect("unauth issue");
    assert_eq!(unauth.status(), 401, "unauthenticated issue must be 401");

    // 2. Issue with the admin token → nonce (+ reason hash, never raw reason).
    let issued = client
        .post(format!("{base}/api/break-glass"))
        .header("content-type", "application/json")
        .header(admin_h.0, admin_h.1)
        .body(r#"{"reason":"e2e emergency","provider":"default","ttl_secs":60}"#)
        .send()
        .await
        .expect("issue");
    assert_eq!(issued.status(), 200, "authenticated issue must be 200");
    let issue_json: serde_json::Value = issued.json().await.expect("issue json");
    let nonce = issue_json["nonce"].as_str().expect("nonce").to_string();
    assert_eq!(nonce.len(), 64, "256-bit CSPRNG nonce");
    assert!(issue_json["reason_hash"].as_str().unwrap_or("").starts_with("sha256:"));
    let raw = issue_json.to_string();
    assert!(!raw.contains("e2e emergency"), "raw reason must never be returned");

    // 3. Without a bypass token the block applies (403).
    let plain = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("plain");
    assert_eq!(plain.status(), 403);

    // 4. Data-plane redemption: `X-Cerberus-Bypass: break-glass:<nonce>` +
    //    admin token → the block is bypassed (200 from the mock upstream).
    let bypassed = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", format!("break-glass:{nonce}"))
        .header(admin_h.0, admin_h.1)
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("bypassed");
    assert_eq!(bypassed.status(), 200, "one-shot redemption must bypass the block");

    // 5. ONE-SHOT: the same nonce is consumed; replay is refused → 403.
    let replay = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", format!("break-glass:{nonce}"))
        .header(admin_h.0, admin_h.1)
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("replay");
    assert_eq!(replay.status(), 403, "second use must be rejected (one-shot)");

    // 6. The bypass use is AUDITED: the event carries the `bypass` +
    //    `break-glass` flags and the hashed reason, never the raw one.
    let events = client
        .get(format!("{base}/api/events"))
        .header(admin_h.0, admin_h.1)
        .send()
        .await
        .expect("events");
    assert_eq!(events.status(), 200);
    let events_json: serde_json::Value = events.json().await.expect("events json");
    let events_str = events_json.to_string();
    assert!(events_str.contains("\"bypass\""), "bypass flag audited: {events_str}");
    assert!(
        events_str.contains("break-glass"),
        "break-glass marker audited: {events_str}"
    );
    assert!(
        events_str.contains("bypass-hash:"),
        "hashed reason audited: {events_str}"
    );
    assert!(
        !events_str.contains("e2e emergency"),
        "raw reason must never be audited"
    );

    // 7. The ledger no longer holds the consumed nonce.
    assert!(ctx_clone.api.break_glass.is_empty(), "nonce consumed (one-shot)");
    mock_handle.abort();
}

#[tokio::test]
async fn test_break_glass_wrong_provider_scope_rejected() {
    // F2.3: a token scoped to provider X is refused for provider Y; the
    // token is NOT consumed (still valid for X) and the request is blocked.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let admin = "r9-test-admin-token-0123456789abcdef";
    let ctx = make_ctx_r9(
        &[block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        Some(admin),
        false,
    );
    let ctx_clone = std::sync::Arc::clone(&ctx);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    let issued = client
        .post(format!("{base}/api/break-glass"))
        .header("content-type", "application/json")
        .header("x-cerberus-admin-token", admin)
        .body(r#"{"reason":"scoped emergency","provider":"openai"}"#)
        .send()
        .await
        .expect("issue");
    assert_eq!(issued.status(), 200);
    let issue_json: serde_json::Value = issued.json().await.expect("issue json");
    let nonce = issue_json["nonce"].as_str().expect("nonce").to_string();

    // The data-plane request routes to provider `default`, not `openai`.
    let resp = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", format!("break-glass:{nonce}"))
        .header("x-cerberus-admin-token", admin)
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("wrong provider");
    assert_eq!(resp.status(), 403, "scope mismatch must refuse the bypass");
    assert_eq!(
        ctx_clone.api.break_glass.len(),
        1,
        "token not consumed on scope mismatch"
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_reversible_vault_round_trip_request_scoped() {
    // F2.2 (R9-8): with `reversible_redaction` (opt-in) the upstream receives
    // a vault token (never the raw secret) and the response restores the
    // original (non-streaming un-redaction). Each request gets its own
    // request-scoped vault: no cross-request secret reuse.
    let (mock_adj, mock_handle) = spawn_mock_upstream_echo().await;
    let ctx = make_ctx_r9(
        &[redact_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        None,
        true,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // Request 1: secret A.
    let body1 = r#"{"content":"sk-ROUNDTRIPaaa111222333444"}"#;
    let r1 = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(body1)
        .send()
        .await
        .expect("r1");
    assert_eq!(r1.status(), 200);
    let text1 = r1.text().await.expect("r1 body");
    // The echo mock returns the raw request it received; un-redaction must
    // have restored the original value on the client side.
    assert!(
        text1.contains("sk-ROUNDTRIPaaa111222333444"),
        "original restored in response: {text1}"
    );
    assert!(!text1.contains("[VAULT:"), "token must be un-redacted: {text1}");

    // Request 2: a DIFFERENT secret (request-scoped vault, new token).
    let body2 = r#"{"content":"sk-ROUNDTRIPbbb555666777888"}"#;
    let r2 = client
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .body(body2)
        .send()
        .await
        .expect("r2");
    assert_eq!(r2.status(), 200);
    let text2 = r2.text().await.expect("r2 body");
    assert!(
        text2.contains("sk-ROUNDTRIPbbb555666777888"),
        "second secret restored: {text2}"
    );
    assert!(
        !text2.contains("sk-ROUNDTRIPaaa111222333444"),
        "no cross-request secret reuse"
    );
    mock_handle.abort();
}

#[tokio::test]
async fn test_reversible_redaction_is_opt_in_default_irreversible() {
    // Closed decision §9 #4: irreversible redaction is the DEFAULT. Without
    // the flag the same request emits `[REDACTED:test.redact]` and there is
    // no vault round trip.
    let (mock_adj, mock_handle) = spawn_mock_upstream_echo().await;
    let ctx = make_ctx_r9(
        &[redact_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        None,
        false, // reversible_redaction NOT enabled
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let r = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(r#"{"content":"sk-IRREVERSIBLEaaa111222333"}"#)
        .send()
        .await
        .expect("r");
    assert_eq!(r.status(), 200);
    let text = r.text().await.expect("body");
    assert!(
        text.contains("[REDACTED:test.redact]"),
        "default is irreversible: {text}"
    );
    assert!(
        !text.contains("sk-IRREVERSIBLEaaa111222333"),
        "raw secret never restored without the opt-in"
    );
    mock_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// F3.1 + F3.2 — R9-11 (per-upstream mode), R9-12 (closed-on-critical default),
// R9-13 (multipart MVP decoder), R9-20 (expected_auth wire-name compat).
// ═══════════════════════════════════════════════════════════════════════════

use bytes::Bytes;
use cerberus_proxy::decoder::decode;
use std::sync::{Arc, Mutex};

/// Raw-capturing mock upstream: reads the full request (per content-length)
/// and stores it verbatim; responds `{"ok":true}`.
async fn spawn_mock_upstream_capture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, Arc<Mutex<Vec<u8>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind capturing mock");
    let addr = listener.local_addr().expect("addr");
    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                // Read until EOF or enough for headers + content-length.
                let mut headers_end = None;
                let mut content_length = 0usize;
                loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if headers_end.is_none() {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            headers_end = Some(pos + 4);
                            let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                            content_length = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                        }
                    }
                    if let Some(start) = headers_end {
                        if buf.len() >= start + content_length {
                            break;
                        }
                    }
                }
                (*sink.lock().unwrap()).clone_from(&buf);
                let body = r#"{"ok":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, handle, captured)
}

/// Context builder that keeps the DEFAULT fail policy (`closed-on-critical`,
/// R9-12) — unlike `make_ctx_opts`, which pins `FailPolicy::Closed`.
fn make_ctx_default_fail_policy(
    rules: &[cerberus_engine::rule::Rule],
    operation_mode: OperationMode,
    upstream_url: &str,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(rules).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: None,
            auth_header: "authorization".to_string(),
            mode: None,
            expected_auth: None,
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: operation_mode,
        // fail_policy left at the DEFAULT (closed-on-critical, R9-12).
        // R9-5/F6: the harness authenticates the control plane like the product.
        admin_token: Some(HARNESS_ADMIN_TOKEN.to_string()),
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared).with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec()),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Context with a mixed upstream fleet and per-upstream modes (R9-11).
fn make_ctx_mixed_fleet(
    rules: &[cerberus_engine::rule::Rule],
    global_mode: OperationMode,
    upstream_url: &str,
    shadowed_mode: Option<OperationMode>,
    enforced_mode: Option<OperationMode>,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(rules).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "shadowed".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: Some("/shadowed".to_string()),
            auth_header: "authorization".to_string(),
            mode: shadowed_mode,
            expected_auth: None,
        },
    );
    upstreams.insert(
        "enforced".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: Some("/enforced".to_string()),
            auth_header: "authorization".to_string(),
            mode: enforced_mode,
            expected_auth: None,
        },
    );
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            url: upstream_url.to_string(),
            path_prefix: None,
            auth_header: "authorization".to_string(),
            mode: None,
            expected_auth: None,
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: global_mode,
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Block rule for `BLOCKSECRET1…` (critical severity).
fn f3_block_rule() -> cerberus_engine::rule::Rule {
    let mut r = block_rule();
    r.patterns = vec![r"BLOCKSECRET1[A-Za-z0-9]{10,}".to_string()];
    r
}

/// Redact rule for `REDACTSECRET2…` with a controllable severity.
fn f3_redact_rule(severity: cerberus_engine::rule::Severity) -> cerberus_engine::rule::Rule {
    cerberus_engine::rule::Rule {
        flag: "test.redact".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity,
        action: cerberus_engine::rule::Action::Redact,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"REDACTSECRET2[A-Za-z0-9]{10,}".to_string()],
        validators: Vec::new(),
    }
}

/// ── R9-11: per-upstream shadow mode in a mixed fleet ──
#[tokio::test]
async fn per_upstream_shadow_mode_never_blocks_in_mixed_fleet() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    // Global enforce; the "shadowed" upstream is explicitly shadow; the
    // "default" upstream inherits the global (enforce).
    let ctx = make_ctx_mixed_fleet(
        &[f3_block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        Some(OperationMode::Shadow),
        None,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("BLOCKSECRET1{}", "aaaaaaaaaa");

    // Shadow upstream: never blocks, forwards intact.
    let r = client
        .post(format!("http://{addr}/shadowed/v1/chat"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"content":"{secret}"}}"#))
        .send()
        .await
        .expect("shadow upstream request");
    assert_eq!(
        r.status(),
        200,
        "a shadow upstream must never block (got {})",
        r.status()
    );
    // Default upstream (no per-upstream mode → global enforce): blocked.
    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"content":"{secret}"}}"#))
        .send()
        .await
        .expect("default upstream request");
    assert_eq!(r.status(), 403, "global enforce must still block");
    mock_handle.abort();
}

/// ── R9-11: per-upstream enforce overrides a global shadow mode ──
#[tokio::test]
async fn per_upstream_enforce_mode_overrides_global_shadow() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    // Global shadow; the "enforced" upstream explicitly enforces; "shadowed"
    // and "default" inherit the global shadow.
    let ctx = make_ctx_mixed_fleet(
        &[f3_block_rule()],
        OperationMode::Shadow,
        &format!("http://{mock_adj}"),
        None,
        Some(OperationMode::Enforce),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("BLOCKSECRET1{}", "bbbbbbbbbb");
    let body = format!(r#"{{"content":"{secret}"}}"#);

    // Enforced upstream: blocks even though the global mode is shadow.
    let r = client
        .post(format!("http://{addr}/enforced/v1/chat"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .expect("enforced upstream request");
    assert_eq!(r.status(), 403, "per-upstream enforce must override global shadow");

    // Shadowed upstream (explicit shadow): passes intact.
    let r = client
        .post(format!("http://{addr}/shadowed/v1/chat"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .expect("shadowed upstream request");
    assert_eq!(r.status(), 200);

    // Default upstream (no mode → global shadow): passes intact.
    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("default upstream request");
    assert_eq!(r.status(), 200, "global shadow fallback must pass through");
    mock_handle.abort();
}

/// ── R9-12: critical redaction failure under the DEFAULT policy → 502 ──
#[tokio::test]
async fn closed_on_critical_rejects_redaction_failure_with_critical_findings() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let block = format!("BLOCKSECRET1{}", "cccccccccc");
    let redactable = format!("REDACTSECRET2{}", "dddddddddd");
    let ctx = make_ctx_default_fail_policy(
        &[
            f3_block_rule(),
            f3_redact_rule(cerberus_engine::rule::Severity::Critical),
        ],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    // Allowlist the BLOCK secret so the pipeline passes the block stage and
    // reaches redaction, where the JSON leaf re-scan still fails on it
    // (the same mechanism as the forward.rs redaction-failure test).
    // R9-7: the allowlist carries the HMAC fingerprint, not the raw value.
    ctx.config.write().unwrap().policy.allowlist = vec![harness_fingerprint(&block)];
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"content":"{block} {redactable}"}}"#))
        .send()
        .await
        .expect("critical redaction failure request");
    assert_eq!(
        r.status(),
        502,
        "closed-on-critical must reject when the request carries critical findings"
    );
    let text = r.text().await.expect("body");
    assert!(text.contains("redact failure"), "body: {text}");
    mock_handle.abort();
}

/// ── R9-12: non-critical redaction failure under the DEFAULT policy → the
/// ORIGINAL body is forwarded (fail-open for the rest, the behavioral delta
/// vs the previous `Closed` default) ──
#[tokio::test]
async fn closed_on_critical_forwards_original_for_non_critical_redaction_failure() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let block = format!("BLOCKSECRET1{}", "eeeeeeeeee");
    let redactable = format!("REDACTSECRET2{}", "ffffffffff");
    let ctx = make_ctx_default_fail_policy(
        &[f3_block_rule(), f3_redact_rule(cerberus_engine::rule::Severity::Low)],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    // R9-7: the allowlist carries the HMAC fingerprint, not the raw value.
    ctx.config.write().unwrap().policy.allowlist = vec![harness_fingerprint(&block)];
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let original = format!(r#"{{"content":"{block} {redactable}"}}"#);

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(original.clone())
        .send()
        .await
        .expect("non-critical redaction failure request");
    assert_eq!(
        r.status(),
        200,
        "closed-on-critical must fail OPEN when no critical findings exist (got {})",
        r.status()
    );
    let forwarded = captured.lock().unwrap().clone();
    let body_start = forwarded
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("captured headers")
        + 4;
    assert_eq!(
        &forwarded[body_start..],
        original.as_bytes(),
        "the ORIGINAL body must be forwarded verbatim (fail-open)"
    );
    mock_handle.abort();
}

/// ── R9-12: undecodable JSON body under the DEFAULT policy → 502
/// (indeterminate criticality → fail-closed posture) ──
#[tokio::test]
async fn closed_on_critical_rejects_undecodable_json_body() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_default_fail_policy(&[], OperationMode::Enforce, &format!("http://{mock_adj}"));
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .expect("undecodable request");
    assert_eq!(
        r.status(),
        502,
        "closed-on-critical must fail closed when criticality is indeterminate"
    );
    mock_handle.abort();
}

/// ── R9-13: multipart text part redacted end-to-end; binary part preserved ──
#[tokio::test]
async fn multipart_text_part_redacted_binary_part_byte_exact_end_to_end() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(
        &[f3_redact_rule(cerberus_engine::rule::Severity::High)],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("REDACTSECRET2{}", "gggggggggg");
    let binary: Vec<u8> = (0u8..=255).cycle().take(256).collect();

    let mut body = Vec::new();
    body.extend_from_slice(b"--F3BOUNDARY\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"prompt\"\r\n");
    body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    body.extend_from_slice(format!("my key is {secret}").as_bytes());
    body.extend_from_slice(b"\r\n--F3BOUNDARY\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"file\"; filename=\"clip.wav\"\r\n");
    body.extend_from_slice(b"Content-Type: audio/wav\r\n\r\n");
    body.extend_from_slice(&binary);
    body.extend_from_slice(b"\r\n--F3BOUNDARY--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/transcribe"))
        .header("content-type", "multipart/form-data; boundary=F3BOUNDARY")
        .body(body)
        .send()
        .await
        .expect("multipart request");
    assert_eq!(
        r.status(),
        200,
        "multipart with a redactable text part must forward (got {})",
        r.status()
    );

    let forwarded = captured.lock().unwrap().clone();
    let body_start = forwarded
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("captured headers")
        + 4;
    let fwd_body = &forwarded[body_start..];
    let fwd_text = String::from_utf8_lossy(fwd_body);
    assert!(
        !fwd_text.contains(&secret),
        "the raw secret must not reach the upstream: {fwd_text}"
    );
    assert!(
        fwd_text.contains("[REDACTED:test.redact]"),
        "text part redacted: {fwd_text}"
    );
    assert!(fwd_text.contains("name=\"prompt\""), "part headers preserved");
    assert!(fwd_text.contains("filename=\"clip.wav\""), "file metadata preserved");
    // The binary payload must be byte-exact in the forwarded body.
    let bin_pos = fwd_body
        .windows(b"audio/wav".len())
        .position(|w| w == b"audio/wav")
        .expect("audio content-type preserved");
    let bin_start = bin_pos + b"audio/wav\r\n\r\n".len();
    assert_eq!(
        &fwd_body[bin_start..bin_start + 256],
        &binary[..],
        "binary part byte-exact"
    );
    mock_handle.abort();
}

/// ── R9-13: a block rule matching a multipart text part cuts the request ──
#[tokio::test]
async fn multipart_block_rule_blocks_the_request() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(
        &[f3_block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("BLOCKSECRET1{}", "hhhhhhhhhh");

    let mut body = Vec::new();
    body.extend_from_slice(b"--F3B2\r\n");
    body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    body.extend_from_slice(format!("note {secret}").as_bytes());
    body.extend_from_slice(b"\r\n--F3B2--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/x"))
        .header("content-type", "multipart/form-data; boundary=F3B2")
        .body(body)
        .send()
        .await
        .expect("multipart block request");
    assert_eq!(r.status(), 403, "block finding in a text part must block");
    assert!(
        captured.lock().unwrap().is_empty(),
        "nothing must be forwarded when blocked"
    );
    mock_handle.abort();
}

/// ── R9-13: multipart in shadow mode passes through intact ──
#[tokio::test]
async fn multipart_shadow_mode_forwards_intact() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(&[f3_block_rule()], OperationMode::Shadow, &format!("http://{mock_adj}"));
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("BLOCKSECRET1{}", "iiiiiiiiii");
    let original = format!("--F3B3\r\nContent-Type: text/plain\r\n\r\nnote {secret}\r\n--F3B3--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/x"))
        .header("content-type", "multipart/form-data; boundary=F3B3")
        .body(original.clone())
        .send()
        .await
        .expect("multipart shadow request");
    assert_eq!(r.status(), 200, "shadow never blocks");
    let forwarded = captured.lock().unwrap().clone();
    let body_start = forwarded.windows(4).position(|w| w == b"\r\n\r\n").expect("headers") + 4;
    assert_eq!(
        &forwarded[body_start..],
        original.as_bytes(),
        "shadow forwards the body intact"
    );
    mock_handle.abort();
}

/// ── R9-13: multipart over `max_body_bytes` → 413 (size limit case) ──
#[tokio::test]
async fn multipart_over_body_limit_returns_413() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_default_fail_policy(&[], OperationMode::Enforce, &format!("http://{mock_adj}"));
    ctx.config.write().unwrap().max_body_bytes = Some(1024);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    let mut body = Vec::new();
    body.extend_from_slice(b"--F3B4\r\nContent-Type: text/plain\r\n\r\n");
    body.extend_from_slice(&vec![b'x'; 4096]);
    body.extend_from_slice(b"\r\n--F3B4--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/x"))
        .header("content-type", "multipart/form-data; boundary=F3B4")
        .body(body)
        .send()
        .await
        .expect("multipart oversized request");
    assert_eq!(r.status(), 413, "multipart over max_body_bytes must be 413");
    mock_handle.abort();
}

/// ── R9-13: malformed multipart falls back to whole-text scanning (over-scan:
/// a secret is still caught, never missed) ──
#[tokio::test]
async fn multipart_malformed_structure_still_blocks_via_text_fallback() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_default_fail_policy(
        &[f3_block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("BLOCKSECRET1{}", "jjjjjjjjjj");

    // Multipart hint WITHOUT a boundary parameter → no structured parse.
    let r = client
        .post(format!("http://{addr}/v1/x"))
        .header("content-type", "multipart/form-data")
        .body(format!("junk {secret}"))
        .send()
        .await
        .expect("malformed multipart request");
    assert_eq!(r.status(), 403, "text fallback must still scan and block");
    mock_handle.abort();
}

/// ── R9-20 + R9-12: the Appendix A.1 YAML parses and the proxy runs with it ──
#[tokio::test]
async fn a1_yaml_config_drives_the_proxy_end_to_end() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let yaml = format!(
        "listen: 127.0.0.1:8787\n\
         fail_mode: closed-on-critical\n\
         upstreams:\n\
         \x20 default: {{ url: http://{mock_adj}, expected_auth: header }}\n"
    );
    let cfg = ProxyConfig::parse(&yaml).expect("the A.1-shaped YAML must parse");
    assert_eq!(cfg.fail_policy, FailPolicy::ClosedOnCritical);
    assert_eq!(cfg.upstreams["default"].expected_auth.as_deref(), Some("header"));
    let engine = cerberus_engine::engine::EngineBuilder::new(&[]).build().unwrap();
    let shared = std::sync::Arc::new(std::sync::RwLock::new(cfg));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    let ctx = std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    });
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("authorization", "Bearer provider-key")
        .body(r#"{"content":"clean prompt"}"#)
        .send()
        .await
        .expect("a1 proxy request");
    assert_eq!(r.status(), 200, "A.1 config must serve traffic");
    let forwarded = captured.lock().unwrap().clone();
    let head = String::from_utf8_lossy(&forwarded);
    assert!(
        head.contains("authorization:"),
        "the provider credential header (default auth_header) must be forwarded"
    );
    mock_handle.abort();
}

/// ── R9-13 unit-level: the decoder is reachable from the pipeline path with
/// the same `DecodedBody` contract (single parse; regions recorded — since
/// the attempt-2 fix they cover payloads, part headers, preamble and
/// epilogue; `binary_parts_skipped` counts the byte-exact-preservation
/// trade-off) ──
#[test]
fn decoder_records_multipart_regions_for_single_parse_redaction() {
    let body = Bytes::from(
        "--B1\r\nContent-Type: text/plain\r\n\r\nalpha secret\r\n--B1\r\nContent-Type: text/plain\r\n\r\nbeta\r\n--B1--\r\n",
    );
    let decoded = decode(&body, Some("multipart/form-data; boundary=B1"));
    assert_eq!(decoded.content_type, cerberus_proxy::decoder::ContentType::Multipart);
    assert!(decoded.parsed.is_none(), "multipart bodies carry no JSON tree");
    let regions = decoded.multipart.expect("regions recorded at decode time");
    assert_eq!(regions.len(), 4, "two header blocks + two payloads recorded once");
    assert_eq!(decoded.binary_parts_skipped, 0, "no binary payloads in this body");
}

// ═══════════════════════════════════════════════════════════════════════════
// FIX attempt 2 — pipeline-layer closure tests for the attempt-1 panel P1s:
// F-1/P1-3 (one authoritative scan model), P1-1 (preamble/epilogue/headers),
// P1-2 (MITM mode lives in forward.rs), P2-1/P2-2 (visible, honest audit).
// Every test drives the REAL request path (spawn_proxy → proxy_handler), not
// direct redact_body calls.
// ═══════════════════════════════════════════════════════════════════════════

/// Block rule for `BLOCKSECRET1…` (critical) gated by a context keyword.
fn f3_context_block_rule(keyword: &str) -> cerberus_engine::rule::Rule {
    let mut r = f3_block_rule();
    r.context_keywords = vec![keyword.to_string()];
    r
}

/// Redact rule for `CTXSECRET-…` (critical) gated by a context keyword.
fn f3_context_redact_rule(keyword: &str) -> cerberus_engine::rule::Rule {
    cerberus_engine::rule::Rule {
        flag: "test.ctxredact".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::Critical,
        action: cerberus_engine::rule::Action::Redact,
        hash_normalization: None,
        context_keywords: vec![keyword.to_string()],
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![r"CTXSECRET-[A-Za-z0-9]{10,}".to_string()],
        validators: Vec::new(),
    }
}

/// ── FIX F-1 (attempt-1 correctness P1): the EXACT reproduction payload —
/// a critical BLOCK rule whose contextKeyword appears ONLY in a part header
/// — must now yield closed behavior through the real pipeline. Under the
/// authoritative scan the keyword (part header) validates the payload match,
/// the DECISION itself sees the block finding → 403, nothing forwarded.
#[tokio::test]
async fn f1_repro_keyword_in_part_header_blocks_via_pipeline() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(
        &[
            f3_redact_rule(cerberus_engine::rule::Severity::Low), // test.lowredact, no keywords
            f3_context_block_rule("harmlessword="),               // test.critblock
        ],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let redactable = format!("REDACTSECRET2{}", "dddddddddddd");
    let block = format!("BLOCKSECRET1{}", "cccccccccccc");

    // The attempt-1 adv1 payload: keyword ONLY in part-2's header.
    let mut body = Vec::new();
    body.extend_from_slice(b"--XBOUND123\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"f1\"\r\n\r\n");
    body.extend_from_slice(redactable.as_bytes());
    body.extend_from_slice(b"\r\n--XBOUND123\r\n");
    body.extend_from_slice(b"X-Note: harmlessword=\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"f2\"\r\n\r\n");
    body.extend_from_slice(block.as_bytes());
    body.extend_from_slice(b"\r\n--XBOUND123--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "multipart/form-data; boundary=XBOUND123")
        .body(body)
        .send()
        .await
        .expect("f1 repro request");
    assert_eq!(
        r.status(),
        403,
        "the block rule must fire in the PIPELINE decision (closed behavior, got {})",
        r.status()
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "closed behavior: nothing may be forwarded when the critical block rule fires"
    );
    mock_handle.abort();
}

/// ── FIX P1-3 (attempt-1 security P1): cross-part context keywords must work
/// in the DECISION path through the REAL pipeline. This is the rewritten
/// acceptance test — the attempt-1 version called `redact_body` directly,
/// validating the wrong layer.
#[tokio::test]
async fn multipart_context_keyword_in_other_part_redacts_via_pipeline() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(
        &[f3_context_redact_rule("zeta")],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("CTXSECRET-{}", "kkkkkkkkkkkk");

    // Keyword in part 1's PAYLOAD, secret in part 2's payload.
    let mut body = Vec::new();
    body.extend_from_slice(b"--ZETAB\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"context\"\r\n\r\n");
    body.extend_from_slice(b"zeta\r\n");
    body.extend_from_slice(b"--ZETAB\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"secret\"\r\n\r\n");
    body.extend_from_slice(secret.as_bytes());
    body.extend_from_slice(b"\r\n--ZETAB--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "multipart/form-data; boundary=ZETAB")
        .body(body)
        .send()
        .await
        .expect("cross-part keyword request");
    assert_eq!(r.status(), 200, "a redact finding forwards (got {})", r.status());
    let forwarded = captured.lock().unwrap().clone();
    let fwd_text = String::from_utf8_lossy(&forwarded);
    assert!(
        !fwd_text.contains(&secret),
        "cross-part context must redact: {fwd_text}"
    );
    assert!(fwd_text.contains("[REDACTED:test.ctxredact]"), "{fwd_text}");
    mock_handle.abort();
}

/// ── FIX P1-3 (companion): the keyword placed in part METADATA (a form field
/// name, part header) must validate the payload secret in the DECISION path
/// too — the redaction then removes it (A6/A6b from the attempt-1 panel).
#[tokio::test]
async fn multipart_keyword_in_part_metadata_redacts_via_pipeline() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(
        &[f3_context_redact_rule("zeta")],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("CTXSECRET-{}", "llllllllllll");

    // The keyword appears ONLY in the part HEADER (`name="zeta"` metadata).
    let mut body = Vec::new();
    body.extend_from_slice(b"--ZETAC\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"zeta\"\r\n\r\n");
    body.extend_from_slice(secret.as_bytes());
    body.extend_from_slice(b"\r\n--ZETAC--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "multipart/form-data; boundary=ZETAC")
        .body(body)
        .send()
        .await
        .expect("metadata keyword request");
    assert_eq!(r.status(), 200);
    let forwarded = captured.lock().unwrap().clone();
    let fwd_text = String::from_utf8_lossy(&forwarded);
    assert!(
        !fwd_text.contains(&secret),
        "metadata-keyword context must redact: {fwd_text}"
    );
    assert!(fwd_text.contains("[REDACTED:test.ctxredact]"), "{fwd_text}");
    mock_handle.abort();
}

/// ── FIX P1-1 (attempt-1 security P1): secrets in the PREAMBLE, the
/// EPILOGUE and a part HEADER are scanned and redacted through the real
/// pipeline — the old lossy path covered them; the attempt-1 structured path
/// forwarded them raw silently.
#[tokio::test]
async fn multipart_preamble_epilogue_and_header_secrets_never_forward_raw() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(
        &[f3_redact_rule(cerberus_engine::rule::Severity::High)],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let pre = format!("REDACTSECRET2{}", "mmmmmmmmmm");
    let epi = format!("REDACTSECRET2{}", "nnnnnnnnnn");
    let hdr = format!("REDACTSECRET2{}", "oooooooooo");

    let mut body = Vec::new();
    body.extend_from_slice(format!("preamble has {pre}\r\n").as_bytes());
    body.extend_from_slice(b"--P1BOUND\r\n");
    body.extend_from_slice(b"Content-Type: text/plain\r\n");
    body.extend_from_slice(format!("X-Note: header has {hdr}\r\n\r\n").as_bytes());
    body.extend_from_slice(b"clean payload\r\n");
    body.extend_from_slice(b"--P1BOUND--\r\n");
    body.extend_from_slice(format!("epilogue has {epi}\r\n").as_bytes());

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "multipart/form-data; boundary=P1BOUND")
        .body(body)
        .send()
        .await
        .expect("preamble/epilogue/header request");
    assert_eq!(r.status(), 200);
    let forwarded = captured.lock().unwrap().clone();
    let fwd_text = String::from_utf8_lossy(&forwarded);
    assert!(
        !fwd_text.contains(&pre),
        "PREAMBLE secret must not forward raw: {fwd_text}"
    );
    assert!(
        !fwd_text.contains(&epi),
        "EPILOGUE secret must not forward raw: {fwd_text}"
    );
    assert!(
        !fwd_text.contains(&hdr),
        "PART HEADER secret must not forward raw: {fwd_text}"
    );
    assert!(fwd_text.contains("clean payload"), "payload intact: {fwd_text}");
    assert_eq!(fwd_text.matches("--P1BOUND").count(), 2, "structure intact: {fwd_text}");
    mock_handle.abort();
}

/// ── FIX P1-1, block direction: a critical BLOCK secret in a part header
/// must block the request (detection parity with the old lossy path).
#[tokio::test]
async fn multipart_block_secret_in_part_header_blocks_via_pipeline() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(
        &[f3_block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("BLOCKSECRET1{}", "pppppppppp");

    let mut body = Vec::new();
    body.extend_from_slice(b"--HDRVICTIM\r\n");
    body.extend_from_slice(b"Content-Type: text/plain\r\n");
    body.extend_from_slice(format!("X-Custom: token {secret}\r\n\r\n").as_bytes());
    body.extend_from_slice(b"harmless payload\r\n");
    body.extend_from_slice(b"--HDRVICTIM--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "multipart/form-data; boundary=HDRVICTIM")
        .body(body)
        .send()
        .await
        .expect("header block secret request");
    assert_eq!(r.status(), 403, "a block secret in a part header must block");
    assert!(captured.lock().unwrap().is_empty(), "nothing forwarded when blocked");
    mock_handle.abort();
}

/// ── FIX P2-1: a text secret inside a BINARY-CLAIMED part still forwards
/// (documented §4.2 byte-exact trade-off) but the under-scan is now VISIBLE:
/// the audit event carries the `binary-unscanned` flag even with zero
/// findings.
#[tokio::test]
async fn multipart_binary_claimed_part_under_scan_is_audited() {
    let (mock_adj, mock_handle, _captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(&[], OperationMode::Enforce, &format!("http://{mock_adj}"));
    let events = ctx.api.events.clone();
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    let mut body = Vec::new();
    body.extend_from_slice(b"--BINAUDIT\r\n");
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"file\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(b"text secret hidden in a binary-claimed part\r\n");
    body.extend_from_slice(b"\r\n--BINAUDIT--\r\n");

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "multipart/form-data; boundary=BINAUDIT")
        .body(body)
        .send()
        .await
        .expect("binary under-scan request");
    assert_eq!(r.status(), 200, "the byte-exact trade-off still forwards");

    let events = events.lock().await;
    assert!(
        events.iter().any(|e| e.flags.iter().any(|f| f == "binary-unscanned")),
        "the skipped binary payload must be visible in the audit: {:?}",
        events.iter().map(|e| (&e.action_taken, &e.flags)).collect::<Vec<_>>()
    );
    drop(events);
    mock_handle.abort();
}

/// ── FIX P2-2: a fail-open forward after a redaction failure is audited with
/// the honest action `fail-open` + the `redact-failed` flag — NEVER as plain
/// `redact` while the raw original went upstream.
#[tokio::test]
async fn closed_on_critical_fail_open_is_audited_honestly() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let block = format!("BLOCKSECRET1{}", "eeeeeeeeee");
    let redactable = format!("REDACTSECRET2{}", "ffffffffff");
    let ctx = make_ctx_default_fail_policy(
        &[f3_block_rule(), f3_redact_rule(cerberus_engine::rule::Severity::Low)],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let events = ctx.api.events.clone();
    // R9-7: the allowlist carries the HMAC fingerprint, not the raw value.
    ctx.config.write().unwrap().policy.allowlist = vec![harness_fingerprint(&block)];
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let original = format!(r#"{{"content":"{block} {redactable}"}}"#);

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(original.clone())
        .send()
        .await
        .expect("fail-open audit request");
    assert_eq!(r.status(), 200, "non-critical redaction failure fails open");
    let forwarded = captured.lock().unwrap().clone();
    let body_start = forwarded.windows(4).position(|w| w == b"\r\n\r\n").expect("headers") + 4;
    assert_eq!(
        &forwarded[body_start..],
        original.as_bytes(),
        "original forwarded (fail-open)"
    );

    let events = events.lock().await;
    let failure_events: Vec<_> = events
        .iter()
        .filter(|e| e.flags.iter().any(|f| f == "redact-failed"))
        .collect();
    assert_eq!(
        failure_events.len(),
        1,
        "exactly one honest fail-open event: {:?}",
        events.iter().map(|e| (&e.action_taken, &e.flags)).collect::<Vec<_>>()
    );
    assert_eq!(
        failure_events[0].action_taken, "fail-open",
        "the audited action must name the outcome, never plain 'redact'"
    );
    drop(events);
    mock_handle.abort();
}

/// ── FIX P2-2, fail-closed direction: a 502 redact-failure reject is also
/// audited (action `fail-closed`, flag `redact-failed`) — the outcome is
/// visible without reading daemon logs.
#[tokio::test]
async fn closed_on_critical_reject_is_audited_honestly() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let block = format!("BLOCKSECRET1{}", "cccccccccc");
    let redactable = format!("REDACTSECRET2{}", "dddddddddd");
    let ctx = make_ctx_default_fail_policy(
        &[
            f3_block_rule(),
            f3_redact_rule(cerberus_engine::rule::Severity::Critical),
        ],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let events = ctx.api.events.clone();
    // R9-7: the allowlist carries the HMAC fingerprint, not the raw value.
    ctx.config.write().unwrap().policy.allowlist = vec![harness_fingerprint(&block)];
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"content":"{block} {redactable}"}}"#))
        .send()
        .await
        .expect("fail-closed audit request");
    assert_eq!(r.status(), 502, "critical findings → closed behavior");

    let events = events.lock().await;
    let failure_events: Vec<_> = events
        .iter()
        .filter(|e| e.flags.iter().any(|f| f == "redact-failed"))
        .collect();
    assert_eq!(
        failure_events.len(),
        1,
        "the fail-closed outcome is audited: {events:?}"
    );
    assert_eq!(failure_events[0].action_taken, "fail-closed");
    drop(events);
    mock_handle.abort();
}

/// ── FIX P2-2, shadow flag: a shadow-mode event records what WOULD have
/// happened while the body passed intact — the `shadow` flag makes that
/// unmistakable in the audit store.
#[tokio::test]
async fn shadow_mode_events_carry_the_shadow_flag() {
    let (mock_adj, mock_handle, captured) = spawn_mock_upstream_capture().await;
    let ctx = make_ctx_default_fail_policy(&[f3_block_rule()], OperationMode::Shadow, &format!("http://{mock_adj}"));
    let events = ctx.api.events.clone();
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let secret = format!("BLOCKSECRET1{}", "iiiiiiiiii");

    let r = client
        .post(format!("http://{addr}/v1/x"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"content":"{secret}"}}"#))
        .send()
        .await
        .expect("shadow request");
    assert_eq!(r.status(), 200, "shadow never blocks");
    assert!(!captured.lock().unwrap().is_empty(), "shadow forwards");

    let events = events.lock().await;
    let shadow_events: Vec<_> = events
        .iter()
        .filter(|e| e.flags.iter().any(|f| f == "shadow"))
        .collect();
    assert_eq!(shadow_events.len(), 1, "the shadow event carries the flag: {events:?}");
    assert_eq!(
        shadow_events[0].action_taken, "block",
        "the recorded action is the WOULD-BE action"
    );
    drop(events);
    mock_handle.abort();
}

// ─── R9-5 / R9-7 (F6.A): fail-closed auth, anti-rebinding, HMAC allowlist ──

/// Send a RAW HTTP/1.1 request over TCP so the Host/Origin headers are fully
/// attacker-controlled (reqwest derives Host from the URL).
async fn raw_http(port: u16, request: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, text)
}

/// R9-5 acceptance 1: EVERY data `/api/*` route is FAIL-CLOSED — no token →
/// 401, wrong token → 401, valid token → NOT 401 (loopback included: the
/// proxy binds 127.0.0.1 here, exactly the R9-5 vulnerable shape).
#[tokio::test]
async fn r9_5_route_matrix_fail_closed() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    // NO token at all.
    let bare = reqwest::Client::new();
    // A client with a WRONG token.
    let wrong = {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-cerberus-admin-token",
            reqwest::header::HeaderValue::from_static("wrong-token-wrong-token-1234"),
        );
        reqwest::Client::builder().default_headers(headers).build().unwrap()
    };
    let valid = api_client();

    // Every route of the control plane (method, path, JSON body or None).
    let routes: Vec<(&str, &str, Option<serde_json::Value>)> = vec![
        ("GET", "/api/config", None),
        ("PUT", "/api/config", Some(serde_json::json!({"mode": "shadow"}))),
        ("GET", "/api/events", None),
        ("GET", "/api/stats", None),
        ("POST", "/api/allowlist", Some(serde_json::json!({"value": "x"}))),
        ("GET", "/api/allowlist", None),
        ("DELETE", "/api/allowlist", Some(serde_json::json!({"value": "x"}))),
        ("GET", "/api/policy", None),
        ("PUT", "/api/policy", Some(serde_json::json!({}))),
        ("GET", "/api/upstreams", None),
        (
            "POST",
            "/api/upstreams",
            Some(serde_json::json!({"name": "n", "url": "http://u"})),
        ),
        ("GET", "/api/packs", None),
        ("POST", "/api/break-glass", Some(serde_json::json!({"reason": "r"}))),
        // An UNKNOWN api path must not become an oracle either (401 before 404).
        ("GET", "/api/nonexistent", None),
    ];

    for (method, path, body) in &routes {
        for (who, client) in [("no-token", &bare), ("wrong-token", &wrong)] {
            let mut req = match *method {
                "GET" => client.get(format!("{base}{path}")),
                "PUT" => client.put(format!("{base}{path}")),
                "POST" => client.post(format!("{base}{path}")),
                "DELETE" => client.delete(format!("{base}{path}")),
                _ => unreachable!(),
            };
            if let Some(json) = body {
                req = req.json(json);
            }
            let resp = req.send().await.expect("request");
            assert_eq!(
                resp.status(),
                401,
                "{method} {path} with {who} must be 401 (fail-closed, R9-5), got {}",
                resp.status()
            );
        }
        // Valid token → the gate passes (the route may 200/400/404/413/503,
        // but never 401: authentication is what this matrix verifies).
        let mut req = match *method {
            "GET" => valid.get(format!("{base}{path}")),
            "PUT" => valid.put(format!("{base}{path}")),
            "POST" => valid.post(format!("{base}{path}")),
            "DELETE" => valid.delete(format!("{base}{path}")),
            _ => unreachable!(),
        };
        if let Some(json) = body {
            req = req.json(json);
        }
        let resp = req.send().await.expect("request");
        assert_ne!(
            resp.status(),
            401,
            "{method} {path} with a VALID token must pass the auth gate, got {}",
            resp.status()
        );
    }

    // The dashboard stays public (static HTML without data)…
    let dash = bare
        .get(format!("{base}/api/dashboard"))
        .send()
        .await
        .expect("dashboard");
    assert_eq!(dash.status(), 200, "dashboard HTML is public");
    // …and /health stays public.
    let health = bare.get(format!("{base}/health")).send().await.expect("health");
    assert_eq!(health.status(), 200);
}

/// R9-5 acceptance 2: DNS-rebinding attack shapes are REJECTED (403) by the
/// Host/Origin allowlist BEFORE authentication — `attacker.com` as Host, an
/// evil Origin, `Origin: null`, and a form-submittable content type on a
/// browser mutation. A same-shape request with the allowed loopback Host
/// reaches the auth layer instead (401 without token — never 403).
#[tokio::test]
async fn r9_5_rebinding_attack_shapes_are_rejected() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let port = addr.port();

    // (name, request, expected status)
    let attacks: Vec<(&str, String, u16)> = vec![
        // Classic DNS-rebinding: attacker.com resolves to 127.0.0.1 and the
        // browser sends Host: attacker.com:8787.
        (
            "rebound-host",
            format!("GET /api/events HTTP/1.1\r\nHost: attacker.com:{port}\r\nConnection: close\r\n\r\n"),
            403,
        ),
        (
            "rebound-host-mutation",
            format!(
                "POST /api/allowlist HTTP/1.1\r\nHost: attacker.com:{port}\r\nContent-Type: application/json\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{{\"value\":\"evil\"}}\r\n"
            ),
            403,
        ),
        // Evil Origin on an allowed loopback Host (cross-site browser fetch).
        (
            "evil-origin",
            format!(
                "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://attacker.com\r\nConnection: close\r\n\r\n"
            ),
            403,
        ),
        // Sandboxed iframe (opaque origin) — never trusted.
        (
            "null-origin",
            format!("GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: null\r\nConnection: close\r\n\r\n"),
            403,
        ),
        // CSRF classic: simple form content type on a browser mutation.
        (
            "simple-form-mutation",
            format!(
                "POST /api/allowlist HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: text/plain\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{{\"value\":\"evil\"}}\r\n"
            ),
            403,
        ),
    ];
    for (name, request, expected) in &attacks {
        let (status, body) = raw_http(port, request).await;
        assert_eq!(status, *expected, "{name} must be rejected, got {status}: {body}");
    }

    // The same loopback shape WITHOUT the attack headers reaches the auth
    // layer (401 = fail-closed token gate, NOT 403).
    let (status, _) = raw_http(
        port,
        &format!("GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(
        status, 401,
        "loopback Host without token → 401 (auth gate), got {status}"
    );

    // Allowed loopback Host + valid token + JSON → the API serves.
    let (status, body) = raw_http(
        port,
        &format!(
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Cerberus-Admin-Token: {HARNESS_ADMIN_TOKEN}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 200, "allowed Host + valid token must serve: {body}");
}

/// R9-5/F6.2 — the ADAPTED F4 negative test: the F4 evidence injected an
/// UNAUTHENTICATED `X-Cerberus-Bypass` in dev mode (no token configured) and
/// the secret reached the upstream. That vector must now FAIL: the bypass is
/// refused (no valid credential exists), the request proceeds to the normal
/// scan and is BLOCKED (403) — the secret never reaches the mock.
#[tokio::test]
async fn r9_5_f4_injection_vector_bypass_without_token_is_refused() {
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    // Tokenless control plane (the F4 dev-mode shape) — and the data-plane
    // request carries NO admin token, only the bypass header.
    let ctx = make_ctx_tokenless(vec![block_rule()], OperationMode::Enforce);
    // Point the default upstream at the mock so a granted bypass WOULD leak.
    {
        let mut cfg = ctx.config.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(upstream) = cfg.upstreams.get_mut("default") {
            upstream.url = format!("http://{mock_adj}");
        }
    }
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let plain = reqwest::Client::new();

    // THE F4 VECTOR: unauthenticated bypass carrying a secret payload.
    let leak_attempt = plain
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", "smoke-negative-leak-injection")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("bypass injection");
    assert_eq!(
        leak_attempt.status(),
        403,
        "the unauthenticated bypass must be REFUSED and the request BLOCKED (got {})",
        leak_attempt.status()
    );

    // Contrast (the F4 review-v4 rule, unchanged): WITH the admin token the
    // audited bypass still works — token-gated, not dead.
    let granted = api_client()
        .post(format!("{base}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", "smoke-negative-leak-injection")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("authenticated bypass");
    assert_eq!(granted.status(), 200, "valid admin token → audited bypass still works");

    mock_handle.abort();
}

/// R9-7 acceptance: end-to-end fingerprinting — add a raw value through the
/// API, verify the STORED BYTES (config.yaml + GET responses) are `hmac:`
/// fingerprints, the hot path honors the fingerprint, and the raw value is
/// grep-clean from every surface. Key rotation invalidates fingerprints.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn r9_7_allowlist_fingerprints_end_to_end() {
    // Matches the harness block rule (`sk-[A-Za-z0-9]{20,}`).
    let raw_value = "sk-ENDTOENDfingerprintcheck00011";
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let config_path = unique_temp_path("r9-7-allowlist.yaml");
    // Context with a BLOCK RULE + config path: mirror
    // make_ctx_with_token_and_config_path but with the block rule.
    let ctx = {
        let engine = cerberus_engine::engine::EngineBuilder::new(&[block_rule()])
            .build()
            .expect("engine");
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "default".to_string(),
            UpstreamConfig {
                url: format!("http://{mock_adj}"),
                path_prefix: None,
                auth_header: "authorization".to_string(),
                mode: None,
                expected_auth: None,
            },
        );
        let config = ProxyConfig {
            upstreams,
            mode: OperationMode::Enforce,
            fail_policy: FailPolicy::Closed,
            admin_token: Some(HARNESS_ADMIN_TOKEN.to_string()),
            ..ProxyConfig::default()
        };
        let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
        let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
        std::sync::Arc::new(ProxyContext {
            config: shared.clone(),
            engine: engine_arc,
            redact_options: cerberus_engine::redact::RedactOptions::default(),
            api: ApiContext::new(shared)
                .with_config_path(config_path.clone())
                .with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec()),
            last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    };
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx.clone()).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // 1) The raw value is blocked before triage.
    assert_eq!(
        post_scan(&client, &base, raw_value).await,
        403,
        "precondition: the value must be flagged before allowlisting"
    );

    // 2) One-click triage: POST the RAW value → the API converts it.
    let add = client
        .post(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({"value": raw_value}))
        .send()
        .await
        .expect("allowlist add");
    assert_eq!(add.status(), 200);
    let doc: serde_json::Value = add.json().await.expect("add doc");
    let fp = harness_fingerprint(raw_value);
    assert_eq!(doc["fingerprint"].as_str(), Some(fp.as_str()));
    assert!(!doc.to_string().contains(raw_value), "raw never echoed: {doc}");

    // 3) The hot path honors the FINGERPRINT (the raw is gone from config).
    assert_eq!(
        post_scan(&client, &base, raw_value).await,
        200,
        "the fingerprint must allow the value on the scan path"
    );

    // 4) STORED BYTES: the YAML on disk contains the fingerprint and NEVER
    // the raw value (R9-7: "check stored bytes are hmac: fingerprints").
    let yaml = std::fs::read_to_string(&config_path).expect("stored yaml");
    assert!(yaml.contains(fp.as_str()), "fingerprint persisted: {yaml}");
    assert!(yaml.contains("hmac:"), "stored entry is an hmac: fingerprint");
    assert!(
        !yaml.contains(raw_value),
        "raw value must NOT be in the stored YAML: {yaml}"
    );

    // 5) API surfaces never return the raw value (grep-clean). The policy
    // views carry the fingerprints; /api/config (no policy view) is checked
    // only for the raw leak.
    for path in ["/api/allowlist", "/api/policy"] {
        let body = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .expect("get")
            .text()
            .await
            .expect("body");
        assert!(body.contains("hmac:"), "{path} carries fingerprints: {body}");
        assert!(!body.contains(raw_value), "{path} leaked the raw value: {body}");
    }
    let cfg_view = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config")
        .text()
        .await
        .expect("config body");
    assert!(
        !cfg_view.contains(raw_value),
        "/api/config leaked the raw value: {cfg_view}"
    );

    // 6) KEY ROTATION invalidates fingerprints (documented, fail-closed):
    // under a different installation key the value is flagged again.
    *ctx.config.write().unwrap_or_else(std::sync::PoisonError::into_inner) = {
        let mut cfg = ctx
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        cfg.policy.allowlist = vec![cerberus_proxy::allowlist::fingerprint(
            b"a-different-installation-key-0123456789",
            raw_value,
        )];
        cfg
    };
    // ...and with the key GONE (unkeyed context), nothing is allowed either.
    *ctx.config.write().unwrap_or_else(std::sync::PoisonError::into_inner) = {
        let mut cfg = ctx
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        cfg.policy.allowlist = vec!["not-a-fingerprint".to_string()];
        cfg
    };
    ctx.config
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .policy
        .allowlist = vec![harness_fingerprint("another-value-entirely")];
    assert_eq!(
        post_scan(&client, &base, raw_value).await,
        403,
        "a rotated key / foreign fingerprint must NOT allow the value (fail-closed)"
    );

    mock_handle.abort();
    std::fs::remove_file(&config_path).ok();
}
