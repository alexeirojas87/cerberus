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

fn local_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Build a `ProxyContext` manually (mirrors the pattern from proxy.rs unit test).
#[allow(clippy::needless_pass_by_value)]
fn make_ctx(rules: Vec<cerberus_engine::rule::Rule>, operation_mode: OperationMode) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(rules, operation_mode, "http://127.0.0.1:9999", FailPolicy::Closed, None)
}

/// Variante con upstream configurable (para integraciones con mock real).
#[allow(clippy::needless_pass_by_value)]
fn make_ctx_with_url(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    upstream_url: &str,
) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(rules, operation_mode, upstream_url, FailPolicy::Closed, None)
}

/// Variante con control plane protegido (`admin_token`) — fix P1 admin.
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

/// Variante con `admin_token` **y** persistencia YAML (review v6.1): hace
/// falta para comprobar que un PUT que preserva el token también lo persiste,
/// y que un fallo de escritura no muta la config viva.
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
        api: ApiContext::new(shared).with_config_path(config_path),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Variante con política de fallo del motor configurable — fix P1 `fail_open`.
fn make_ctx_with_fail_policy(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    upstream_url: &str,
    fail_policy: FailPolicy,
) -> std::sync::Arc<ProxyContext> {
    make_ctx_opts(rules, operation_mode, upstream_url, fail_policy, None)
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
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: operation_mode,
        fail_policy,
        admin_token: admin_token.map(ToString::to_string),
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

/// Variante con persistencia YAML fijada (review v6 F6): la Config API escribe
/// a `config_path` en cada mutación (PUT /api/config, CRUD de upstreams).
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
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: operation_mode,
        fail_policy: FailPolicy::Closed,
        admin_token: None,
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared).with_config_path(config_path),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Contexto real de política: conserva las reglas base de packs, aplica la
/// política restaurada del YAML y conecta el mismo `EngineControl` al API y
/// al dataplane.
fn make_policy_ctx(
    base_rules: Vec<cerberus_engine::rule::Rule>,
    config: ProxyConfig,
    config_path: std::path::PathBuf,
) -> std::sync::Arc<ProxyContext> {
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
            .with_engine(control),
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

    let resp = reqwest::get(&format!("http://{addr}/health"))
        .await
        .expect("health request");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_api_config_returns_json() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let resp = reqwest::get(&format!("http://{addr}/api/config"))
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

    let resp = reqwest::get(&format!("http://{addr}/api/events"))
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

    let resp = reqwest::get(&format!("http://{addr}/api/stats"))
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

    let resp = reqwest::Client::new()
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

    let resp = reqwest::Client::new()
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
    let _block_resp = reqwest::Client::new()
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(r#"{"content":"sk-abcDEFghijklmnopqrstuvwxyz1234"}"#)
        .send()
        .await
        .expect("trigger block");

    // Check events
    let events_resp = reqwest::get(&format!("http://{addr}/api/events"))
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

    let resp = reqwest::Client::new()
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

/// Mock upstream mínimo: acepta una request y responde JSON 200.
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

/// Mock upstream que devuelve un JSON con el request crudo recibido (headers
/// incluidos) para poder aseverar qué headers NO llegaron al proveedor.
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
    // P0-5: PUT /api/config debe cambiar el modo REAL del proxy.
    let (mock_addr, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_addr}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");

    let client = reqwest::Client::new();
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
    // P1-7: header X-Cerberus-Bypass debe dejar pasar aunque haya finder de block.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    // Sin bypass, 403.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .body(BLOCK_BODY)
        .send()
        .await
        .expect("no bypass");
    assert_eq!(resp.status(), 403);

    // Con bypass, pasa al upstream (200).
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
    // P0-5: la allowlist debe filtrar en la ruta de escaneo real.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

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
    // Con admin_token configurado /health queda abierto pero /api/* exige auth.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        "s3krit",
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");

    let ok = reqwest::get(&format!("{base}/health")).await.expect("health");
    assert_eq!(ok.status(), 200, "health is exempt from admin auth");

    let client = reqwest::Client::new();
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
    let client = reqwest::Client::new();

    // PUT /api/config sin token → 401
    let denied = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"mode": "shadow"}))
        .send()
        .await
        .expect("put without token");
    assert_eq!(denied.status(), 401, "PUT config must require admin token");

    // PUT /api/config con token válido → 200
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
    // El mock responde 200 a cualquier path/body recibido.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_fail_policy(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        FailPolicy::Open,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");

    let client = reqwest::Client::new();
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

    let client = reqwest::Client::new();
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
    // El motivo del bypass con secreto literal `sk-...` debe quedar hasheado,
    // jamás crudo en /api/events.
    let secret_reason = "motivo de emergencia sk-KEEPTHISSECRET1234567890abcdefX";
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");

    let client = reqwest::Client::new();
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
    // fix P1 #4: una respuesta del upstream que supera `max_body_bytes` debe
    // devolver 502 JSON y NO derribar la conexión con un Err.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Limitar el body a 8 bytes (la respuesta del mock {"ok":true} la supera).
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
    // Review v4 #1: el arranque en 0.0.0.0 sin admin token debe FALLAR con
    // error (un compose con `change-me` < 24 chars tampoco arranca).
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let non_loop: SocketAddr = "0.0.0.0:0".parse().expect("addr");
    let err = spawn_proxy(non_loop, ctx).await.unwrap_err().to_string();
    assert!(err.contains("admin token"), "got: {err}");
}

#[tokio::test]
async fn test_admin_token_header_not_forwarded_to_upstream() {
    // Review v4 #2: `X-Cerberus-Admin-Token` nunca debe llegar al upstream.
    let (echo_addr, echo_handle) = spawn_mock_upstream_echo().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{echo_addr}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-admin-token", ADMIN_TOKEN)
        .header("x-custom-keep", "keepme")
        .body(r#"{"content":"hola"}"#)
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
    // Review v4 #2: el bypass del data plane se honra SOLO vía
    // `X-Cerberus-Admin-Token`; `Authorization: Bearer <admin>` se IGNORA
    // (warning) para no sustituir la API key del proveedor.
    let (echo_addr, echo_handle) = spawn_mock_upstream_echo().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{echo_addr}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = reqwest::Client::new();

    // Bypass vía Authorization → ignorado → 403 (block).
    let blocked = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", "emergencia de prueba")
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

    // Bypass vía X-Cerberus-Admin-Token → honrado → 200.
    let passed = client
        .post(format!("http://{addr}/test"))
        .header("content-type", "application/json")
        .header("x-cerberus-bypass", "emergencia de prueba")
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
    // Review v5 F6: el dashboard es HTML estático PÚBLICO sin datos; con admin
    // token configurado se sirve SIN auth y NUNCA incrusta el token en el DOM.
    // Las rutas de datos (/api/*) siguen exigiendo auth (401 sin token).
    let (mock_addr, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        vec![block_rule()],
        OperationMode::Enforce,
        &format!("http://{mock_addr}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // Dashboard sin auth → 200 HTML y sin token en el DOM.
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

    // Ruta de datos sin token → 401.
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
    // Review v5 F6: /api/stats?provider=X resume solo los eventos de X.
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

    let stats = reqwest::get(&format!("http://{addr}/api/stats?provider=openai"))
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
    // Review v4 #4: el control plane rechaza cuerpos > 1 MiB con 413, tanto
    // en PUT /api/config como en POST /api/allowlist.
    let (mock_addr, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(Vec::new(), OperationMode::Enforce, &format!("http://{mock_addr}"));
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

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
        .json(&serde_json::json!({ "value": "algo-sin-secreto" }))
        .send()
        .await
        .expect("small api body");
    assert_eq!(small.status(), 200, "small allowlist entry must succeed");
    mock_handle.abort();
}

#[tokio::test]
async fn test_hot_reload_swaps_engine_without_restart() {
    // F7 / review v5: el proxy debe cambiar de reglas SIN reiniciar cuando se
    // sustituye el engine activo bajo el `RwLock`. Este test:
    //   1. arranca el proxy con un engine limpio → el marker NO se bloquea;
    //   2. bajo el lock del ctx se SWAPA el engine a uno con regla de block
    //      para el marker (lo que hace el worker de packs del daemon);
    //   3. el MISMO proxy en marcha ahora devuelve 403 para ese marker.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let _ = mock_adj;
    let ctx = make_ctx_with_url(Vec::new(), OperationMode::Enforce, "https://invalid-upstream");
    let proxy = spawn_proxy(local_addr(0), ctx.clone()).await.expect("spawn");
    let base = format!("http://{}", proxy.0);
    let client = reqwest::Client::new();
    let marker = "HOTRELOAD_SIGNAL_VAL";

    // 1) engine base (sin reglas) → el marker NO bloquea (va al upstream/mock).
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
        "sin pack instalado el marker debe pasar (got {})",
        passthrough.status()
    );

    // 2) swap del engine activo bajo el lock (worker pack install). El guard se
    // libera explícitamente ANTES del siguiente await (Send-safe, clippy).
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

    // 3) el MISMO proxy, SIN reiniciar, ahora bloquea el marker.
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
        "hot-reload: tras swap el proxy debe bloquear el marker (got {})",
        blocked.status()
    );
    mock_handle.abort();
}

#[tokio::test]
async fn config_get_never_leaks_admin_token() {
    // Review v6 F6: GET /api/config debe redactar el admin_token; se expone
    // `admin_token_configured: true` pero NUNCA el valor.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        vec![],
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Sin token → 401 (el config expone datos del control plane).
    let denied = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get config no token");
    assert_eq!(denied.status(), 401, "config must require auth when token set");

    // Con token válido → 200, y el valor del token NO aparece.
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
    // Review v6 F6, requisito 1: PUT /api/config persiste la config compartida
    // a YAML en `ApiContext.config_path` (escritura atómica). El YAML escrito
    // debe contener los campos de la config (mode).
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
    let client = reqwest::Client::new();

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
async fn upstream_add_list_delete() {
    // Review v6 F6, requisito 3: CRUD de upstreams vía GET/POST/DELETE.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_url(Vec::new(), OperationMode::Enforce, &format!("http://{mock_adj}"));
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Lista inicial: solo el upstream por defecto.
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

    // Alta.
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

    // Aparece en la lista.
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

    // Baja.
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
    // Review v6 F6, requisito 5: el CRUD de upstreams es parte del control
    // plane y DEBE exigir auth cuando hay admin token configurado.
    let (mock_adj, mock_handle) = spawn_mock_upstream().await;
    let ctx = make_ctx_with_token(
        Vec::new(),
        OperationMode::Enforce,
        &format!("http://{mock_adj}"),
        ADMIN_TOKEN,
    );
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

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

    // Con token válido el DELETE responde 404 (no existe 'x' en la config),
    // probando que la ruta atraviesa el gate y responde como tal.
    let authed = client
        .delete(format!("{base}/api/upstreams/x"))
        .header("x-cerberus-admin-token", ADMIN_TOKEN)
        .send()
        .await
        .expect("delete authed");
    assert_ne!(authed.status(), 401, "with token the route must not be 401");
    mock_handle.abort();
}

// ─── Review v6.1: config como DTO, transaccionalidad y F6 ────────────────

/// Token de 28 bytes (≥ `ADMIN_TOKEN_MIN_BYTES`), válido en no-loopback.
const STRONG_ADMIN_TOKEN: &str = "correct-horse-battery-stapl0";

/// Requisito principal de la review v6.1: un ciclo HTTP real GET → PUT no
/// puede perder el admin token, porque el GET no lo revela y el PUT lo omite.
/// Tras el PUT, una petición SIN token debe seguir en 401.
#[tokio::test]
async fn config_get_then_put_over_http_preserves_the_admin_token() {
    let config_path = std::env::temp_dir().join("cerberus_v61_get_put_preserves.yaml");
    std::fs::remove_file(&config_path).ok();
    let ctx =
        make_ctx_with_token_and_config_path("http://127.0.0.1:9999", Some(STRONG_ADMIN_TOKEN), config_path.clone());
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // 1) GET autenticado: el valor del token NO viaja; sí el booleano.
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
    assert!(cfg.get("admin_token").is_none(), "no debe existir la clave: {text}");
    assert_eq!(cfg["admin_token_configured"].as_bool(), Some(true), "{text}");

    // 2) PUT reenviando el body del GET (que NO trae el token) + un cambio.
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

    // 3) El cambio se aplicó...
    let after: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .header("x-cerberus-admin-token", STRONG_ADMIN_TOKEN)
        .send()
        .await
        .expect("get after")
        .json()
        .await
        .expect("parse after");
    assert_eq!(after["mode"].as_str(), Some("shadow"), "el patch se aplicó");
    assert_eq!(after["admin_token_configured"].as_bool(), Some(true));

    // 4) ...y el token SIGUE exigiéndose: sin token, 401 (no dev mode).
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
    assert_eq!(denied_put.status(), 401, "PUT sin token sigue en 401");

    // 5) El YAML persistido tampoco pierde el token (el daemon lo relee).
    let yaml = std::fs::read_to_string(&config_path).expect("config persisted");
    assert!(yaml.contains(STRONG_ADMIN_TOKEN), "token must persist to YAML: {yaml}");
    assert!(yaml.contains("shadow"), "{yaml}");
    std::fs::remove_file(&config_path).ok();
}

/// Adversarial: `admin_token_configured` es de sólo lectura. Mandarlo en
/// `false` no puede apagar la autenticación.
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
    let client = reqwest::Client::new();

    let put = client
        .put(format!("{base}/api/config"))
        .header("x-cerberus-admin-token", STRONG_ADMIN_TOKEN)
        .json(&serde_json::json!({"admin_token_configured": false}))
        .send()
        .await
        .expect("put flag");
    assert_eq!(put.status(), 200, "el campo se acepta y se ignora");

    let denied = client
        .get(format!("{base}/api/config"))
        .send()
        .await
        .expect("get without token");
    assert_eq!(denied.status(), 401, "auth must still be enforced");
}

/// La API no puede persistir una config que el daemon rechazaría al arrancar:
/// `listen` no-loopback exige token ≥ 24 bytes. Y al rechazarla, la config
/// viva no cambia.
#[tokio::test]
async fn put_config_rejects_public_listen_without_a_strong_token() {
    let config_path = std::env::temp_dir().join("cerberus_v61_public_listen.yaml");
    std::fs::remove_file(&config_path).ok();
    let ctx = make_ctx_with_token_and_config_path("http://127.0.0.1:9999", None, config_path.clone());
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Sin token y listen público → 400 (el daemon no arrancaría así).
    let denied = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"listen": "0.0.0.0:8080"}))
        .send()
        .await
        .expect("put public listen");
    assert_eq!(denied.status(), 400, "must refuse to open the control plane");
    let text = denied.text().await.unwrap_or_default();
    assert!(text.contains("non-loopback"), "{text}");

    // Token corto: también 400.
    let short = client
        .put(format!("{base}/api/config"))
        .json(&serde_json::json!({"listen": "0.0.0.0:8080", "admin_token": "change-me"}))
        .send()
        .await
        .expect("put short token");
    assert_eq!(short.status(), 400, "short token must be refused");

    // Nada se aplicó en memoria ni se escribió a disco.
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
    assert_eq!(cfg["admin_token_configured"].as_bool(), Some(false));
    assert!(!config_path.exists(), "a rejected patch must not write the YAML");

    // Con token fuerte, el mismo cambio de listen SÍ pasa (requires_restart).
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

/// Persistencia transaccional desde la perspectiva en memoria: si el YAML no
/// se puede escribir, la config viva queda EXACTAMENTE como estaba.
#[tokio::test]
async fn put_config_persist_failure_leaves_the_live_config_untouched() {
    let unwritable = std::path::PathBuf::from("/nonexistent-cerberus-dir-v61/config.yaml");
    let ctx = make_ctx_with_token_and_config_path("http://127.0.0.1:9999", None, unwritable);
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

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

/// F6: overlay de política (categorías + reglas propias) por HTTP real.
#[tokio::test]
async fn policy_categories_and_rules_round_trip() {
    let ctx = make_ctx_with_url(vec![], OperationMode::Enforce, "http://127.0.0.1:9999");
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

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
        "sin configuración explícita se hereda la acción declarada por regla: {pol}"
    );
    assert_eq!(pol["valid_actions"][0].as_str(), Some("allow"));

    // Fijar acción por categoría y override por regla.
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
        "patch parcial preserva ausencia"
    );

    // `null` borra la entrada.
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

    // Acción inválida → 400 y NADA se aplica.
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
        "un patch inválido no aplica ninguna de sus entradas: {after}"
    );
}

/// F6: triage de falsos positivos — añadir, listar y quitar de la allowlist.
#[tokio::test]
async fn allowlist_add_list_and_remove() {
    let ctx = make_ctx_with_url(vec![], OperationMode::Enforce, "http://127.0.0.1:9999");
    let (addr, _handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

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

    let listed: serde_json::Value = client
        .get(format!("{base}/api/allowlist"))
        .send()
        .await
        .expect("get allowlist")
        .json()
        .await
        .expect("parse");
    assert_eq!(listed[0].as_str(), Some("sk-EXAMPLE-do-not-flag"));

    // La allowlist también sale en el documento de política (una sola vista).
    let pol: serde_json::Value = client
        .get(format!("{base}/api/policy"))
        .send()
        .await
        .expect("get policy")
        .json()
        .await
        .expect("parse");
    assert_eq!(pol["allowlist"][0].as_str(), Some("sk-EXAMPLE-do-not-flag"));

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

    // Quitar algo que no está → 404.
    let missing = client
        .delete(format!("{base}/api/allowlist"))
        .json(&serde_json::json!({"value": "nope"}))
        .send()
        .await
        .expect("delete missing");
    assert_eq!(missing.status(), 404);
}

/// El overlay de política es parte del control plane: exige token.
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
    let client = reqwest::Client::new();

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

/// Fix v6.1: prueba HTTP + dataplane del ciclo completo before/after/reopen.
/// La regla base representa un pack ya activo; debe sobrevivir al hot-reload
/// y al reopen, mientras la regla custom y la allowlist se restauran del YAML.
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
    let client = reqwest::Client::new();

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
    assert_eq!(reopened.policy.allowlist, vec!["CUSTOM-1234".to_string()]);

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

/// Wire v2 se prueba contra el handler HTTP real: los bytes llegan al worker;
/// la forma v1 por path se rechaza antes del worker aunque el path apunte a un
/// pack válido en el filesystem visible por el proceso servidor.
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
                | cerberus_proxy::api::PackCommand::List { reply } => {
                    let _ = reply.send(Err("unexpected command".to_string()));
                }
            }
        }
    });

    let engine = cerberus_engine::engine::EngineBuilder::new(&[])
        .build()
        .expect("engine");
    let config = ProxyConfig::with_upstream("default", "http://127.0.0.1:9999");
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let live = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    let ctx = std::sync::Arc::new(ProxyContext {
        config: shared.clone(),
        engine: live,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api: ApiContext::new(shared).with_pack_worker(tx),
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    });
    let (addr, proxy_handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
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

/// La CSP viaja en la CABECERA (para que `frame-ancestors` aplique) y sin
/// `unsafe-inline`: el bloque inline servido se autoriza por su sha256.
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

    // El dashboard es HTML público: se sirve sin token (no lleva datos).
    let resp = reqwest::get(format!("{base}/api/dashboard"))
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
