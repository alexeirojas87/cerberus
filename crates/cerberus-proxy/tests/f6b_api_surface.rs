//! F6.B — control-plane surface tests for the Appendix B API additions.
//!
//! Drives the REAL proxy (`spawn_proxy`, same pattern as `smoke_harness.rs`)
//! over HTTP and proves each new route: `POST /api/packs/enable|disable|
//! update` (worker commands), `POST /api/reload`, `POST /api/scan`,
//! `GET /ui` redirect, and the `tool`/`since` event filters (R9-6 inverse
//! finding). Auth semantics from F6.A are preserved: every data route 401s
//! without the admin token.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use cerberus_proxy::api::ApiContext;
use cerberus_proxy::config::{FailPolicy, OperationMode, ProxyConfig, UpstreamConfig};
use cerberus_proxy::proxy::{spawn_proxy, ProxyContext};

const HARNESS_ADMIN_TOKEN: &str = "harness-admin-token-0123456789abcdef";
const HARNESS_INSTALLATION_KEY: &[u8] = b"harness-installation-key-0123456789abcdef";

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

fn raw_client() -> reqwest::Client {
    reqwest::Client::new()
}

fn local_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Build a `ProxyContext` with the given rules/mode and (optionally) a pack
/// worker channel wired into the API context.
fn make_ctx_with_worker(
    rules: Vec<cerberus_engine::rule::Rule>,
    operation_mode: OperationMode,
    worker_tx: Option<tokio::sync::mpsc::Sender<cerberus_proxy::api::PackCommand>>,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(&rules).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            url: "http://127.0.0.1:9999".to_string(),
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
        admin_token: Some(HARNESS_ADMIN_TOKEN.to_string()),
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    let mut api = ApiContext::new(shared.clone())
        .with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec())
        // The daemon wires the EngineControl so `/api/scan` and the policy
        // routes use the LIVE engine — mirror that here.
        .with_engine(cerberus_proxy::detection_policy::EngineControl::new(
            engine_arc.clone(),
            rules,
            Some(HARNESS_INSTALLATION_KEY.to_vec()),
        ));
    if let Some(tx) = worker_tx {
        api = api.with_pack_worker(tx);
    }
    std::sync::Arc::new(ProxyContext {
        config: shared,
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api,
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

fn make_ctx(rules: Vec<cerberus_engine::rule::Rule>, operation_mode: OperationMode) -> std::sync::Arc<ProxyContext> {
    make_ctx_with_worker(rules, operation_mode, None)
}

/// Like [`make_ctx`], but the `ApiContext` carries `config_path` + an
/// `EngineControl` (the daemon wiring) so `POST /api/reload` can re-read
/// the YAML from disk.
#[allow(clippy::needless_pass_by_value)]
fn make_ctx_with_config_path(
    rules: Vec<cerberus_engine::rule::Rule>,
    in_memory_mode: OperationMode,
    config_path: std::path::PathBuf,
) -> std::sync::Arc<ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(&rules).build().unwrap();
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "openai".to_string(),
        UpstreamConfig {
            url: "https://api.openai.com".to_string(),
            path_prefix: None,
            auth_header: "authorization".to_string(),
            mode: None,
            expected_auth: None,
        },
    );
    let config = ProxyConfig {
        upstreams,
        mode: in_memory_mode,
        fail_policy: FailPolicy::Closed,
        admin_token: Some(HARNESS_ADMIN_TOKEN.to_string()),
        ..ProxyConfig::default()
    };
    let shared = std::sync::Arc::new(std::sync::RwLock::new(config));
    let engine_arc = std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(engine)));
    let engine_control = cerberus_proxy::detection_policy::EngineControl::new(
        engine_arc.clone(),
        vec![],
        Some(HARNESS_INSTALLATION_KEY.to_vec()),
    );
    let api = ApiContext::new(shared.clone())
        .with_audit_hash_key(HARNESS_INSTALLATION_KEY.to_vec())
        .with_config_path(config_path)
        .with_engine(engine_control);
    std::sync::Arc::new(ProxyContext {
        config: shared,
        engine: engine_arc,
        redact_options: cerberus_engine::redact::RedactOptions::default(),
        api,
        last_upstream: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}

/// A rule that blocks `sk-`-prefixed tokens.
fn openai_rule() -> Vec<cerberus_engine::rule::Rule> {
    match cerberus_engine::loader::load_rules_from_str(
        r#"[{"flag":"secret.openai_api_key","category":"secrets","severity":"high","action":"block","patterns":["sk-[A-Za-z0-9]{20,}"]}]"#,
    ) {
        Ok(rules) if !rules.is_empty() => rules,
        _ => panic!("openai rule must load"),
    }
}

// Keep the compiler honest about the (unused) fallback helper above.

/// ── Events: tool + since filters (R9-6 inverse finding) ──────────────────
#[tokio::test]
async fn events_filter_by_tool_and_since() {
    let ctx = make_ctx(openai_rule(), OperationMode::Enforce);
    let (addr, handle) = spawn_proxy(local_addr(0), ctx.clone()).await.expect("spawn");
    let url = format!("http://{addr}/api/events");

    // Two events from different tools at different times.
    let mut old = sample_event("claude-code", "openai", "secret.openai_api_key", "block");
    old.ts_unix = 1_000_000; // ancient
    let fresh = sample_event("opencode", "openai", "secret.openai_api_key", "redact");
    // Record through the SAME ApiContext the proxy serves.
    cerberus_proxy::api::record_event(&ctx.api, old).await;
    cerberus_proxy::api::record_event(&ctx.api, fresh.clone()).await;

    let client = api_client();
    // tool=opencode returns only the fresh event.
    let resp = client.get(format!("{url}?tool=opencode")).send().await.expect("get");
    assert_eq!(resp.status(), 200);
    let events: serde_json::Value = resp.json().await.expect("json");
    let arr = events.as_array().expect("array");
    assert_eq!(arr.len(), 1, "tool filter: {arr:?}");
    assert_eq!(arr[0]["tool"], "opencode");

    // since (unix seconds) excludes the ancient event.
    let now_minus = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("clock fits i64")
        - 60;
    let resp = client
        .get(format!("{url}?since={now_minus}"))
        .send()
        .await
        .expect("get");
    let events: serde_json::Value = resp.json().await.expect("json");
    let arr = events.as_array().expect("array");
    assert_eq!(arr.len(), 1, "since filter: {arr:?}");
    assert_eq!(arr[0]["tool"], "opencode");

    // tool + provider combined.
    let resp = client
        .get(format!("{url}?tool=claude-code&provider=openai"))
        .send()
        .await
        .expect("get");
    let events: serde_json::Value = resp.json().await.expect("json");
    let arr = events.as_array().expect("array");
    assert_eq!(arr.len(), 1, "combined filter: {arr:?}");
    assert_eq!(arr[0]["tool"], "claude-code");

    // Auth gate still applies (F6.A): no token → 401.
    let resp = raw_client().get(&url).send().await.expect("get");
    assert_eq!(resp.status(), 401, "events must stay auth-gated");

    handle.abort();
}

/// ── POST /api/scan: dry-run, no persistence, hashes only ─────────────────
#[tokio::test]
async fn api_scan_dry_runs_and_persists_nothing() {
    let ctx = make_ctx(openai_rule(), OperationMode::Enforce);
    let (addr, handle) = spawn_proxy(local_addr(0), ctx.clone()).await.expect("spawn");
    let client = api_client();

    // Clean baseline (0 events), scan, still 0 events.
    let before: serde_json::Value = client
        .get(format!("http://{addr}/api/events"))
        .send()
        .await
        .expect("events")
        .json()
        .await
        .expect("json");
    assert_eq!(before.as_array().map_or(0, std::vec::Vec::len), 0);

    let secret = "sk-abcdef0123456789abcdef01";
    let resp = client
        .post(format!("http://{addr}/api/scan"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "text": format!("use key {secret}") }).to_string())
        .send()
        .await
        .expect("scan");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["action"], "block", "{body}");
    let flags = body["flags"].as_object().expect("flags map");
    assert!(
        flags.contains_key("secret.openai_api_key"),
        "the rule must fire (entropy may also fire): {body}"
    );
    // NO-LEAK: the raw secret NEVER comes back.
    let body_text = body.to_string();
    assert!(!body_text.contains(secret), "raw secret echoed back: {body_text}");

    // Shadow mode: same scan reports warn (nothing applied).
    {
        let mut live = ctx.config.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        live.mode = OperationMode::Shadow;
    }
    let resp = client
        .post(format!("http://{addr}/api/scan"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "text": format!("use key {secret}") }).to_string())
        .send()
        .await
        .expect("scan");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["action"], "warn", "shadow reports without applying: {body}");

    // The dry-run did NOT persist an event.
    let after: serde_json::Value = client
        .get(format!("http://{addr}/api/events"))
        .send()
        .await
        .expect("events")
        .json()
        .await
        .expect("json");
    assert_eq!(
        after.as_array().map_or(0, std::vec::Vec::len),
        0,
        "scan must not record events"
    );

    // Bad body → 400.
    let resp = client
        .post(format!("http://{addr}/api/scan"))
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .expect("scan");
    assert_eq!(resp.status(), 400);

    // Auth gate.
    let resp = raw_client()
        .post(format!("http://{addr}/api/scan"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("scan");
    assert_eq!(resp.status(), 401);

    handle.abort();
}

/// ── POST /api/packs/enable|disable|update: worker command wiring ─────────
#[tokio::test]
async fn pack_enable_disable_update_reach_the_worker() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<cerberus_proxy::api::PackCommand>(8);
    let worker = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                cerberus_proxy::api::PackCommand::Enable { name, reply } => {
                    let _ = reply.send(Ok(format!("enabled {name}")));
                }
                cerberus_proxy::api::PackCommand::Disable { name, reply } => {
                    let _ = reply.send(Ok(format!("disabled {name}")));
                }
                cerberus_proxy::api::PackCommand::Update { reply } => {
                    let _ = reply.send(Ok("2/2 verified".to_string()));
                }
                _ => {}
            }
        }
    });
    let ctx = make_ctx_with_worker(vec![], OperationMode::Enforce, Some(tx));
    let (addr, handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    let resp = client
        .post(format!("http://{addr}/api/packs/enable"))
        .header("content-type", "application/json")
        .body(r#"{"name":"aws"}"#)
        .send()
        .await
        .expect("enable");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["message"], "enabled aws", "{body}");

    let resp = client
        .post(format!("http://{addr}/api/packs/disable"))
        .header("content-type", "application/json")
        .body(r#"{"name":"aws"}"#)
        .send()
        .await
        .expect("disable");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["message"], "disabled aws", "{body}");

    let resp = client
        .post(format!("http://{addr}/api/packs/update"))
        .send()
        .await
        .expect("update");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["message"], "2/2 verified", "{body}");

    // F6.B attempt 2 (security P2-1): the successful mutations are AUDITED —
    // the events feed shows the honest action names with tool
    // `control-plane`.
    let events: serde_json::Value = client
        .get(format!("http://{addr}/api/events?tool=control-plane"))
        .send()
        .await
        .expect("events")
        .json()
        .await
        .expect("json");
    let events_str = events.to_string();
    for action in ["pack-enable", "pack-disable", "pack-update"] {
        assert!(
            events_str.contains(action),
            "the {action} mutation must be audited: {events_str}"
        );
    }

    // Bad body → 400 (worker never sees it).
    let resp = client
        .post(format!("http://{addr}/api/packs/enable"))
        .header("content-type", "application/json")
        .body(r#"{"nme":"aws"}"#)
        .send()
        .await
        .expect("enable");
    assert_eq!(resp.status(), 400);

    // Auth gate on the new routes (F6.A preserved).
    let resp = raw_client()
        .post(format!("http://{addr}/api/packs/enable"))
        .header("content-type", "application/json")
        .body(r#"{"name":"aws"}"#)
        .send()
        .await
        .expect("enable");
    assert_eq!(resp.status(), 401);
    let resp = raw_client()
        .post(format!("http://{addr}/api/packs/update"))
        .send()
        .await
        .expect("update");
    assert_eq!(resp.status(), 401);
    let resp = raw_client()
        .post(format!("http://{addr}/api/packs/disable"))
        .send()
        .await
        .expect("disable");
    assert_eq!(resp.status(), 401);

    worker.abort();
    handle.abort();
}

/// ── GET /ui: public 302 to the dashboard (B.6 documented URL) ────────────
#[tokio::test]
async fn ui_path_redirects_to_the_dashboard() {
    let ctx = make_ctx(vec![], OperationMode::Enforce);
    let (addr, handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    // No token: /ui stays PUBLIC (no data served). Redirects are NOT
    // followed so we can assert the 302 itself.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("no-redirect client");
    let resp = client.get(format!("http://{addr}/ui")).send().await.expect("get");
    assert_eq!(resp.status(), 302, "/ui must redirect");
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/api/dashboard")
    );
    // And the redirect target (with the default client) serves the HTML.
    let resp = raw_client().get(format!("http://{addr}/ui")).send().await.expect("get");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.text().await.expect("body").contains("Cerberus"),
        "dashboard HTML served"
    );
    handle.abort();
}

/// ── POST /api/reload: hot-reload of the on-disk config ───────────────────
#[tokio::test]
async fn reload_applies_on_disk_config_without_restart() {
    let dir = std::env::temp_dir().join(format!(
        "cerberus-f6b-reload-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let config_path = dir.join("config.yaml");
    // On-disk config: SHADOW. It carries the SAME admin token (as any real
    // daemon config does): `reload` applies the file EXACTLY — a file
    // without `admin_token` would close the control plane (fail-closed) and
    // require a restart, which is the documented behavior.
    std::fs::write(
        &config_path,
        format!(
            "listen: 127.0.0.1:8787\nmode: shadow\nadmin_token: {HARNESS_ADMIN_TOKEN}\nupstreams:\n  openai:\n    url: https://api.openai.com\n"
        ),
    )
    .expect("write");

    // Boot with ENFORCE in memory (disk says shadow) — daemon wiring present.
    let ctx = make_ctx_with_config_path(vec![], OperationMode::Enforce, config_path.clone());
    let (addr, handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    // Live mode before reload: enforce (from the boot config).
    let cfg: serde_json::Value = client
        .get(format!("http://{addr}/api/config"))
        .send()
        .await
        .expect("cfg")
        .json()
        .await
        .expect("json");
    assert_eq!(cfg["mode"], "enforce", "{cfg}");

    // On-disk config says shadow → reload flips it live.
    let resp = client
        .post(format!("http://{addr}/api/reload"))
        .send()
        .await
        .expect("reload");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["status"], "ok", "{body}");

    let cfg: serde_json::Value = client
        .get(format!("http://{addr}/api/config"))
        .send()
        .await
        .expect("cfg")
        .json()
        .await
        .expect("json");
    assert_eq!(cfg["mode"], "shadow", "reload must apply the disk config: {cfg}");

    // A broken on-disk config is REJECTED and does NOT touch the live one.
    std::fs::write(&config_path, "listen: [not: valid\n").expect("write broken");
    let resp = client
        .post(format!("http://{addr}/api/reload"))
        .send()
        .await
        .expect("reload");
    assert_eq!(resp.status(), 400, "broken config must be a 400");
    let cfg: serde_json::Value = client
        .get(format!("http://{addr}/api/config"))
        .send()
        .await
        .expect("cfg")
        .json()
        .await
        .expect("json");
    assert_eq!(cfg["mode"], "shadow", "live config unchanged after failed reload");

    // A file that REMOVES the admin token is rejected (anti-lockout: the
    // control plane must never silently go from secured to closed).
    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:8787\nmode: enforce\nupstreams:\n  openai:\n    url: https://api.openai.com\n",
    )
    .expect("write tokenless");
    let resp = client
        .post(format!("http://{addr}/api/reload"))
        .send()
        .await
        .expect("reload");
    assert_eq!(resp.status(), 400, "token-removing reload must be rejected");
    let cfg: serde_json::Value = client
        .get(format!("http://{addr}/api/config"))
        .send()
        .await
        .expect("cfg")
        .json()
        .await
        .expect("json");
    assert_eq!(
        cfg["mode"], "shadow",
        "live config unchanged after rejected token-removal"
    );

    // Auth gate.
    let resp = raw_client()
        .post(format!("http://{addr}/api/reload"))
        .send()
        .await
        .expect("reload");
    assert_eq!(resp.status(), 401);

    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

/// ── Route table sanity (the parity test's API leg) ───────────────────────
#[test]
fn known_api_routes_contains_the_f6b_surface() {
    let routes = cerberus_proxy::api::known_api_routes();
    for (method, path) in [
        ("POST", "/api/packs/enable"),
        ("POST", "/api/packs/disable"),
        ("POST", "/api/packs/update"),
        ("POST", "/api/reload"),
        ("POST", "/api/scan"),
        ("GET", "/ui"),
        ("GET", "/api/events"),
        ("GET", "/api/stats"),
        ("POST", "/api/break-glass"),
        ("PUT", "/api/policy"),
        ("DELETE", "/api/upstreams/{name}"),
    ] {
        assert!(
            routes.contains(&(method, path)),
            "route table missing {method} {path}: {routes:?}"
        );
        assert!(cerberus_proxy::api::is_known_api_route(method, path));
    }
    // Parameterized upstream delete resolves; the bare collection does not.
    assert!(cerberus_proxy::api::is_known_api_route("DELETE", "/api/upstreams/aws"));
    assert!(!cerberus_proxy::api::is_known_api_route("DELETE", "/api/upstreams"));
}

/// ── Policy document exposes effective rules (`cerberus rules list`) ──────
#[tokio::test]
async fn policy_document_lists_effective_rules() {
    let ctx = make_ctx(openai_rule(), OperationMode::Enforce);
    let (addr, handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();
    let policy: serde_json::Value = client
        .get(format!("http://{addr}/api/policy"))
        .send()
        .await
        .expect("policy")
        .json()
        .await
        .expect("json");
    let effective = policy["effective_rules"].as_array().expect("effective_rules");
    assert!(
        effective.iter().any(|r| r["flag"] == "secret.openai_api_key"),
        "the live rule must be listed: {policy}"
    );
    handle.abort();
}

/// ── helper: build an `AuditEvent` with explicit timestamps ──────────────
fn sample_event(tool: &str, provider: &str, flag: &str, action: &str) -> cerberus_store::event::AuditEvent {
    let mut e = cerberus_store::event::AuditEvent::from_findings(
        &[cerberus_engine::engine::Finding {
            flag: flag.to_string(),
            category: cerberus_engine::rule::Category::Secrets,
            severity: cerberus_engine::rule::Severity::High,
            action: cerberus_engine::rule::Action::Block,
            start: 0,
            end: 5,
            hashed_value: "hmac:aa".to_string(),
        }],
        cerberus_engine::rule::Action::Block,
        "local",
        tool,
        provider,
    );
    if action == "redact" {
        e.action_taken = "redact".to_string();
    }
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("clock fits i64");
    e.ts_unix = now;
    e
}

/// ── F1 anti-lockout on PUT /api/config (attempt 2, LIVE) ─────────────────
/// `POST /api/reload` already refuses to remove the admin token (attempt 1
/// verified); the sibling route `PUT /api/config` had NO such guard: an
/// explicit `"admin_token":null` answered 200, closed every `/api/*` route,
/// AND persisted `admin_token:null` (the closure survived restart). The fix
/// rejects the PUT 400 BEFORE persist/publish; token CHANGE stays allowed.
#[tokio::test]
async fn put_config_rejects_admin_token_removal_anti_lockout() {
    const ROTATED: &str = "rotated-parity-token-0123456789abcdef";
    let dir = std::env::temp_dir().join(format!(
        "cerberus-f6b-putlock-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            "listen: 127.0.0.1:8787\nmode: enforce\nadmin_token: {HARNESS_ADMIN_TOKEN}\nupstreams:\n  openai:\n    url: https://api.openai.com\n"
        ),
    )
    .expect("write");

    let ctx = make_ctx_with_config_path(openai_rule(), OperationMode::Enforce, config_path.clone());
    let (addr, handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = reqwest::Client::new();

    // 1. The attempt-1 repro: explicit null with a VALID token must now 400.
    let resp = client
        .put(format!("http://{addr}/api/config"))
        .header("content-type", "application/json")
        .header("x-cerberus-admin-token", HARNESS_ADMIN_TOKEN)
        .body(r#"{"admin_token":null}"#)
        .send()
        .await
        .expect("put null");
    assert_eq!(resp.status(), 400, "token removal via PUT must be rejected");
    let body = resp.text().await.expect("body");
    assert!(body.contains("CLOSE the control plane"), "anti-lockout error: {body}");

    // 2. The plane STAYS UP with the OLD token: config reads 200, the data
    //    plane health reads 200.
    let resp = client
        .get(format!("http://{addr}/api/config"))
        .header("x-cerberus-admin-token", HARNESS_ADMIN_TOKEN)
        .send()
        .await
        .expect("get config");
    assert_eq!(resp.status(), 200, "the old token must still authenticate");
    let resp = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("health");
    assert_eq!(resp.status(), 200, "data plane still healthy");

    // 3. `admin_token: null` was NEVER persisted — the on-disk file is
    //    byte-for-byte the old one (the rejection happens before persist).
    let disk = std::fs::read_to_string(&config_path).expect("read disk config");
    assert!(
        disk.contains(&format!("admin_token: {HARNESS_ADMIN_TOKEN}")),
        "on-disk config must keep the old token: {disk}"
    );

    // 4. Token CHANGE via PUT remains allowed (documented rotation
    //    semantics — the anti-lockout must not break rotation).
    let resp = client
        .put(format!("http://{addr}/api/config"))
        .header("content-type", "application/json")
        .header("x-cerberus-admin-token", HARNESS_ADMIN_TOKEN)
        .body(format!(r#"{{"admin_token":"{ROTATED}"}}"#))
        .send()
        .await
        .expect("put rotation");
    assert_eq!(
        resp.status(),
        200,
        "token rotation must stay allowed (the anti-lockout rejects removal only)"
    );

    // 5. The rotation applies immediately: the OLD token is now 401 and the
    //    new token authenticates.
    let resp = client
        .get(format!("http://{addr}/api/config"))
        .header("x-cerberus-admin-token", HARNESS_ADMIN_TOKEN)
        .send()
        .await
        .expect("get config (old token)");
    assert_eq!(resp.status(), 401, "the old token must be retired");
    let resp = client
        .get(format!("http://{addr}/api/config"))
        .header("x-cerberus-admin-token", ROTATED)
        .send()
        .await
        .expect("get config (new token)");
    assert_eq!(resp.status(), 200, "the new token must authenticate");

    // 6. No auth event leak: the rotated token value must not appear in the
    //    audit trail either (the config-update event carries no body echo).
    let events = client
        .get(format!("http://{addr}/api/events?tool=control-plane"))
        .header("x-cerberus-admin-token", ROTATED)
        .send()
        .await
        .expect("events")
        .text()
        .await
        .expect("events body");
    assert!(events.contains("config-update"), "rotation is audited: {events}");
    assert!(
        !events.contains(ROTATED),
        "the token value must never be audited: {events}"
    );
    assert!(
        !events.contains(HARNESS_ADMIN_TOKEN),
        "no old token in events: {events}"
    );

    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

/// ── Security P2-1 (attempt 2): config mutations are AUDITED ──────────────
/// Reload used to swap the whole live config with zero trace (only
/// dataplane `proxy` events appeared). Every successful config-mutation
/// action must now be reconstructable from `GET /api/events`.
#[tokio::test]
async fn config_mutations_emit_audit_events_visible_via_api() {
    let dir = std::env::temp_dir().join(format!(
        "cerberus-f6b-audit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            "listen: 127.0.0.1:8787\nmode: shadow\nadmin_token: {HARNESS_ADMIN_TOKEN}\nupstreams:\n  openai:\n    url: https://api.openai.com\n"
        ),
    )
    .expect("write");

    let ctx = make_ctx_with_config_path(openai_rule(), OperationMode::Enforce, config_path.clone());
    let (addr, handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let client = api_client();

    // Five mutations across the audited surface: reload, config PUT,
    // allowlist add, upstream add, upstream remove.
    let resp = client
        .post(format!("http://{addr}/api/reload"))
        .send()
        .await
        .expect("reload");
    assert_eq!(resp.status(), 200);
    let resp = client
        .put(format!("http://{addr}/api/config"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("config put");
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("http://{addr}/api/allowlist"))
        .header("content-type", "application/json")
        .body(r#"{"value":"audit-canary-raw"}"#)
        .send()
        .await
        .expect("allowlist add");
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("http://{addr}/api/upstreams"))
        .header("content-type", "application/json")
        .body(r#"{"name":"anthropic","url":"https://api.anthropic.com"}"#)
        .send()
        .await
        .expect("upstream add");
    assert_eq!(resp.status(), 200);
    let resp = client
        .delete(format!("http://{addr}/api/upstreams/anthropic"))
        .send()
        .await
        .expect("upstream remove");
    assert_eq!(resp.status(), 200);

    // Every action name is visible via /api/events, honest, and secret-free.
    let events: Vec<serde_json::Value> = client
        .get(format!("http://{addr}/api/events?tool=control-plane"))
        .send()
        .await
        .expect("events")
        .json()
        .await
        .expect("json");
    let serialized = serde_json::to_string(&events).expect("serialize");
    for action in [
        "config-reload",
        "config-update",
        "allowlist-add",
        "upstream-add",
        "upstream-remove",
    ] {
        assert!(
            events
                .iter()
                .any(|e| e["flags"].as_array().is_some_and(|f| f.iter().any(|x| x == action))),
            "the {action} mutation must be audited: {serialized}"
        );
    }
    for e in &events {
        assert_eq!(e["tool"], "control-plane");
        assert_eq!(e["action_taken"], "audit");
        assert!(
            e["hashed_values"].as_array().is_some_and(std::vec::Vec::is_empty),
            "control-plane events carry no hashes: {e}"
        );
    }
    // NO secrets in the audit trail: not the raw allowlist canary, not the
    // admin token, not even the fingerprint (honest action names only).
    assert!(
        !serialized.contains("audit-canary-raw"),
        "raw value leaked: {serialized}"
    );
    assert!(!serialized.contains(HARNESS_ADMIN_TOKEN), "token leaked: {serialized}");
    assert!(
        !serialized.contains("hmac:"),
        "no fingerprints in audit events: {serialized}"
    );

    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

/// ── F2 table↔router cross-check (attempt 2, LIVE) ───────────────────────
/// `known_api_routes()` is a hand-maintained copy of the dispatch match
/// ("keep in sync" by comment). The attempt-1 reviewer mutation-proved the
/// parity test green with a REMOVED router arm. This test iterates the
/// TABLE itself and dispatches every entry through the REAL router over
/// HTTP: a table entry whose dispatch arm is missing answers the router's
/// bare `404 {"error":"not found"}` and FAILS here. (The CLI parity test in
/// `crates/cerberus/src/main.rs` performs the same live dispatch for its 24
/// CLI rows — removal fails BOTH.)
#[tokio::test]
async fn route_table_matches_the_router() {
    let ctx = make_ctx(openai_rule(), OperationMode::Enforce);
    let (addr, handle) = spawn_proxy(local_addr(0), ctx).await.expect("spawn");
    let base = format!("http://{addr}");
    let client = api_client();

    // Control canary: the router DOES answer the bare 404 for unknown
    // routes (authenticated — the auth gate 401s an unauthenticated request
    // BEFORE dispatch, so the canary carries the token), so the table check
    // below cannot pass vacuously.
    let resp = client
        .get(format!("{base}/api/not-a-route"))
        .send()
        .await
        .expect("canary");
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.text().await.expect("body"), r#"{"error":"not found"}"#);

    for (method, path) in cerberus_proxy::api::known_api_routes() {
        let url_path = path.replace("{name}", "default");
        let url = format!("{base}{url_path}");
        let request = match *method {
            "GET" => client.get(&url),
            "PUT" => client.put(&url).header("content-type", "application/json").body("{}"),
            "POST" => {
                let body = if *path == "/api/allowlist" {
                    r#"{"value":"parity-canary"}"#.to_string()
                } else if *path == "/api/upstreams" {
                    r#"{"name":"extra","url":"https://api.extra.com"}"#.to_string()
                } else if *path == "/api/break-glass" {
                    r#"{"reason":"parity probe"}"#.to_string()
                } else if *path == "/api/scan" {
                    r#"{"text":"hello"}"#.to_string()
                } else if *path == "/api/packs/enable" || *path == "/api/packs/disable" {
                    r#"{"name":"parity-pack"}"#.to_string()
                } else {
                    String::new()
                };
                client.post(&url).header("content-type", "application/json").body(body)
            }
            "DELETE" => {
                let body = if *path == "/api/allowlist" {
                    r#"{"value":"parity-canary"}"#.to_string() // the POST row above added it
                } else {
                    String::new()
                };
                client
                    .delete(&url)
                    .header("content-type", "application/json")
                    .body(body)
            }
            other => panic!("unknown method {other} in the route table"),
        };
        let resp = request
            .send()
            .await
            .unwrap_or_else(|e| panic!("dispatch {method} {path}: {e}"));
        let status = resp.status();
        assert_ne!(
            status,
            reqwest::StatusCode::NOT_FOUND,
            "route table claims {method} {path} but the ROUTER does not serve it"
        );
    }
    handle.abort();
}
