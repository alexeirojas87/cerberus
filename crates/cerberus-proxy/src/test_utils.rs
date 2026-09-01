//! Test utilities for proxy integration tests.

#![allow(clippy::missing_const_for_fn)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cerberus_engine::redact::RedactOptions;
use cerberus_engine::rule::Rule;
use tokio::task::JoinHandle;

use super::api;
use super::config::{OperationMode, ProxyConfig, UpstreamConfig};
use super::proxy;
use cerberus_store::event::AuditEvent;

/// A test-ready proxy handle.
pub struct TestProxy {
    /// The actual (ephemeral) address the proxy is listening on.
    pub addr: SocketAddr,
    /// The tokio task handle.
    pub handle: JoinHandle<()>,
    /// Events recorded so far.
    pub events: Arc<tokio::sync::Mutex<Vec<AuditEvent>>>,
    /// Shared config: the triage allowlist lives in `policy.allowlist`.
    pub config: Arc<std::sync::RwLock<ProxyConfig>>,
}

impl TestProxy {
    /// Stop and await the proxy task.
    pub async fn stop(self) {
        let _ = self.handle.await;
    }
}

/// Build a proxy context with the given rules and upstreams.
#[must_use]
#[allow(
    clippy::inconsistent_struct_constructor,
    clippy::needless_pass_by_value,
    clippy::implicit_hasher
)]
pub fn build_test_context(
    rules: &[Rule],
    upstreams: HashMap<String, UpstreamConfig>,
    mode: OperationMode,
) -> Arc<proxy::ProxyContext> {
    let engine = cerberus_engine::engine::EngineBuilder::new(rules)
        .build()
        .expect("cannot build test engine");

    let config = ProxyConfig {
        mode,
        upstreams,
        ..ProxyConfig::default()
    };
    let shared = Arc::new(std::sync::RwLock::new(config));

    Arc::new(proxy::ProxyContext {
        config: shared.clone(),
        engine: Arc::new(std::sync::RwLock::new(Arc::new(engine))),
        redact_options: RedactOptions::default(),
        api: api::ApiContext::new(shared),
        last_upstream: Arc::new(std::sync::Mutex::new(None)),
    })
}

/// Spawn a proxy on a random port.
pub async fn spawn_test_proxy(
    ctx: Arc<proxy::ProxyContext>,
) -> Result<TestProxy, Box<dyn std::error::Error + Send + Sync>> {
    let api = Arc::clone(&ctx);
    let events = api.api.events.clone();
    let config = api.config.clone();

    let (addr, handle) = proxy::spawn_proxy((Ipv4Addr::LOCALHOST, 0).into(), ctx).await?;

    Ok(TestProxy {
        addr,
        handle,
        events,
        config,
    })
}

/// Spawn a proxy connected to an upstream mock URL.
pub async fn spawn_test_proxy_with_upstream(
    upstream_url: &str,
) -> Result<TestProxy, Box<dyn std::error::Error + Send + Sync>> {
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
    let ctx = build_test_context(&[], upstreams, OperationMode::Enforce);
    spawn_test_proxy(ctx).await
}

/// Get the base URL for the test proxy.
#[must_use]
pub fn test_proxy_url(proxy: &TestProxy) -> String {
    format!("http://{}", proxy.addr)
}

/// Spawn a test proxy in shadow mode (no blocking).
pub async fn spawn_test_proxy_shadow() -> Result<TestProxy, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = build_test_context(&[], HashMap::new(), OperationMode::Shadow);
    spawn_test_proxy(ctx).await
}

/// Create a test rule.
pub fn make_test_rule(flag: &str, patterns: &[&str]) -> Rule {
    use cerberus_engine::rule::{Action, Category, Severity};
    Rule {
        flag: flag.to_string(),
        category: Category::Secrets,
        severity: Severity::High,
        action: Action::Block,
        hash_normalization: None,
        context_keywords: Vec::new(),
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: patterns.iter().map(std::string::ToString::to_string).collect(),
        validators: Vec::new(),
    }
}
