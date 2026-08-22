//! Reverse proxy core — scans and redacts LLM requests before
//! forwarding them to the upstream (§4.1, §4.2, §4.4 of the build plan).
#![allow(
    clippy::needless_borrows_for_generic_args,
    clippy::redundant_closure_for_method_calls
)]
//!
//! Fixes post-review:
//! - **TLS**: the client connects to `https://` upstreams via hiper-rustls
//!   (webpki-roots). Goodbye to the TLS-less `HttpConnector` (P0-1).
//! - **JSON-safe redaction** on the AST, not the concatenated text (P0-2).
//! - **Body limit** defensive (memory-exhaustion, P1-11); streaming resp.
//!   remains out of MVP (documented).
//! - **Provider-agnostic routing** by explicit `path_prefix`, with prefix
//!   stripping and query string preservation (P0-6).
//! - **Real hot-reload**: the config lives in a shared `Arc<RwLock>` between
//!   the proxy and the Config API (P0-5).
//! - **Allowlist** consulted in the scanning path; bypass audited by
//!   `X-Cerberus-Bypass` header (P1-7); feedback header (P1-7).
//! - Clean requests do not pollute the metrics (P1-12).

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use cerberus_engine::engine::{CompiledEngine, ScanOutput};
use cerberus_engine::feedback::RedactFeedback;
use cerberus_engine::redact::RedactOptions;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

use crate::api::ADMIN_TOKEN_MIN_BYTES;
use crate::api::{self, ApiContext, ADMIN_TOKEN_HEADER};
use crate::config::{FailPolicy, ProxyConfig};
use crate::decoder::{decode, ContentType};
use crate::health::{health_json, is_health_path};
use crate::json_redact::redact_body;
use crate::log::{log_security_event, SecurityEvent};
use crate::shadow;

/// Hop-by-hop headers that are never forwarded to the upstream (fix P1: list
/// extended with `te`, `trailer` and `proxy-authorization`, in addition to
/// the standard list).
const SKIP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
];

/// Hop-by-hop headers filtered from the upstream RESPONSE before copying
/// them to the client (fix P1: includes `te`, `trailer`, `proxy-authenticate`).
const RESPONSE_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Headers (lowercased) that must never be forwarded upstream.
const BYPASS_HEADER: &str = "x-cerberus-bypass";
const FEEDBACK_HEADER: &str = "x-cerberus-feedback";

/// Built-in path-prefix routing for known providers (still overridable by an
/// explicit `path_prefix` in config; keeps `cerberus add-provider` simple for
/// OpenAI-compatible endpoints).
const BUILTIN_PREFIXES: &[(&str, &str)] = &[
    ("/openai/", "openai"),
    ("/anthropic/", "anthropic"),
    ("/gemini/", "gemini"),
    ("/mistral/", "mistral"),
    ("/groq/", "groq"),
];

/// Result of resolving a request's route.
struct UpstreamRoute {
    /// Upstream base URL, e.g. `https://api.openai.com`.
    base: String,
    /// Path that is forwarded (without the path prefix).
    rest_path: String,
    /// Provider name (audit consistent with the destination).
    provider: String,
}

/// Direct destination fixed by the forward proxy once a `CONNECT` has been
/// validated against its exact allowlist. It is never built from headers of
/// the already-intercepted TLS request: the authorized authority of the
/// tunnel is the only source of truth, avoiding confused-deputy/SSRF
/// between hosts.
#[derive(Clone, Debug)]
pub(crate) struct DirectUpstream {
    pub(crate) base: String,
    pub(crate) provider: String,
}

/// Proxy shared state.
pub struct ProxyContext {
    /// Config shared with the Config API (hot-reload).
    pub config: Arc<RwLock<ProxyConfig>>,
    /// Compiled detection engine, atomically swappable (fix review v5:
    /// pack hot-reload). The `RwLock` allows a pack installed hot to replace
    /// the rules without restarting the proxy; the read in the hot path is
    /// very short (a `read()` that takes a reference to the Arc).
    pub engine: Arc<RwLock<Arc<CompiledEngine>>>,
    /// Redaction options.
    pub redact_options: RedactOptions,
    /// API context (dashboard, config, stats).
    pub api: ApiContext,
    /// Last upstream name used for routing (provider tracking).
    pub last_upstream: Arc<std::sync::Mutex<Option<String>>>,
}

/// Is the listen address loopback (127.0.0.0/8 or `::1`)?
#[must_use]
const fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Validate that a startup on a NON-loopback interface requires a strong
/// admin token (review v4 #1). On loopback open dev-mode is allowed
/// (documented).
///
/// # Errors
///
/// `Err` if `listen` is not loopback and the token is `None` or < 24 bytes.
fn check_listen_security(listen: &SocketAddr, ctx: &ProxyContext) -> Result<(), String> {
    if is_loopback(listen) {
        return Ok(());
    }
    let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    match cfg.admin_token.as_deref() {
        Some(t) if t.len() >= ADMIN_TOKEN_MIN_BYTES => Ok(()),
        Some(t) => Err(format!(
            "refusing to bind on non-loopback address {listen}: admin token is too short ({len} < {min} bytes)",
            len = t.len(),
            min = ADMIN_TOKEN_MIN_BYTES
        )),
        None => Err(format!(
            "refusing to bind on non-loopback address {listen}: no admin token configured (set a token of at least {ADMIN_TOKEN_MIN_BYTES} characters)"
        )),
    }
}

/// Spawn the proxy server.
///
/// # Errors
///
/// Returns an error if the address is non-loopback without a strong admin
/// token (review v4 #1), or if the listener can't bind.
pub async fn spawn_proxy(
    listen: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    // Fix P0 (review v4 #1): the control plane must NOT be left open on a
    // non-loopback interface; we require a strong admin token (≥24 bytes) there.
    // The validation happens BEFORE the bind, so startup fails cleanly.
    check_listen_security(&listen, &ctx)?;
    let listener = TcpListener::bind(listen).await?;
    let actual = listener.local_addr()?;
    let handle = tokio::spawn(serve_proxy(listener, ctx));
    Ok((actual, handle))
}

/// Handle for a proxy that can stop accepting new connections and drain the
/// requests that were already in flight before the audit store is closed.
pub struct ManagedProxyHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ManagedProxyHandle {
    /// Stop accepting, wait for active HTTP/1 connections, and force-abort if
    /// they do not finish within `grace`.
    pub async fn shutdown(mut self, grace: Duration) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }

        match tokio::time::timeout(grace, &mut self.task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(format!("proxy task failed during shutdown: {err}")),
            Err(_) => {
                self.task.abort();
                let _ = self.task.await;
                Err(format!(
                    "proxy drain exceeded {} ms; active connections were aborted",
                    grace.as_millis()
                ))
            }
        }
    }
}

/// Spawn a proxy with an explicit graceful-shutdown handle.
///
/// The regular [`spawn_proxy`] remains available to callers whose lifetime is
/// already owned by a Tokio task. Daemons should use this variant so the audit
/// store cannot close while requests are still able to enqueue events.
pub async fn spawn_managed_proxy(
    listen: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> Result<(SocketAddr, ManagedProxyHandle), Box<dyn std::error::Error + Send + Sync>> {
    check_listen_security(&listen, &ctx)?;
    let listener = TcpListener::bind(listen).await?;
    let actual = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(serve_proxy_until_shutdown(listener, ctx, shutdown_rx));
    Ok((
        actual,
        ManagedProxyHandle {
            shutdown: Some(shutdown_tx),
            task,
        },
    ))
}

async fn serve_proxy(listener: TcpListener, ctx: Arc<ProxyContext>) {
    // TLS-capable client: HTTPS upstream via rustls, else plain HTTP.
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!("proxy accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let ctx = ctx.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let ctx = ctx.clone();
                let client = client.clone();
                async move { proxy_handler(req, &ctx, &client).await }
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::error!("proxy connection error: {err}");
            }
        });
    }
}

async fn serve_proxy_until_shutdown(
    listener: TcpListener,
    ctx: Arc<ProxyContext>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!("proxy accept error: {e}");
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                let ctx = ctx.clone();
                let client = client.clone();
                connections.spawn(async move {
                    let service = service_fn(move |req| {
                        let ctx = ctx.clone();
                        let client = client.clone();
                        async move { proxy_handler(req, &ctx, &client).await }
                    });
                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::error!("proxy connection error: {err}");
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(err)) = completed {
                    tracing::error!("proxy connection task failed: {err}");
                }
            }
        }
    }

    // Dropping the listener above stops admission. Existing keep-alive
    // connections are allowed to finish before this server task resolves.
    while let Some(result) = connections.join_next().await {
        if let Err(err) = result {
            tracing::error!("proxy connection task failed while draining: {err}");
        }
    }
}

/// Tokens declared dynamically in the `Connection` header (hop-by-hop).
fn connection_tokens(headers: &hyper::HeaderMap) -> Vec<String> {
    headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default()
}

/// Buffer the body applying `max_body_bytes` DURING the read
/// (`http_body_util::Limited`), so an oversized body never materializes
/// in memory (review 2, P1 #5).
async fn build_buffered<B>(body: B, max: Option<usize>) -> Result<Bytes, String>
where
    B: hyper::body::Body + Sized,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + std::fmt::Display,
{
    match max {
        Some(m) => http_body_util::Limited::new(body, m)
            .collect()
            .await
            .map(|b| b.to_bytes())
            .map_err(|_| "body too large".to_string()),
        None => body
            .collect()
            .await
            .map(|b| b.to_bytes())
            .map_err(|e| format!("body read error: {e}")),
    }
}

/// Filter the hop-by-hop headers from an upstream response before copying
/// them to the client: fixed list + dynamic tokens from `Connection`.
fn filter_response_headers(headers: &hyper::HeaderMap) -> hyper::HeaderMap {
    let conn_tokens = connection_tokens(headers);
    let mut out = hyper::HeaderMap::new();
    for (name, value) in headers {
        let lower = name.as_str();
        if RESPONSE_HOP_BY_HOP.contains(&lower) || conn_tokens.iter().any(|t| t == lower) {
            continue;
        }
        out.insert(name, value.clone());
    }
    out
}

/// Truncate the bypass reason to at most 200 bytes without cutting a UTF-8
/// char in half (the hash is done afterwards on the truncation; the secret
/// is never stored).
#[must_use]
fn truncate_bypass_reason(reason: &str) -> &str {
    const MAX: usize = 200;
    if reason.len() <= MAX {
        return reason;
    }
    let mut end = MAX;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// Error reading the upstream response body with the limit applied.
enum RespBodyError {
    TooLarge,
    Read(String),
}

/// Buffer the upstream response with `max_body`, distinguishing the limit
/// cutoff (`LengthLimitError`) from generic read errors.
async fn collect_resp_body(body: hyper::body::Incoming, max: Option<usize>) -> Result<Bytes, RespBodyError> {
    use http_body_util::BodyExt;
    match max {
        Some(m) => match http_body_util::Limited::new(body, m).collect().await {
            Ok(c) => Ok(c.to_bytes()),
            Err(e) if e.is::<http_body_util::LengthLimitError>() => Err(RespBodyError::TooLarge),
            Err(e) => Err(RespBodyError::Read(format!("response read error: {e}"))),
        },
        None => body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .map_err(|e| RespBodyError::Read(format!("response read error: {e}"))),
    }
}

/// Resulting decision from a redaction failure according to the policy (review v4 #5).
#[derive(Debug)]
enum RedactDecision {
    Forward(Vec<u8>),
    Reject(StatusCode, String),
}

/// Apply `fail_policy` to a redaction failure. Closed → 502 with
/// `{"error":"redact failure",...}` (the raw secret is NEVER sent);
/// Open → forward the ORIGINAL body and mark warn (real fail-open).
#[must_use]
fn decide_redact_result(
    redaction: Result<Vec<u8>, String>,
    fail_policy: FailPolicy,
    original: &[u8],
) -> RedactDecision {
    match redaction {
        Ok(b) => RedactDecision::Forward(b),
        Err(e) if fail_policy == FailPolicy::Closed => RedactDecision::Reject(
            StatusCode::BAD_GATEWAY,
            format!(r#"{{"error":"redact failure","detail":"{e}"}}"#),
        ),
        Err(e) => {
            tracing::warn!("redaction failed — fail_policy=open, forwarding original body: {e}");
            RedactDecision::Forward(original.to_vec())
        }
    }
}

/// Main proxy handler.
#[allow(clippy::too_many_lines)]
pub(crate) async fn proxy_handler(
    req: Request<Incoming>,
    ctx: &ProxyContext,
    client: &Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, String> {
    let (parts, body) = req.into_parts();
    let direct_upstream = parts.extensions.get::<DirectUpstream>().cloned();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map_or_else(String::new, |q| format!("?{q}"));

    // API routes.
    if direct_upstream.is_none() && api::is_api_path(&path) {
        let api_req = Request::from_parts(parts, body);
        return api::handle_api_request(api_req, &ctx.api).await;
    }

    // Healthcheck.
    let is_health = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        is_health_path(&path, &cfg)
    };
    if direct_upstream.is_none() && is_health {
        let json = {
            let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
            health_json(&cfg)
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(|e| e.to_string());
    }

    // Body limit applied DURING buffering, not after (review 2, P1 #5).
    let (max_body, mode, fail_policy) = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        (cfg.max_body_bytes, cfg.mode, cfg.fail_policy)
    };
    // Body read errors (fix P1): too large → 413; the rest of the read
    // errors → 502 (there is no body to forward).
    let body_bytes = match build_buffered(body, max_body).await {
        Ok(b) => b,
        Err(msg) if msg == "body too large" => {
            return json_status(StatusCode::PAYLOAD_TOO_LARGE, r#"{"error":"body too large"}"#);
        }
        Err(msg) => {
            return json_status(
                StatusCode::BAD_GATEWAY,
                &format!(r#"{{"error":"body read error","detail":"{msg}"}}"#),
            );
        }
    };

    // Audited break-glass: the `X-Cerberus-Bypass` header is only honored when
    // the control plane is protected AND the request carries the valid admin
    // token **via `X-Cerberus-Admin-Token`** (fix review v4 #2). Auth via
    // `Authorization: Bearer` is valid for `/api/*`, but on the DATA PLANE
    // we require exclusively the own header, to avoid risking substituting
    // the provider key (which travels in `Authorization`) with the admin
    // token. With a configured token and missing/invalid auth the header is
    // IGNORED (it does not block) and a warn is logged. Without a configured
    // token (dev mode) the bypass stays open (P0).
    let bypass_reason: Option<String> = {
        let present = parts
            .headers
            .get(BYPASS_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        present.filter(|_| {
            let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
            match api::expected_admin_token(&cfg) {
                // Dev mode: no token configured, bypass open.
                None => true,
                // Token config: the data-plane bypass is honored ONLY by the
                // `X-Cerberus-Admin-Token` header (not by `Authorization`).
                Some(expected) => {
                    if api::admin_token_header_is_present(&parts.headers, expected) {
                        true
                    } else {
                        if api::authorized(&parts.headers, expected) {
                            tracing::warn!(
                                "X-Cerberus-Bypass ignored: data-plane bypass requires the {} header, \
                                 not Authorization (avoids overwriting the provider API key)",
                                ADMIN_TOKEN_HEADER
                            );
                        }
                        false
                    }
                }
            }
        })
    };

    // Decode and scan, wrapping the engine phase in the failure policy
    // (fix P1 #2): fail_policy=Open → if the engine cannot decode/redact
    // the ORIGINAL body is forwarded intact; Closed → 502.
    let content_type_hint = parts.headers.get("content-type").and_then(|v| v.to_str().ok());
    let decoded = decode(&body_bytes, content_type_hint);
    // Decode failure: content-type declares JSON but the body is not valid JSON.
    let json_hint = content_type_hint.is_some_and(|h| h.to_ascii_lowercase().contains("json"));
    let decode_failed = json_hint && decoded.content_type != ContentType::Json;
    if decode_failed && fail_policy == FailPolicy::Closed {
        return json_status(StatusCode::BAD_GATEWAY, r#"{"error":"cannot decode"}"#);
    }
    if decode_failed {
        // fail_policy=Open: a non-decodable body cannot be scanned; it is
        // forwarded intact and marked in the log.
        tracing::warn!("decode failed for json content-type; fail_policy=open — forwarding original body");
    }
    // Snapshot of the engine for the whole request (hot-reload): the Arc is
    // cloned under the brief lock; scan+redact use the same snapshot → no
    // half-swapped pack is visible mid-request.
    let engine_snap = ctx.engine.read().unwrap_or_else(|p| p.into_inner()).clone();
    let scan_result = if decode_failed {
        ScanOutput {
            findings: Vec::new(),
            action_overall: cerberus_engine::rule::Action::Allow,
        }
    } else {
        let mut s = engine_snap.scan(&decoded.text);
        // Allowlist (false-positive triage) — applied in the real path (P0-5).
        apply_allowlist(ctx, &decoded.text, &mut s);
        s
    };

    let mode_result = shadow::apply_mode(&scan_result, mode);
    let has_findings = !scan_result.findings.is_empty();

    // Block (Enforce + critical) — unless bypass.
    let blocked = bypass_reason.is_none() && !mode_result.should_forward();
    if blocked {
        let flag = scan_result.findings.first().map_or("unknown", |f| f.flag.as_str());
        log_security_event(
            SecurityEvent::Blocked,
            &scan_result.findings,
            scan_result.action_overall,
        );
        // Record event in the store.
        let provider = direct_upstream
            .as_ref()
            .map_or_else(|| provider_of(path.as_str(), ctx), |direct| direct.provider.clone());
        record_only_with_findings(ctx, &scan_result, provider.as_str()).await;
        let mut r = json_status(
            StatusCode::FORBIDDEN,
            &format!(r#"{{"error":"blocked","flag":"{flag}"}}"#),
        )?;
        add_feedback_headers(&mut r, &scan_result, bypass_reason.as_deref());
        return Ok(r);
    }

    // Enforce: apply redaction (only in enforce; shadow passes intact).
    // If the internal redaction fails, the failure policy decides: Open →
    // forward the original body (real fail-open); Closed → 502 (fix review v4
    // #5: before the `apply_redaction` error was swallowed in json_redact and
    // the raw secret passed through even though the JSON failed).
    let final_bytes = if matches!(mode_result, shadow::ModeResult::Enforce { .. })
        && mode_result.action() == cerberus_engine::rule::Action::Redact
    {
        let redaction = redact_body(
            &engine_snap,
            &body_bytes,
            &decoded,
            &ctx.redact_options,
            &scan_result.findings,
        );
        match decide_redact_result(redaction, fail_policy, &body_bytes) {
            RedactDecision::Forward(b) => b,
            RedactDecision::Reject(status, reason) => return json_status(status, &reason),
        }
    } else {
        body_bytes.to_vec()
    };

    // Log sec event (by intervention type).
    let sec_event = if mode_result.action() == cerberus_engine::rule::Action::Block {
        SecurityEvent::Blocked
    } else if mode_result.action() == cerberus_engine::rule::Action::Redact {
        SecurityEvent::Redacted
    } else if mode_result.action() == cerberus_engine::rule::Action::Warn {
        SecurityEvent::Warned
    } else {
        SecurityEvent::Clean
    };
    log_security_event(sec_event, &scan_result.findings, scan_result.action_overall);

    // Record event in the store if there are findings (clean ones do not count — P1-12).
    let provider = direct_upstream
        .as_ref()
        .map_or_else(|| provider_of(path.as_str(), ctx), |direct| direct.provider.clone());
    if has_findings {
        let is_bypass = bypass_reason.is_some();
        if is_bypass {
            // Audited break-glass (review 2, P1 #6): the authorized leak is
            // persisted as "bypass" with its reason — not as a fake block.
            log_security_event(
                SecurityEvent::Bypassed,
                &scan_result.findings,
                scan_result.action_overall,
            );
        }
        let mut event = cerberus_store::event::AuditEvent::from_findings(
            &scan_result.findings,
            scan_result.action_overall,
            "local",
            "proxy",
            provider.as_str(),
        );
        if is_bypass {
            event.action_taken = "bypass".to_string();
            // The reason is NEVER persisted raw (secret leak, fix P1):
            // `flags` only carries the "bypass" marker; the reason (truncated
            // to 200 bytes) is stored hashed in `hashed_values` as
            // `bypass-hash:<sha256hex>`.
            event.flags.push("bypass".to_string());
            if let Some(reason) = &bypass_reason {
                let digest = cerberus_engine::engine::hash_value(truncate_bypass_reason(reason));
                event
                    .hashed_values
                    .push(format!("bypass-hash:{}", digest.trim_start_matches("sha256:")));
            }
        }
        api::record_event(&ctx.api, event).await;
    }

    // Resolve upstream (with path prefix stripping).
    let (base, rest_path) = direct_upstream.as_ref().map_or_else(
        || {
            let route = resolve_route(ctx, path.as_str());
            (route.base, route.rest_path)
        },
        |direct| (direct.base.clone(), path.clone()),
    );

    {
        let mut last = ctx.last_upstream.lock().unwrap();
        *last = Some(provider);
    }

    let uri: Uri = format!("{base}{rest_path}{query}")
        .parse()
        .map_err(|e| format!("invalid upstream uri: {e}"))?;

    let mut builder = Request::builder().method(parts.method).uri(uri);
    // Forward hop-by-hop headers correctly: omit the fixed ones and also the
    // tokens declared dynamically in "Connection" (review 2, P1 #10).
    // The admin token (`X-Cerberus-Admin-Token`) is NEVER forwarded to the
    // upstream (fix review v4 #2): it is exclusive to the control plane /
    // bypass.
    let conn_tokens = connection_tokens(&parts.headers);
    for (name, value) in &parts.headers {
        let lower = name.as_str();
        if lower == "host"
            || lower == BYPASS_HEADER
            || lower == ADMIN_TOKEN_HEADER
            || SKIP_HEADERS.contains(&lower)
            || conn_tokens.iter().any(|t| t.as_str() == lower)
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    let up_req = builder
        .body(Full::new(Bytes::from(final_bytes)))
        .map_err(|e| e.to_string())?;

    // Upstream timeout (review 2, P1 #10): 30s per request.
    //
    // fail_policy semantics on UPSTREAM failure (connection/timeout): the
    // Open/Closed policy applies to the ENGINE failure (decode/scan/redact,
    // above). For a down upstream there is no way to forward the request,
    // so both modes reject but with different proxy semantics:
    // Closed → 503 (the proxy is part of the chain and decides to reject);
    // Open → 502 (bad gateway: the destination did not respond).
    let resp = match tokio::time::timeout(std::time::Duration::from_secs(30), client.request(up_req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            // fail_policy Closed → 503 (proxy failure); Open → 502 and we
            // surface the visible error (review 2, P1 #7).
            let status = if fail_policy == crate::config::FailPolicy::Closed {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::BAD_GATEWAY
            };
            return json_status(status, &format!(r#"{{"error":"upstream failure","detail":"{e}"}}"#));
        }
        Err(_) => {
            let status = if fail_policy == crate::config::FailPolicy::Closed {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::BAD_GATEWAY
            };
            return json_status(status, r#"{"error":"upstream timeout"}"#);
        }
    };
    let (resp_parts, resp_body) = resp.into_parts();
    // Limit on the response too (review 2, P1 #5). If the upstream exceeds
    // `max_body_bytes`, we return a 502 JSON instead of propagating the
    // error and cutting the connection (fix P1 #4).
    let resp_bytes = match collect_resp_body(resp_body, max_body).await {
        Ok(b) => b,
        Err(RespBodyError::TooLarge) => {
            return json_status(StatusCode::BAD_GATEWAY, r#"{"error":"response too large"}"#);
        }
        Err(RespBodyError::Read(msg)) => {
            return json_status(StatusCode::BAD_GATEWAY, &format!(r#"{{"error":"{msg}"}}"#));
        }
    };

    let mut response = Response::new(Full::new(resp_bytes));
    *response.status_mut() = resp_parts.status;
    // Filter hop-by-hop headers from the response (fix P1 #6): tokens from
    // `Connection` + fixed list (te, trailer, proxy-authenticate, ...).
    *response.headers_mut() = filter_response_headers(&resp_parts.headers);
    add_feedback_headers(&mut response, &scan_result, bypass_reason.as_deref());
    Ok(response)
}

/// Filter findings whose value is in the allowlist (removes false positives).
///
/// The allowlist is read from the shared config (`policy.allowlist`, fix
/// review v6.1): it is the SAME one the control plane persists, so an FP
/// triage from the dashboard takes effect on the next request without
/// restarting and survives restart.
fn apply_allowlist(ctx: &ProxyContext, text: &str, scan: &mut ScanOutput) {
    let allow: Vec<String> = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        cfg.policy.allowlist.clone()
    };
    if allow.is_empty() {
        return;
    }
    scan.findings.retain(|f| {
        if f.end <= text.len() {
            let raw = text[f.start..f.end].trim();
            !allow.iter().any(|a| a.as_str() == raw)
        } else {
            true
        }
    });
    // Recalculate the overall action with the findings that remain.
    scan.action_overall = scan
        .findings
        .iter()
        .map(|f| f.action)
        .max()
        .unwrap_or(cerberus_engine::rule::Action::Allow);
}

/// Provider of the path (for stats tracking). Consistent with the forward
/// destination (review 2, P1 #10): uses the SAME order as `resolve_route`.
fn provider_of(path: &str, ctx: &ProxyContext) -> String {
    resolve_route(ctx, path).provider
}

/// Deterministic forward route. Priority (longest-match first):
/// - explicit `path_prefix`
/// - built-in table
/// - `default` upstream
///
/// The prefix is stripped before forwarding and the query string is preserved.
fn resolve_route(ctx: &ProxyContext, path: &str) -> UpstreamRoute {
    // Deterministic snapshot of the upstreams (drop the RwLock early).
    let upstreams = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        cfg.upstreams.clone()
    };

    // 1) explicit path_prefix, longest-match first (fix P1 #3): sorted by
    //    the PREFIX length, not the name length, with a deterministic
    //    tiebreak by name.
    let mut explicit: Vec<(&String, &crate::config::UpstreamConfig)> = upstreams.iter().collect();
    explicit.sort_by(|(a_name, a_up), (b_name, b_up)| {
        let a_len = a_up.path_prefix.as_deref().map_or(0, str::len);
        let b_len = b_up.path_prefix.as_deref().map_or(0, str::len);
        b_len.cmp(&a_len).then_with(|| a_name.cmp(b_name))
    });
    for (name, up) in explicit {
        if let Some(prefix) = &up.path_prefix {
            if let Some(rest) = path.strip_prefix(prefix.as_str()) {
                // Normalize the leading slash of the rest: a prefix with a trailing
                // slash (`/openai/`) leaves `rest` without `/` — we always
                // re-add it so the forward URI is correct (P1 #7).
                let rest = rest.trim_start_matches('/');
                return UpstreamRoute {
                    base: up.url.clone(),
                    rest_path: format!("/{rest}"),
                    provider: name.clone(),
                };
            }
        }
    }

    // 2) built-in prefixes to upstreams with the corresponding name.
    for (prefix, name) in BUILTIN_PREFIXES {
        if let Some(rest) = path.strip_prefix(prefix) {
            if let Some(up) = upstreams.get(*name) {
                let rest = rest.trim_start_matches('/');
                return UpstreamRoute {
                    base: up.url.clone(),
                    rest_path: format!("/{rest}"),
                    provider: (*name).to_string(),
                };
            }
        }
    }

    // 3) deterministic fallback: upstream named "default".
    if let Some(def) = upstreams.get("default") {
        return UpstreamRoute {
            base: def.url.clone(),
            rest_path: path.to_string(),
            provider: "default".to_string(),
        };
    }

    UpstreamRoute {
        base: String::new(),
        rest_path: path.to_string(),
        provider: "unknown".to_string(),
    }
}

fn json_status(status: StatusCode, body: &str) -> Result<Response<Full<Bytes>>, String> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|e| e.to_string())
}

/// Attach feedback/bypass headers to the response.
fn add_feedback_headers(response: &mut Response<Full<Bytes>>, scan: &ScanOutput, bypass: Option<&str>) {
    if !scan.findings.is_empty() {
        let feedback = RedactFeedback::from_findings(&scan.findings, scan.action_overall);
        let line = feedback.summary_line();
        if !line.is_empty() {
            if let Ok(hv) = line.parse() {
                response.headers_mut().insert(FEEDBACK_HEADER, hv);
            }
        }
    }
    if let Some(reason) = bypass {
        if let Ok(hv) = format!("ack:{reason}").parse() {
            response.headers_mut().insert(BYPASS_HEADER, hv);
        }
    }
}

async fn record_only_with_findings(ctx: &ProxyContext, scan: &ScanOutput, provider: &str) {
    if !scan.findings.is_empty() {
        let event = cerberus_store::event::AuditEvent::from_findings(
            &scan.findings,
            scan.action_overall,
            "local",
            "proxy",
            provider,
        );
        api::record_event(&ctx.api, event).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_connector_is_wired() {
        // The proxy connects to HTTPS upstreams via rustls (webpki-roots).
        // This test checks that the TLS connector builds without errors.
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let _client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    }

    #[test]
    fn routing_strips_builtin_prefix() {
        let mut upstreams = std::collections::HashMap::new();
        upstreams.insert(
            "openai".to_string(),
            crate::config::UpstreamConfig {
                url: "https://api.openai.com".to_string(),
                path_prefix: None,
                auth_header: "authorization".to_string(),
            },
        );
        upstreams.insert(
            "default".to_string(),
            crate::config::UpstreamConfig {
                url: "http://mock.local".to_string(),
                path_prefix: Some("/myproj".to_string()),
                auth_header: "authorization".to_string(),
            },
        );
        let cfg = crate::config::ProxyConfig {
            upstreams,
            ..crate::config::ProxyConfig::default()
        };
        let ctx = ProxyContext {
            config: Arc::new(RwLock::new(cfg)),
            engine: Arc::new(std::sync::RwLock::new(Arc::new(
                cerberus_engine::engine::EngineBuilder::new(&[])
                    .build()
                    .expect("engine"),
            ))),
            redact_options: RedactOptions::default(),
            api: api::ApiContext::new(Arc::new(RwLock::new(crate::config::ProxyConfig::default()))),
            last_upstream: Arc::new(std::sync::Mutex::new(None)),
        };
        let r1 = resolve_route(&ctx, "/openai/v1/chat");
        assert_eq!(r1.base, "https://api.openai.com");
        assert_eq!(r1.rest_path, "/v1/chat");
        let r2 = resolve_route(&ctx, "/myproj/ping");
        assert_eq!(r2.base, "http://mock.local");
        assert_eq!(r2.rest_path, "/ping");
        assert_eq!(provider_of("/openai/v1", &ctx), "openai");
        assert_eq!(provider_of("/myproj/x", &ctx), "default");
    }

    fn test_ctx(upstreams: std::collections::HashMap<String, crate::config::UpstreamConfig>) -> ProxyContext {
        let cfg = crate::config::ProxyConfig {
            upstreams,
            ..crate::config::ProxyConfig::default()
        };
        ProxyContext {
            config: Arc::new(RwLock::new(cfg)),
            engine: Arc::new(std::sync::RwLock::new(Arc::new(
                cerberus_engine::engine::EngineBuilder::new(&[])
                    .build()
                    .expect("engine"),
            ))),
            redact_options: RedactOptions::default(),
            api: api::ApiContext::new(Arc::new(RwLock::new(crate::config::ProxyConfig::default()))),
            last_upstream: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    #[test]
    fn routing_uses_longest_path_prefix() {
        // P1 #3: sort by the PREFIX length (not the name). "short"
        // has prefix `/v1` and "longer" `/v1/admin`; with short names a
        // sort by name length broke the longest-match.
        let mut upstreams = std::collections::HashMap::new();
        upstreams.insert(
            "short".to_string(),
            crate::config::UpstreamConfig {
                url: "http://short.local".to_string(),
                path_prefix: Some("/v1".to_string()),
                auth_header: "authorization".to_string(),
            },
        );
        upstreams.insert(
            "longer".to_string(),
            crate::config::UpstreamConfig {
                url: "http://longer.local".to_string(),
                path_prefix: Some("/v1/admin".to_string()),
                auth_header: "authorization".to_string(),
            },
        );
        let ctx = test_ctx(upstreams);

        let r = resolve_route(&ctx, "/v1/admin/x");
        assert_eq!(r.provider, "longer", "longest prefix must win");
        assert_eq!(r.base, "http://longer.local");
        assert_eq!(r.rest_path, "/x");

        let r = resolve_route(&ctx, "/v1/users");
        assert_eq!(r.provider, "short", "non-admin path routes to short");
        assert_eq!(r.rest_path, "/users");
    }

    #[test]
    fn response_hop_by_hop_headers_filtered() {
        // P1 #6: the response must filter the `Connection` tokens and the
        // fixed hop-by-hop list (connection, te, trailer, etc).
        let mut headers = hyper::HeaderMap::new();
        headers.insert("connection", hyper::http::HeaderValue::from_static("close"));
        headers.insert("te", hyper::http::HeaderValue::from_static("trailers"));
        headers.insert("trailer", hyper::http::HeaderValue::from_static("X-Foo"));
        headers.insert("transfer-encoding", hyper::http::HeaderValue::from_static("chunked"));
        headers.insert(
            "content-type",
            hyper::http::HeaderValue::from_static("application/json"),
        );
        headers.insert("x-custom", hyper::http::HeaderValue::from_static("keep"));

        let filtered = filter_response_headers(&headers);
        assert!(filtered.get("connection").is_none(), "connection stripped");
        assert!(filtered.get("te").is_none(), "te stripped");
        assert!(filtered.get("trailer").is_none(), "trailer stripped");
        assert!(
            filtered.get("transfer-encoding").is_none(),
            "transfer-encoding stripped"
        );
        assert_eq!(filtered.get("content-type").unwrap(), "application/json");
        assert_eq!(filtered.get("x-custom").unwrap(), "keep");
    }

    #[test]
    fn response_connection_tokens_stripped() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "connection",
            hyper::http::HeaderValue::from_static("keep-alive, x-custom-hop"),
        );
        headers.insert("x-custom-hop", hyper::http::HeaderValue::from_static("v"));
        headers.insert("keep-alive", hyper::http::HeaderValue::from_static("timeout=5"));
        headers.insert("x-ok", hyper::http::HeaderValue::from_static("yes"));

        let filtered = filter_response_headers(&headers);
        assert!(filtered.get("x-custom-hop").is_none(), "connection token stripped");
        assert!(filtered.get("keep-alive").is_none(), "keep-alive stripped");
        assert!(filtered.get("x-ok").is_some(), "normal header kept");
    }

    #[test]
    fn truncate_bypass_reason_limits_at_200_bytes() {
        let long = "x".repeat(500);
        let truncated = truncate_bypass_reason(&long);
        assert_eq!(truncated.len(), 200);
        let short = "short".to_string();
        assert_eq!(truncate_bypass_reason(&short), "short");
        // 150 multi-byte chars (e.g. ñ = 2 bytes) over 200 bytes → truncation keeps a char boundary.
        let utf8 = "ñ".repeat(150);
        let out = truncate_bypass_reason(&utf8);
        assert!(out.len() <= 200);
        assert!(out.len().is_multiple_of(2), "never split a UTF-8 char");
    }

    fn test_ctx_with_admin_token(admin: Option<&str>) -> ProxyContext {
        let cfg = crate::config::ProxyConfig {
            admin_token: admin.map(ToString::to_string),
            ..crate::config::ProxyConfig::default()
        };
        ProxyContext {
            config: Arc::new(RwLock::new(cfg)),
            engine: Arc::new(std::sync::RwLock::new(Arc::new(
                cerberus_engine::engine::EngineBuilder::new(&[])
                    .build()
                    .expect("engine"),
            ))),
            redact_options: RedactOptions::default(),
            api: api::ApiContext::new(Arc::new(RwLock::new(crate::config::ProxyConfig::default()))),
            last_upstream: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    #[tokio::test]
    async fn non_loopback_listener_requires_strong_admin_token() {
        // Review v4 #1: on a non-loopback interface the control plane cannot
        // be left open. No token or token < 24 bytes → Err on deploy.
        let non_loop: SocketAddr = "0.0.0.0:0".parse().unwrap();

        // No token → Err.
        let ctx = Arc::new(test_ctx_with_admin_token(None));
        let err = spawn_proxy(non_loop, ctx).await.unwrap_err().to_string();
        assert!(err.contains("admin token"), "got: {err}");

        // Short token (14 chars, like "change-me") → Err on non-loopback.
        let ctx = Arc::new(test_ctx_with_admin_token(Some("change-me-123")));
        let err = spawn_proxy(non_loop, ctx).await.unwrap_err().to_string();
        assert!(err.contains("too short"), "got: {err}");

        // Strong token (≥24) → Ok.
        let ctx = Arc::new(test_ctx_with_admin_token(Some("012345678901234567890123456789")));
        let (_addr, _h) = spawn_proxy(non_loop, ctx).await.expect("strong token binds on 0.0.0.0");

        // Loopback without token (open dev mode, documented) → Ok.
        let ctx = Arc::new(test_ctx_with_admin_token(None));
        let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (_addr, _h) = spawn_proxy(loopback, ctx).await.expect("loopback dev mode allowed");
    }

    #[tokio::test]
    async fn managed_proxy_shutdown_stops_admission() {
        let ctx = Arc::new(test_ctx_with_admin_token(None));
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (addr, handle) = spawn_managed_proxy(listen, ctx).await.expect("managed proxy binds");

        tokio::net::TcpStream::connect(addr)
            .await
            .expect("listener accepts before shutdown");
        handle
            .shutdown(Duration::from_secs(1))
            .await
            .expect("idle connection drains");

        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "listener must reject new connections after shutdown"
        );
    }

    #[test]
    fn redact_failure_fail_closed_returns_502_without_raw_secret() {
        // Review v4 #5: if redaction fails and fail_policy=Closed, the
        // response is 502 JSON and the raw secret never goes in the body.
        let original = br#"{"content":"RAW-SECRET-DO-NOT-LEAK999"}"#;
        match decide_redact_result(Err("invalid span".to_string()), FailPolicy::Closed, original) {
            RedactDecision::Reject(status, body) => {
                assert_eq!(status, StatusCode::BAD_GATEWAY, "closed → 502");
                assert!(body.contains("redact failure"), "body: {body}");
                assert!(!body.contains("RAW-SECRET"), "raw secret leaked into 502: {body}");
            }
            RedactDecision::Forward(_) => panic!("expected Reject"),
        }
    }

    #[test]
    fn redact_failure_fail_open_forwards_original() {
        // Review v4 #5: fail_policy=Open → the ORIGINAL body is forwarded intact
        // (marked warn) and an OK redact is forwarded as is.
        let original = b"raw-original-bytes".to_vec();
        match decide_redact_result(Err("oops".to_string()), FailPolicy::Open, &original) {
            RedactDecision::Forward(b) => assert_eq!(b, original, "open forwards original"),
            RedactDecision::Reject(..) => panic!("expected Forward"),
        }
        match decide_redact_result(Ok(b"redacted".to_vec()), FailPolicy::Closed, &original) {
            RedactDecision::Forward(b) => assert_eq!(b, b"redacted".to_vec()),
            RedactDecision::Reject(..) => panic!("expected Forward"),
        }
    }
}
