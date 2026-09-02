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
use crate::json_redact::{multipart_scan_output, redact_body_with_multipart_scan, scan_multipart_regions};
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
/// Prefix of the one-shot break-glass redemption inside `X-Cerberus-Bypass`
/// (`break-glass:<nonce>`; F2.3/R9-8). Anything else is the legacy reason.
const BREAK_GLASS_PREFIX: &str = "break-glass:";
/// Audit flag marking that the bypass was granted by a one-shot break-glass
/// token (the legacy reason bypass carries only the `bypass` flag).
pub(crate) const BREAK_GLASS_FLAG: &str = "break-glass";

/// Shape of an accepted data-plane bypass.
#[derive(Debug, Clone)]
enum BypassKind {
    /// Legacy `X-Cerberus-Bypass: <reason>` with valid admin auth. The raw
    /// reason is hashed (never persisted raw) and echoed back to the SAME
    /// caller in the feedback header.
    Legacy(String),
    /// One-shot redemption via `POST /api/break-glass` + `break-glass:<nonce>`
    /// (F2.3). Only the reason HASH travels here; the nonce is consumed
    /// atomically (exactly-once) by the ledger before this variant exists.
    OneShot {
        /// SHA-256 of the truncated reason (audit trail).
        reason_hash: String,
    },
}

impl BypassKind {
    /// Value echoed back in the response feedback header. For one-shot
    /// tokens it is the fixed marker `break-glass` (never the nonce, never
    /// the raw reason).
    fn feedback_ack(&self) -> &str {
        match self {
            Self::Legacy(reason) => reason,
            Self::OneShot { .. } => BREAK_GLASS_FLAG,
        }
    }

    /// Truncated+hashed reason for the audit event (`bypass-hash:<hex>`).
    ///
    /// R9-16 (F5.2): when the installation audit key is wired (product
    /// default), the hash is keyed HMAC-SHA256 over the break-glass domain;
    /// the unkeyed SHA-256 branch is the test-context fallback only.
    fn audit_hash(&self, audit_key: Option<&[u8]>) -> String {
        match self {
            Self::Legacy(reason) => {
                let truncated = truncate_bypass_reason(reason);
                audit_key.map_or_else(
                    || cerberus_engine::engine::hash_value(truncated),
                    |key| {
                        cerberus_engine::engine::domain_hash(
                            key,
                            cerberus_engine::engine::BREAK_GLASS_HASH_DOMAIN,
                            truncated.as_bytes(),
                        )
                    },
                )
            }
            Self::OneShot { reason_hash } => reason_hash.clone(),
        }
    }
}

/// Strip a well-known hash-format prefix (`hmac:`, `sha256:`), returning the
/// bare hex for the `bypass-hash:<hex>` audit artifact.
fn strip_hash_prefix(digest: &str) -> &str {
    digest
        .strip_prefix("hmac:")
        .or_else(|| digest.strip_prefix("sha256:"))
        .unwrap_or(digest)
}
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

/// Audit flag: redaction FAILED and the policy decided the outcome (the raw
/// original was forwarded on fail-open, the request rejected on fail-closed)
/// — the event must NEVER claim plain `redact` in that state (fix P2-2).
pub(crate) const REDACT_FAILED_FLAG: &str = "redact-failed";
/// Audit flag: the request passed through INTACT under `shadow` mode while
/// findings existed (the recorded action is what WOULD have happened) (P2-2).
pub(crate) const SHADOW_FLAG: &str = "shadow";
/// Audit flag: the body carried binary-claimed part payloads that were NOT
/// scanned (byte-exact preservation trade-off, §4.2) — under-scan must never
/// be silent (fix P2-1).
pub(crate) const BINARY_UNSCANNED_FLAG: &str = "binary-unscanned";
/// Audit flag: the body could not be decoded (JSON hint) and was forwarded
/// intact under `fail_policy: open`, or rejected (fail-closed) (P2-2).
pub(crate) const DECODE_FAILED_FLAG: &str = "decode-failed";

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
    // R9-5/F6.1: install the anti-rebinding Host/Origin policy (fail-closed
    // defaults) when the product wiring has not built an explicit one.
    {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        ctx.api.ensure_host_origin(&listen, &cfg);
    }
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
    // R9-5/F6.1: same default policy install as `spawn_proxy`.
    {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        ctx.api.ensure_host_origin(&listen, &cfg);
    }
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
    /// Redaction FAILED and the policy let the ORIGINAL body through
    /// (fail-open). The audit trail must never record this as a plain
    /// `redact` — the caller attaches the `redact-failed` flag and the
    /// honest action (fix P2-2).
    FailOpenForward(Vec<u8>),
    Reject(StatusCode, String),
}

/// Apply `fail_policy` to a redaction failure. Closed → 502 with
/// `{"error":"redact failure",...}` (the raw secret is NEVER sent);
/// Open → forward the ORIGINAL body and mark warn (real fail-open);
/// `closed-on-critical` (§4.1 default, R9-12) → reject ONLY when the request
/// carries `critical`-severity findings (the critical rules), otherwise
/// forward the original body (fail-open for the rest). `findings` is the
/// pipeline view of the request (post-allowlist).
#[must_use]
fn decide_redact_result(
    redaction: Result<Vec<u8>, String>,
    fail_policy: FailPolicy,
    original: &[u8],
    findings: &[cerberus_engine::engine::Finding],
) -> RedactDecision {
    match redaction {
        Ok(b) => RedactDecision::Forward(b),
        Err(e) => match fail_policy {
            FailPolicy::Closed => RedactDecision::Reject(
                StatusCode::BAD_GATEWAY,
                format!(r#"{{"error":"redact failure","detail":"{e}"}}"#),
            ),
            FailPolicy::ClosedOnCritical
                if findings
                    .iter()
                    .any(|f| f.severity == cerberus_engine::rule::Severity::Critical) =>
            {
                RedactDecision::Reject(
                    StatusCode::BAD_GATEWAY,
                    format!(r#"{{"error":"redact failure","detail":"{e}"}}"#),
                )
            }
            _ => {
                tracing::warn!(
                    "redaction failed — fail_policy={:?}, no critical findings, forwarding original body: {e}",
                    fail_policy
                );
                RedactDecision::FailOpenForward(original.to_vec())
            }
        },
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

    // API routes. `/ui` (F6.B, Appendix B B.6) is served here too: it is a
    // public 302 to `/api/dashboard`, so the documented
    // `http://localhost:8787/ui` URL never leaks into the dataplane.
    if direct_upstream.is_none() && (api::is_api_path(&path) || path == "/ui") {
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
    let (max_body, mode, fail_policy, reversible_redaction) = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        (cfg.max_body_bytes, cfg.mode, cfg.fail_policy, cfg.reversible_redaction)
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

    // Audited break-glass: the `X-Cerberus-Bypass` header is ONLY honored when
    // the request carries the valid admin token **via `X-Cerberus-Admin-Token`**
    // (fix review v4 #2, extended to ALL modes by R9-5/F6.2). Auth via
    // `Authorization: Bearer` is valid for `/api/*`, but on the DATA PLANE
    // we require exclusively the own header, to avoid risking substituting
    // the provider key (which travels in `Authorization`) with the admin
    // token.
    //
    // R9-5/F6.2 — FAIL-CLOSED EVERYWHERE: with a configured token and
    // missing/invalid auth the header is IGNORED (it does not block) and a
    // warn is logged. WITHOUT a configured token (dev mode) the bypass is
    // now REFUSED too — the old "dev mode: bypass open" was the F4-verified
    // injection vector (an unauthenticated `X-Cerberus-Bypass` smuggled a
    // secret past the scanner); there is no valid credential to check, so
    // there is no bypass, and the request proceeds to the normal scan.
    //
    // F2.3 (R9-8): the header carries either a plain reason (legacy audited
    // bypass, unchanged) or `break-glass:<nonce>` — the one-shot primitive
    // issued (authenticated) via `POST /api/break-glass`. A nonce is consumed
    // ATOMICALLY exactly once; a replay, an expired token or a provider-scope
    // mismatch REFUSES the bypass (the request proceeds to the normal scan
    // and is blocked if findings require it). No valid admin token → no
    // bypass; both mechanisms share the same audit trail.
    let provider = direct_upstream.as_ref().map_or_else(
        || provider_of(path.as_str(), ctx),
        |direct| mitm_provider_of(ctx, &direct.provider),
    );

    // R9-11 (§4.7): the operation mode may be set PER UPSTREAM
    // (`mode: shadow|enforce` in `UpstreamConfig`). An upstream without an
    // explicit mode inherits the global `ProxyConfig::mode` — a shadow
    // upstream never blocks/redacts, an enforce upstream enforces, mixed
    // fleets route each request by its provider.
    let mode = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        cfg.upstreams.get(&provider).and_then(|u| u.mode).unwrap_or(mode)
    };
    let bypass: Option<BypassKind> = {
        let present = parts
            .headers
            .get(BYPASS_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        present.and_then(|raw| {
            let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
            match api::expected_admin_token(&cfg) {
                // R9-5/F6.2: NO token configured (dev mode) → the bypass is
                // REFUSED. There is no valid credential to authenticate it,
                // and an unauthenticated bypass is the F4 injection vector.
                None => {
                    tracing::warn!(
                        "X-Cerberus-Bypass refused: no admin token is configured, so the \
                         data-plane bypass cannot be authenticated (fail-closed, R9-5/F6.2)"
                    );
                    drop(cfg);
                    return None;
                }
                // Token config: the data-plane bypass is honored ONLY by the
                // `X-Cerberus-Admin-Token` header (not by `Authorization`).
                Some(expected) => {
                    if api::admin_token_header_is_present(&parts.headers, expected) {
                        // authenticated
                    } else {
                        if api::authorized(&parts.headers, expected) {
                            tracing::warn!(
                                "X-Cerberus-Bypass ignored: data-plane bypass requires the {} header, \
                                 not Authorization (avoids overwriting the provider API key)",
                                ADMIN_TOKEN_HEADER
                            );
                        }
                        return None;
                    }
                }
            }
            drop(cfg);
            // Owned intermediate: the nonce is trimmed/copied so the legacy
            // arm can take `raw` by value (map_or_else over if-let-else).
            raw.strip_prefix(BREAK_GLASS_PREFIX)
                .map(str::trim)
                .map(ToString::to_string)
                .map_or_else(
                    || Some(BypassKind::Legacy(raw)),
                    |nonce| match ctx.api.break_glass.redeem(&nonce, Some(provider.as_str())) {
                        Ok(grant) => Some(BypassKind::OneShot {
                            reason_hash: grant.reason_hash,
                        }),
                        Err(e) => {
                            tracing::warn!("break-glass redemption refused: {e}");
                            None
                        }
                    },
                )
        })
    };

    // Decode and scan, wrapping the engine phase in the failure policy
    // (fix P1 #2): fail_policy=Open → if the engine cannot decode/redact
    // the ORIGINAL body is forwarded intact; Closed → 502. With the
    // `closed-on-critical` default (R9-12) an UNDECODABLE body has no
    // findings, so criticality is indeterminate → fail-closed posture
    // (same observable behavior as Closed here; documented in the pack).
    let content_type_hint = parts.headers.get("content-type").and_then(|v| v.to_str().ok());
    let decoded = decode(&body_bytes, content_type_hint);
    // Decode failure: content-type declares JSON but the body is not valid JSON.
    let json_hint = content_type_hint.is_some_and(|h| h.to_ascii_lowercase().contains("json"));
    let decode_failed = json_hint && decoded.content_type != ContentType::Json;
    // Outcome flags for the audit trail (fix P2-2/P2-1): every fail-open /
    // fail-closed / under-scan outcome is visible in the event flags.
    let mut audit_flags: Vec<String> = Vec::new();
    if decode_failed {
        audit_flags.push(DECODE_FAILED_FLAG.to_string());
    }
    if decode_failed && fail_policy != FailPolicy::Open {
        // Fail-closed outcome (P2-2): audited honestly, never silently.
        record_outcome_event(
            ctx,
            provider.as_str(),
            &[],
            cerberus_engine::rule::Action::Allow,
            &audit_flags,
            "fail-closed",
        )
        .await;
        return json_status(StatusCode::BAD_GATEWAY, r#"{"error":"cannot decode"}"#);
    }
    if decode_failed {
        // fail_policy=Open: a non-decodable body cannot be scanned; it is
        // forwarded intact and marked in the log and the audit (P2-2).
        tracing::warn!("decode failed for json content-type; fail_policy=open — forwarding original body");
    }
    // Snapshot of the engine for the whole request (hot-reload): the Arc is
    // cloned under the brief lock; scan+redact use the same snapshot → no
    // half-swapped pack is visible mid-request.
    let engine_snap = ctx.engine.read().unwrap_or_else(|p| p.into_inner()).clone();
    // FIX F-1/P1-3 (attempt 2): ONE authoritative scan pass per body feeds
    // BOTH the pipeline decision (block/redact/criticality) AND the
    // redaction. For multipart that pass is per-REGION (payloads, part
    // headers, preamble, epilogue — whatever the decoder recorded) with one
    // shared analyzer over the full body, exactly the model the redaction
    // splices with; for JSON/text the pass is the whole decoded text. There
    // is no surface left where a region re-scan can fire a rule the
    // decision never saw — the redaction performs NO scan of its own.
    let allowlist = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        cfg.policy.allowlist.clone()
    };
    let audit_key_for_allowlist = ctx.api.audit_hash_key().map(std::vec::Vec::from);
    let (scan_result, multipart_scan) = if decode_failed {
        (
            ScanOutput {
                findings: Vec::new(),
                action_overall: cerberus_engine::rule::Action::Allow,
            },
            None,
        )
    } else if decoded.content_type == ContentType::Multipart && decoded.multipart.is_some() {
        let scan = scan_multipart_regions(
            &engine_snap,
            &body_bytes,
            decoded.multipart.as_deref().unwrap_or(&[]),
            &allowlist,
            audit_key_for_allowlist.as_deref(),
        );
        (multipart_scan_output(&scan), Some(scan))
    } else {
        let mut s = engine_snap.scan(&decoded.text);
        // Allowlist (false-positive triage) — applied in the real path (P0-5).
        filter_with_allowlist(&allowlist, audit_key_for_allowlist.as_deref(), &decoded.text, &mut s);
        (s, None)
    };

    let mode_result = shadow::apply_mode(&scan_result, mode);
    let has_findings = !scan_result.findings.is_empty();
    let is_shadow = matches!(mode_result, shadow::ModeResult::Shadow { .. });
    if is_shadow && has_findings {
        // Shadow events record what WOULD have happened while the body
        // passes intact — the flag makes that unmistakable (fix P2-2).
        audit_flags.push(SHADOW_FLAG.to_string());
    }
    if decoded.binary_parts_skipped > 0 {
        // Byte-exact preservation trade-off made visible (fix P2-1): the
        // request carried binary-claimed payloads that were never scanned.
        audit_flags.push(BINARY_UNSCANNED_FLAG.to_string());
        tracing::warn!(
            count = decoded.binary_parts_skipped,
            "multipart body carries binary-claimed part payloads that were not scanned (byte-exact preservation, §4.2)"
        );
    }

    // Block (Enforce + critical) — unless bypass.
    let blocked = bypass.is_none() && !mode_result.should_forward();
    if blocked {
        let flag = scan_result.findings.first().map_or("unknown", |f| f.flag.as_str());
        log_security_event(
            SecurityEvent::Blocked,
            &scan_result.findings,
            scan_result.action_overall,
        );
        // Record event in the store (`provider` computed before the bypass
        // block; F2.3 needs it early for the one-shot scope check).
        record_only_with_findings(ctx, &scan_result, provider.as_str()).await;
        let mut r = json_status(
            StatusCode::FORBIDDEN,
            &format!(r#"{{"error":"blocked","flag":"{flag}"}}"#),
        )?;
        add_feedback_headers(&mut r, &scan_result, bypass.as_ref().map(BypassKind::feedback_ack));
        return Ok(r);
    }

    // Enforce: apply redaction (only in enforce; shadow passes intact).
    // If the internal redaction fails, the failure policy decides: Open →
    // forward the original body (real fail-open); Closed → 502 (fix review v4
    // #5: before the `apply_redaction` error was swallowed in json_redact and
    // the raw secret passed through even though the JSON failed).
    //
    // F2.2 (R9-8): with `reversible_redaction` (opt-in, closed decision §9 #4)
    // a REQUEST-SCOPED vault is created here — it lives exactly for this
    // request/response cycle (capacity/TTL bounded, zeroized on
    // consume/expiry/clear/drop) and is used to store the originals that
    // restore the response below. Nothing is shared across requests.
    //
    // FIX F-1 (attempt 2): the redaction receives the AUTHORITATIVE
    // per-region scan (`multipart_scan`) the decision above was made from —
    // it performs no scan of its own, so a failure can only ever be caused
    // by a finding the criticality oracle saw.
    let request_vault: Option<cerberus_engine::vault::Vault> =
        reversible_redaction.then(cerberus_engine::vault::Vault::new);
    let mut redact_failed_open = false;
    let final_bytes = if matches!(mode_result, shadow::ModeResult::Enforce { .. })
        && mode_result.action() == cerberus_engine::rule::Action::Redact
    {
        let redaction = redact_body_with_multipart_scan(
            &engine_snap,
            &body_bytes,
            &decoded,
            &ctx.redact_options,
            &scan_result.findings,
            request_vault.as_ref(),
            multipart_scan.as_ref(),
        );
        match decide_redact_result(redaction, fail_policy, &body_bytes, &scan_result.findings) {
            RedactDecision::Forward(b) => b,
            // Fail-open outcome (fix P2-2): the ORIGINAL body is forwarded —
            // audited with the honest action + flag, never as plain "redact".
            RedactDecision::FailOpenForward(b) => {
                redact_failed_open = true;
                audit_flags.push(REDACT_FAILED_FLAG.to_string());
                b
            }
            // Fail-closed outcome (fix P2-2): the request is rejected —
            // audited honestly with the same flag.
            RedactDecision::Reject(status, reason) => {
                audit_flags.push(REDACT_FAILED_FLAG.to_string());
                record_outcome_event(
                    ctx,
                    provider.as_str(),
                    &scan_result.findings,
                    scan_result.action_overall,
                    &audit_flags,
                    "fail-closed",
                )
                .await;
                return json_status(status, &reason);
            }
        }
    } else {
        body_bytes.to_vec()
    };

    // Log sec event (by intervention type).
    let sec_event = if redact_failed_open {
        SecurityEvent::RedactFailed
    } else if mode_result.action() == cerberus_engine::rule::Action::Block {
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
    // (`provider` was computed before the bypass block for the one-shot scope check.)
    if has_findings {
        let is_bypass = bypass.is_some();
        if is_bypass {
            // Audited break-glass (review 2, P1 #6): the authorized leak is
            // persisted as "bypass" with its reason — not as a fake block.
            // Both the legacy reason header and the F2.3 one-shot primitive
            // share this same audit trail.
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
            // `flags` only carries the "bypass" marker (plus "break-glass"
            // when the bypass came from the F2.3 one-shot primitive); the
            // reason (truncated to 200 bytes) is stored hashed in
            // `hashed_values` as `bypass-hash:<hex>` — keyed HMAC-SHA256
            // (R9-16/F5.2) when the installation key is wired.
            event.flags.push("bypass".to_string());
            if let Some(BypassKind::OneShot { .. }) = &bypass {
                event.flags.push(BREAK_GLASS_FLAG.to_string());
            }
            if let Some(kind) = &bypass {
                let digest = kind.audit_hash(ctx.api.audit_hash_key());
                event
                    .hashed_values
                    .push(format!("bypass-hash:{}", strip_hash_prefix(&digest)));
            }
        }
        // Outcome honesty (fix P2-2): a fail-open forward is never recorded
        // as a plain "redact" — the action names the outcome and the
        // `redact-failed` flag carries the cause. Shadow and under-scan
        // outcomes carry their flags too.
        if redact_failed_open {
            event.action_taken = "fail-open".to_string();
        }
        event.flags.extend(audit_flags.iter().cloned());
        api::record_event(&ctx.api, event).await;
    } else if !audit_flags.is_empty() {
        // No findings, but the outcome must still be visible (fix P2-1/P2-2):
        // `binary-unscanned` (byte-exact preservation trade-off) or
        // `decode-failed` under fail-open. Without this the under-scan would
        // be silent. The action names the outcome honestly.
        let action_taken = if audit_flags.iter().any(|f| f == DECODE_FAILED_FLAG) {
            "fail-open"
        } else {
            "allow"
        };
        record_outcome_event(
            ctx,
            provider.as_str(),
            &[],
            scan_result.action_overall,
            &audit_flags,
            action_taken,
        )
        .await;
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
    // `closed-on-critical` (R9-12) is an ENGINE-failure policy; a connection
    // failure carries no criticality signal → closed posture (503).
    let resp = match tokio::time::timeout(std::time::Duration::from_secs(30), client.request(up_req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            // fail_policy Closed/closed-on-critical → 503 (proxy failure);
            // Open → 502 and we surface the visible error (review 2, P1 #7).
            let status = if fail_policy == crate::config::FailPolicy::Open {
                StatusCode::BAD_GATEWAY
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            return json_status(status, &format!(r#"{{"error":"upstream failure","detail":"{e}"}}"#));
        }
        Err(_) => {
            let status = if fail_policy == crate::config::FailPolicy::Open {
                StatusCode::BAD_GATEWAY
            } else {
                StatusCode::SERVICE_UNAVAILABLE
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

    // F2.2 (R9-8): non-streaming un-redaction. The response is fully
    // buffered (streaming is out of MVP), so the request-scoped vault can
    // restore the original values of the `[VAULT:<id>]` tokens present in
    // the response and consume+zeroize the used entries. `request_vault` is
    // dropped right after — end of the request lifecycle, memory wiped.
    let resp_bytes: Bytes = match &request_vault {
        Some(vault) => Bytes::from(vault.unredact(&resp_bytes)),
        None => resp_bytes,
    };

    let mut response = Response::new(Full::new(resp_bytes.clone()));
    *response.status_mut() = resp_parts.status;
    // Filter hop-by-hop headers from the response (fix P1 #6): tokens from
    // `Connection` + fixed list (te, trailer, proxy-authenticate, ...).
    *response.headers_mut() = filter_response_headers(&resp_parts.headers);
    // F2.2 (R9-8): un-redaction rewrote the body, so the upstream's
    // `content-length` no longer describes it — recompute it (a stale
    // header breaks the HTTP framing).
    if request_vault.is_some() {
        if let Ok(hv) = resp_bytes.len().to_string().parse() {
            response.headers_mut().insert("content-length", hv);
        }
    }
    add_feedback_headers(
        &mut response,
        &scan_result,
        bypass.as_ref().map(BypassKind::feedback_ack),
    );
    Ok(response)
}

/// Allowlist filter over a snapshot (fix F-1/P1-3 attempt 2): the pipeline
/// reads the shared config allowlist once per request and applies the SAME
/// semantics on every scan view — whole-text offsets on JSON/text, and the
/// region-relative raw value on the multipart authoritative scan (the raw
/// value sliced from the region text, trimmed, exact match).
///
/// R9-7/F6.3: entries are **HMAC fingerprints** (`hmac:<hex>`, domain
/// `cerberus:allowlist:v1`). A finding is allowed when the fingerprint of the
/// raw candidate (sliced from the text and trimmed — the same normalization
/// the fingerprinting applies) is present in the set. The fingerprints are
/// resolved into a `HashSet` lazily (only when findings exist) so the hot
/// path pays at most one HMAC per finding plus the set lookup.
///
/// Unkeyed context (`None` — direct library tests only; the daemon always
/// keys via `ApiContext::with_audit_hash_key`): fingerprints cannot be
/// evaluated, so NOTHING is filtered — fail-closed for detection (the
/// allowlist can never silently widen what passes).
fn filter_with_allowlist(allow: &[String], key: Option<&[u8]>, text: &str, scan: &mut ScanOutput) {
    if allow.is_empty() {
        return;
    }
    let Some(key) = key else {
        return; // unkeyed test context: cannot evaluate fingerprints (documented)
    };
    let fingerprints: std::collections::HashSet<&str> = allow.iter().map(String::as_str).collect();
    scan.findings.retain(|f| {
        if f.end <= text.len() {
            let raw = text[f.start..f.end].trim();
            let candidate = crate::allowlist::fingerprint(key, raw);
            !fingerprints.contains(candidate.as_str())
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

/// Host of an upstream `url` (e.g. `https://api.openai.com/v1` →
/// `api.openai.com`), lowercased. `None` when the URL does not parse.
#[must_use]
fn upstream_url_host(url: &str) -> Option<String> {
    url.parse::<Uri>().ok()?.host().map(str::to_ascii_lowercase)
}

/// Resolve the CONNECT hostname of an intercepted (MITM) tunnel to the
/// upstream KEY the config itself keys on (fix P1-2, attempt 2).
///
/// Before this fix `DirectUpstream.provider` was the raw CONNECT hostname
/// (`api.openai.com`), so the per-upstream `mode` lookup
/// (`cfg.upstreams.get(&provider)`) only ever matched operators who literally
/// named an upstream entry by hostname — per-upstream mode was silently inert
/// on the MITM path and a per-upstream `enforce` could silently shadow under
/// a global `shadow`. Resolution order:
///
/// 1. **Exact key** — the documented hostname-keying convention (unchanged).
/// 2. **URL-host match** — the upstream whose `url` host equals the CONNECT
///    host (case-insensitive); deterministic name-order tiebreak when several
///    upstreams share one host. This is "the config's own keying": operators
///    name upstreams (`openai`) and point them at provider URLs.
/// 3. **The hostname itself** — traffic to a host no upstream covers keeps
///    the hostname as the provider (audit shows the raw host) and inherits
///    the global mode, exactly like an unknown provider on the reverse-proxy
///    path (documented R9-11 fallback).
#[must_use]
fn mitm_provider_of(ctx: &ProxyContext, connect_host: &str) -> String {
    let upstreams = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        cfg.upstreams.clone()
    };
    if upstreams.contains_key(connect_host) {
        return connect_host.to_string();
    }
    let host = connect_host.to_ascii_lowercase();
    let mut matched: Vec<(&String, &crate::config::UpstreamConfig)> = upstreams
        .iter()
        .filter(|(_, up)| upstream_url_host(&up.url).is_some_and(|h| h == host))
        .collect();
    matched.sort_by(|(a, _), (b, _)| (*a).cmp(*b));
    if let Some((name, _)) = matched.first() {
        tracing::debug!(
            connect_host = %connect_host,
            upstream = %name,
            "MITM CONNECT host mapped to the upstream configured for that URL host"
        );
        return (*name).clone();
    }
    tracing::debug!(
        connect_host = %connect_host,
        "MITM CONNECT host matches no configured upstream — inheriting the global mode"
    );
    connect_host.to_string()
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

/// Record the OUTCOME of a request whose audit story is carried entirely by
/// flags and the honest action (fix P2-2/P2-1): fail-open / fail-closed
/// outcomes after a redaction or decode failure, and under-scan visibility
/// (`binary-unscanned`) when no findings exist. Never contains raw values.
async fn record_outcome_event(
    ctx: &ProxyContext,
    provider: &str,
    findings: &[cerberus_engine::engine::Finding],
    action_overall: cerberus_engine::rule::Action,
    flags: &[String],
    action_taken: &str,
) {
    let mut event =
        cerberus_store::event::AuditEvent::from_findings(findings, action_overall, "local", "proxy", provider);
    event.action_taken = action_taken.to_string();
    event.flags.extend(flags.iter().cloned());
    api::record_event(&ctx.api, event).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── R9-16 (F5.2): the bypass audit hash is keyed by product default ───

    #[test]
    fn legacy_bypass_audit_hash_is_keyed_when_the_installation_key_is_wired() {
        let kind = BypassKind::Legacy("operator reason".to_string());
        let keyed = kind.audit_hash(Some(b"installation-key"));
        assert!(keyed.starts_with("hmac:"), "keyed digest format: {keyed:?}");
        let unkeyed = kind.audit_hash(None);
        assert!(unkeyed.starts_with("sha256:"), "test fallback format: {unkeyed:?}");
        assert_ne!(keyed, unkeyed, "keying must change the digest");
        // The audit artifact carries the bare hex under `bypass-hash:`.
        assert_eq!(strip_hash_prefix(&keyed), keyed.trim_start_matches("hmac:"));
        assert!(
            !strip_hash_prefix(&keyed).contains(':'),
            "bare hex, got {}",
            strip_hash_prefix(&keyed)
        );
    }

    #[test]
    fn strip_hash_prefix_handles_both_schemes() {
        assert_eq!(strip_hash_prefix("hmac:abc123"), "abc123");
        assert_eq!(strip_hash_prefix("sha256:abc123"), "abc123");
        assert_eq!(strip_hash_prefix("abc123"), "abc123");
    }

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
                mode: None,
                expected_auth: None,
            },
        );
        upstreams.insert(
            "default".to_string(),
            crate::config::UpstreamConfig {
                url: "http://mock.local".to_string(),
                path_prefix: Some("/myproj".to_string()),
                auth_header: "authorization".to_string(),
                mode: None,
                expected_auth: None,
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
                mode: None,
                expected_auth: None,
            },
        );
        upstreams.insert(
            "longer".to_string(),
            crate::config::UpstreamConfig {
                url: "http://longer.local".to_string(),
                path_prefix: Some("/v1/admin".to_string()),
                auth_header: "authorization".to_string(),
                mode: None,
                expected_auth: None,
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
        match decide_redact_result(Err("invalid span".to_string()), FailPolicy::Closed, original, &[]) {
            RedactDecision::Reject(status, body) => {
                assert_eq!(status, StatusCode::BAD_GATEWAY, "closed → 502");
                assert!(body.contains("redact failure"), "body: {body}");
                assert!(!body.contains("RAW-SECRET"), "raw secret leaked into 502: {body}");
            }
            RedactDecision::Forward(_) | RedactDecision::FailOpenForward(_) => panic!("expected Reject"),
        }
    }

    #[test]
    fn redact_failure_fail_open_forwards_original() {
        // Review v4 #5: fail_policy=Open → the ORIGINAL body is forwarded intact
        // (marked warn) and an OK redact is forwarded as is. Fix P2-2: the
        // fail-open outcome is its OWN variant so the audit can never record
        // it as a plain "redact".
        let original = b"raw-original-bytes".to_vec();
        match decide_redact_result(Err("oops".to_string()), FailPolicy::Open, &original, &[]) {
            RedactDecision::FailOpenForward(b) => assert_eq!(b, original, "open forwards original"),
            RedactDecision::Forward(_) | RedactDecision::Reject(..) => panic!("expected FailOpenForward"),
        }
        match decide_redact_result(Ok(b"redacted".to_vec()), FailPolicy::Closed, &original, &[]) {
            RedactDecision::Forward(b) => assert_eq!(b, b"redacted".to_vec()),
            RedactDecision::FailOpenForward(_) | RedactDecision::Reject(..) => panic!("expected Forward"),
        }
    }

    // ── R9-12: `closed-on-critical` redaction-failure decision table ──

    fn finding_with_severity(severity: cerberus_engine::rule::Severity) -> cerberus_engine::engine::Finding {
        cerberus_engine::engine::Finding {
            flag: "secret.test".to_string(),
            category: cerberus_engine::rule::Category::Secrets,
            severity,
            action: cerberus_engine::rule::Action::Redact,
            start: 0,
            end: 1,
            hashed_value: "sha256:test".to_string(),
        }
    }

    #[test]
    fn closed_on_critical_rejects_when_critical_findings_present() {
        // §4.1: fail-closed for critical rules — a redaction failure on a
        // request with critical findings is a 502, the raw secret never
        // leaves.
        let original = br#"{"content":"RAW-SECRET-DO-NOT-LEAK999"}"#;
        let findings = [finding_with_severity(cerberus_engine::rule::Severity::Critical)];
        match decide_redact_result(
            Err("invalid span".to_string()),
            FailPolicy::ClosedOnCritical,
            original,
            &findings,
        ) {
            RedactDecision::Reject(status, body) => {
                assert_eq!(status, StatusCode::BAD_GATEWAY, "critical finding → fail closed");
                assert!(!body.contains("RAW-SECRET"), "raw secret leaked: {body}");
            }
            RedactDecision::Forward(_) | RedactDecision::FailOpenForward(_) => {
                panic!("expected Reject for critical findings")
            }
        }
    }

    #[test]
    fn closed_on_critical_forwards_original_for_non_critical_findings() {
        // §4.1: fail-open for the rest — a redaction failure with only
        // non-critical findings forwards the ORIGINAL body (real fail-open).
        let original = b"non-critical-original".to_vec();
        let findings = [
            finding_with_severity(cerberus_engine::rule::Severity::Low),
            finding_with_severity(cerberus_engine::rule::Severity::High),
        ];
        match decide_redact_result(
            Err("oops".to_string()),
            FailPolicy::ClosedOnCritical,
            &original,
            &findings,
        ) {
            RedactDecision::FailOpenForward(b) => {
                assert_eq!(b, original, "non-critical → fail open");
            }
            RedactDecision::Forward(_) | RedactDecision::Reject(..) => {
                panic!("expected FailOpenForward for non-critical findings")
            }
        }
    }

    #[test]
    fn closed_on_critical_forwards_original_when_no_critical_findings() {
        // §4.1: fail-open for the rest — a redaction failure with no
        // critical findings forwards the ORIGINAL body (real fail-open).
        // (Indeterminate criticality — undecodable bodies — is decided at
        // the decode site, which fails closed for everything but Open.)
        let original = b"non-critical-original".to_vec();
        match decide_redact_result(Err("oops".to_string()), FailPolicy::ClosedOnCritical, &original, &[]) {
            RedactDecision::FailOpenForward(b) => assert_eq!(b, original, "no critical findings → fail open"),
            RedactDecision::Forward(_) | RedactDecision::Reject(..) => {
                panic!("expected FailOpenForward when no critical findings")
            }
        }
    }

    #[test]
    fn redact_failure_fail_closed_is_its_own_variant() {
        // Fix P2-2: the reject outcome is distinct from both Forward and
        // FailOpenForward, so the audit records "fail-closed" honestly.
        let original = b"original".to_vec();
        match decide_redact_result(Err("boom".to_string()), FailPolicy::Closed, &original, &[]) {
            RedactDecision::Reject(status, body) => {
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert!(body.contains("redact failure"));
            }
            RedactDecision::Forward(_) | RedactDecision::FailOpenForward(_) => panic!("expected Reject"),
        }
    }

    // ── Fix P1-2 (attempt 2): MITM CONNECT host → upstream key mapping ──

    #[test]
    fn upstream_url_host_parses_scheme_and_port() {
        assert_eq!(
            upstream_url_host("https://api.openai.com").as_deref(),
            Some("api.openai.com")
        );
        assert_eq!(
            upstream_url_host("https://api.openai.com/v1/chat").as_deref(),
            Some("api.openai.com")
        );
        assert_eq!(
            upstream_url_host("http://API.Example.COM:8080/x").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(upstream_url_host("not a url"), None);
    }

    #[test]
    fn mitm_provider_maps_connect_host_to_upstream_url_host() {
        // Fix P1-2: the CONNECT hostname (`api.nanbuilders.test`) must resolve
        // to the upstream KEYED `nanbuilders` whose URL points at that host,
        // so the per-upstream `mode` applies on the MITM path.
        let mut upstreams = std::collections::HashMap::new();
        upstreams.insert(
            "nanbuilders".to_string(),
            crate::config::UpstreamConfig {
                url: "https://api.nanbuilders.test/v1".to_string(),
                path_prefix: None,
                auth_header: "authorization".to_string(),
                mode: Some(crate::config::OperationMode::Enforce),
                expected_auth: None,
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
        assert_eq!(mitm_provider_of(&ctx, "api.nanbuilders.test"), "nanbuilders");
        // An unconfigured host keeps the hostname as the provider (global
        // mode fallback, documented R9-11 behavior).
        assert_eq!(mitm_provider_of(&ctx, "unknown.host.test"), "unknown.host.test");
    }

    #[test]
    fn mitm_provider_exact_hostname_key_wins_and_mapping_is_deterministic() {
        // 1) The documented hostname-keying convention still wins.
        // 2) Two upstreams sharing one URL host resolve deterministically
        //    (name order).
        let mut upstreams = std::collections::HashMap::new();
        upstreams.insert(
            "byhost.test".to_string(),
            crate::config::UpstreamConfig {
                url: "https://other-place.test".to_string(),
                path_prefix: None,
                auth_header: "authorization".to_string(),
                mode: Some(crate::config::OperationMode::Shadow),
                expected_auth: None,
            },
        );
        upstreams.insert(
            "zeta".to_string(),
            crate::config::UpstreamConfig {
                url: "https://api.shared.test".to_string(),
                path_prefix: None,
                auth_header: "authorization".to_string(),
                mode: Some(crate::config::OperationMode::Enforce),
                expected_auth: None,
            },
        );
        upstreams.insert(
            "alpha".to_string(),
            crate::config::UpstreamConfig {
                url: "https://api.shared.test".to_string(),
                path_prefix: None,
                auth_header: "authorization".to_string(),
                mode: Some(crate::config::OperationMode::Enforce),
                expected_auth: None,
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
        // Exact key beats URL-host matching (documented convention).
        assert_eq!(mitm_provider_of(&ctx, "byhost.test"), "byhost.test");
        // URL-host tiebreak: alpha < zeta by name, deterministic.
        assert_eq!(mitm_provider_of(&ctx, "api.shared.test"), "alpha");
        // An URL host that only the exact-key upstream points at.
        assert_eq!(mitm_provider_of(&ctx, "other-place.test"), "byhost.test");
    }
}
