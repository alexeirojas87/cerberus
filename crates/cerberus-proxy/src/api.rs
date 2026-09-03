//! Config API — HTTP handlers for reading/writing proxy configuration
//! and querying audit events / stats (§4.6 of the build plan).
//!
//! Routes:
//! - `GET  /api/config` — get current config (`admin_token` redacted,
//!   review v6 F6: the value is never leaked; `admin_token_configured` is
//!   exposed)
//! - `PUT  /api/config` — update config (**real** hot-reload; review v6 F6:
//!   persists to YAML if `ApiContext.config_path` is set, and reports
//!   `requires_restart:true` when `listen` changed — the rebind is NOT live)
//! - `GET  /api/events` — recent events (with optional filters)
//! - `GET  /api/stats` — aggregated statistics
//! - `POST /api/allowlist` — add to allowlist (FP triage)
//! - `POST /api/break-glass` — issue a one-shot bypass token (F2.3/R9-8;
//!   authenticated; nonce redeemed once via `X-Cerberus-Bypass`)
//! - `GET  /api/upstreams` — list upstreams/providers `{name,url,auth_header,mode}`
//! - `POST /api/upstreams` — add an upstream `{name,url,auth_header?,mode?}`
//! - `DELETE /api/upstreams/{name}` — remove a provider (not the last one)
//!   (upstream CRUD: review v6 F6, UI/API parity. Each mutation persists
//!   to YAML with the SAME policy as `PUT /api/config`.)
//! - `GET  /api/policy` — policy overlay: categories, custom rules,
//!   allowlist and valid actions (F6 "config-screens", §4.6 of the plan)
//! - `PUT  /api/policy` — overlay patch (`null` on a value deletes it)
//! - `GET  /api/allowlist` — current allowlist (one-click FP triage)
//! - `DELETE /api/allowlist` — remove an entry (`{"value":"…"}`)
//!
//! ## Review v6.1 — config as DTO and transactional persistence
//!
//! `GET`/`PUT /api/config` do NOT use [`ProxyConfig`] as the API type:
//! - [`ConfigView`] is the `GET` response. By construction it has no
//!   `admin_token` field, so the secret cannot leak by oversight; it
//!   exposes the derived boolean `admin_token_configured`.
//! - [`ConfigPatch`] is the `PUT` body. Absent fields are PRESERVED
//!   (patch semantics): omitting `admin_token` leaves the live token intact
//!   and `admin_token_configured` is accepted but IGNORED (read-only).
//! - Before touching memory or disk, the control plane exposure is
//!   revalidated (`listen` non-loopback ⇒ token ≥ 24 bytes), the same rule
//!   `proxy::check_listen_security` applies when binding.
//! - Persistence is **transactional from the in-memory perspective**: the
//!   candidate is computed, validated, written to YAML and ONLY if all of
//!   that succeeds is it published to memory. If anything fails, the live
//!   config stays exactly as it was.
#![allow(
    clippy::significant_drop_tightening,
    clippy::unused_async,
    clippy::redundant_closure_for_method_calls,
    clippy::needless_borrows_for_generic_args
)]

use std::sync::{Arc, RwLock};

use bytes::Bytes;
use cerberus_store::event::AuditEvent;
use cerberus_store::stats;
use cerberus_store::store::AuditStore;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::config::{ProxyConfig, UpstreamConfig};
use cerberus_packs::wire::{PackInstallRequest, MAX_PACK_BODY_BYTES};

/// Rule pack operation command. The control plane sends it to the daemon
/// worker (fix review v5: real hot-reload and durable rollback).
///
/// `reply` is a oneshot that carries the result back to the caller.
#[derive(Debug)]
pub enum PackCommand {
    /// Install the signed content received by the control plane; the worker
    /// never interprets filesystem paths of the client.
    Install {
        /// Already-validated wire v2 request, bounded by size.
        request: PackInstallRequest,
        /// oneshot that returns the result to the control-plane caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Revert to the last persisted activation (durable rollback).
    Rollback {
        /// oneshot that returns the result to the caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// List packs with state.
    List {
        /// oneshot that returns the result to the caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Enable a pack by name (Appendix B B.3 `packs enable`); the worker
    /// flips the manifest flag and hot-reloads the engine.
    Enable {
        /// Pack name (metadata name, not a versioned key).
        name: String,
        /// oneshot that returns the result to the caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Disable a pack by name (rules leave the engine; JSON stays on disk).
    Disable {
        /// Pack name.
        name: String,
        /// oneshot that returns the result to the caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Re-verify every installed pack signature and hot-reload (F6 contract
    /// of `packs update`; registry fetch is the F7 auto-update unit).
    Update {
        /// oneshot that returns the result to the caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
}

/// Canonical header for the admin token. Always accepted on `/api/*` and on
/// the data-plane bypass (review v4 #2). Never forwarded to the upstream.
pub const ADMIN_TOKEN_HEADER: &str = "x-cerberus-admin-token";

/// Minimum length (bytes) required for the admin token on non-loopback
/// interfaces (review v4 #1).
///
/// A token below this threshold leaves the control plane open; on loopback
/// tokenless dev-mode is allowed (documented).
pub const ADMIN_TOKEN_MIN_BYTES: usize = 24;

/// Maximum body limit for the `/api/*` control-plane routes (1 MiB,
/// review v4 #4). The data-plane limit (`max_body_bytes`) applies separately
/// and is not touched.
///
/// KNOWN LIMIT (F6.B attempt 2, security P3-2 — documented, by design): the
/// build plan's "100 KB scan budget" describes the scan BUDGET SHAPE (how
/// much text a dry-run may cost), while `POST /api/scan` here is bounded by
/// this shared 1 MiB CONTROL-PLANE limit like every other `/api/*` body.
/// Empirically bounded either way (10 MB → 413; 954 KB → ~38 ms linear
/// scan); a scan-specific cap would be a behavior change and stays out of
/// this fix (see evidence pack, attempt 2).
const CONTROL_PLANE_MAX_BYTES: usize = MAX_PACK_BODY_BYTES;

/// Shared context for the API.
#[derive(Clone)]
pub struct ApiContext {
    /// Current proxy config (shared with the hot path).
    pub config: Arc<RwLock<ProxyConfig>>,
    /// In-memory audit event list.
    pub events: Arc<Mutex<Vec<AuditEvent>>>,
    /// `SQLite` store for event persistence (optional).
    pub store: Option<Arc<AuditStore>>,
    /// Channel to the daemon rule-pack worker (F7). When present, the
    /// `/api/packs/*` routes (install/rollback/list) are enabled with real
    /// hot-reload of the active engine (fix review v5).
    pub pack_worker: Option<tokio::sync::mpsc::Sender<PackCommand>>,
    /// Path of the config YAML file (review v6 F6). When `Some`, every
    /// config mutation (PUT /api/config and upstream CRUD) does a
    /// `serde_yaml::to_string` + atomic write (temp + rename) to that path.
    /// `None` (tests/dev) = no persistence (no failure).
    pub config_path: Option<std::path::PathBuf>,

    /// Control handle for the dataplane's live engine (fix review v6.1). When
    /// `Some`, a policy change (categories, custom rules, overrides) is
    /// **compiled and published** into the engine the hot path reads: the
    /// dataplane changes rules without restarting and without losing the
    /// pack rules. `None` (tests/dev) = the policy is validated and
    /// persisted, but there is no engine to update.
    pub engine: Option<crate::detection_policy::EngineControl>,

    /// Server-side one-shot break-glass ledger (F2.3/R9-8): the control
    /// plane issues tokens here (behind the admin-token gate) and the data
    /// plane redeems them on `X-Cerberus-Bypass: break-glass:<nonce>`.
    pub break_glass: std::sync::Arc<cerberus_engine::break_glass::BreakGlassLedger>,

    /// Per-installation HMAC key for audit hashes (R9-16, F5.2). When set
    /// (product wiring), break-glass reason hashes AND the legacy bypass
    /// audit hash are keyed + domain-separated. `None` only in test
    /// contexts that never construct this builder — the daemon always keys.
    /// Not `Debug`-printed (`ApiContext` has no `Debug` derive) and never logged.
    pub audit_hash_key: Option<std::sync::Arc<Vec<u8>>>,

    /// Control-plane Host/Origin allowlist (R9-5 anti-DNS-rebinding, F6.1).
    /// Installed once per boot: the product wiring (daemon) builds it from
    /// the listen address + config BEFORE sharing the context; every other
    /// producer ([`crate::proxy::spawn_proxy`]) installs the fail-closed
    /// default from the bound address at spawn time. Enforced on every
    /// `/api/*` request BEFORE authentication.
    pub host_origin: std::sync::Arc<std::sync::OnceLock<std::sync::Arc<crate::host_origin::HostOriginPolicy>>>,
}

impl ApiContext {
    /// Create a new API context without a store.
    #[must_use]
    pub fn new(config: Arc<RwLock<ProxyConfig>>) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            store: None,
            pack_worker: None,
            config_path: None,
            engine: None,
            break_glass: std::sync::Arc::new(cerberus_engine::break_glass::BreakGlassLedger::new()),
            audit_hash_key: None,
            host_origin: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Create an API context with a store.
    #[must_use]
    pub fn with_store(config: Arc<RwLock<ProxyConfig>>, store: Arc<AuditStore>) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            store: Some(store),
            pack_worker: None,
            config_path: None,
            engine: None,
            break_glass: std::sync::Arc::new(cerberus_engine::break_glass::BreakGlassLedger::new()),
            audit_hash_key: None,
            host_origin: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Create an API context with an optional store.
    #[must_use]
    pub fn with_store_opt(config: Arc<RwLock<ProxyConfig>>, store: Option<Arc<AuditStore>>) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            store,
            pack_worker: None,
            config_path: None,
            engine: None,
            break_glass: std::sync::Arc::new(cerberus_engine::break_glass::BreakGlassLedger::new()),
            audit_hash_key: None,
            host_origin: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Connect the daemon rule-pack worker (F7 hot-reload).
    #[must_use]
    pub fn with_pack_worker(mut self, pack_worker: tokio::sync::mpsc::Sender<PackCommand>) -> Self {
        self.pack_worker = Some(pack_worker);
        self
    }

    /// Set the YAML path where the config is persisted (review v6 F6).
    #[must_use]
    pub fn with_config_path(mut self, config_path: std::path::PathBuf) -> Self {
        self.config_path = Some(config_path);
        self
    }

    /// Connect the live engine control handle (fix review v6.1): without this the
    /// policy is persisted but the dataplane is not updated hot.
    #[must_use]
    pub fn with_engine(mut self, engine: crate::detection_policy::EngineControl) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Create an API context without a store (fallback).
    #[must_use]
    pub fn without_store(config: Arc<RwLock<ProxyConfig>>) -> Self {
        Self::new(config)
    }

    /// Key ALL audit hashes with the per-installation HMAC key (R9-16/F5.2):
    /// break-glass reason hashes issued by the ledger AND the legacy bypass
    /// audit hash computed on the data path become keyed, domain-separated
    /// HMAC-SHA256. Product wiring (daemon) MUST call this before the
    /// context is shared; test contexts that skip it keep the unkeyed
    /// library fallback.
    #[must_use]
    pub fn with_audit_hash_key(mut self, key: Vec<u8>) -> Self {
        self.break_glass =
            std::sync::Arc::new(cerberus_engine::break_glass::BreakGlassLedger::new().with_hash_key(key.clone()));
        self.audit_hash_key = Some(std::sync::Arc::new(key));
        self
    }

    /// The installation audit-hash key, if wired (`None` only in tests).
    #[must_use]
    pub fn audit_hash_key(&self) -> Option<&[u8]> {
        self.audit_hash_key.as_ref().map(|v| v.as_slice())
    }

    /// Install the control-plane Host/Origin allowlist (R9-5/F6.1). Product
    /// wiring (daemon) calls this with the policy built from the real listen
    /// address + config so wildcard/blank entries FAIL the boot; every other
    /// producer gets the fail-closed default installed by
    /// [`Self::ensure_host_origin`].
    #[must_use]
    pub fn with_host_origin(self, policy: crate::host_origin::HostOriginPolicy) -> Self {
        let _ = self.host_origin.set(std::sync::Arc::new(policy));
        self
    }

    /// The installed policy, if any.
    #[must_use]
    pub fn host_origin_policy(&self) -> Option<&crate::host_origin::HostOriginPolicy> {
        self.host_origin.get().map(std::sync::Arc::as_ref)
    }

    /// Install the DEFAULT (fail-closed) policy for a bound address when the
    /// product wiring has not installed one. Called by `spawn_proxy` with the
    /// requested listen address: loopback binds get the loopback names,
    /// non-loopback binds get ONLY the explicitly configured entries
    /// (config-driven, A.1).
    pub fn ensure_host_origin(&self, listen: &std::net::SocketAddr, cfg: &ProxyConfig) {
        if self.host_origin.get().is_none() {
            if let Ok(policy) = crate::host_origin::HostOriginPolicy::build(listen, cfg) {
                let _ = self.host_origin.set(std::sync::Arc::new(policy));
            }
        }
    }
}

/// Determine if a path belongs to the API.
#[must_use]
pub fn is_api_path(path: &str) -> bool {
    path.starts_with("/api/")
}

/// The control-plane route table, as `<METHOD> <path>` pairs (F6.B).
///
/// Single source of truth for the CI parity test (`crates/cerberus` walks
/// the Appendix B CLI surface and asserts each daemon-backed command's
/// endpoint is present here) and for the parity matrix
/// (`evidence/f6/parity-matrix.md`). Keep in sync with
/// [`handle_api_request`].
#[must_use]
pub const fn known_api_routes() -> &'static [(&'static str, &'static str)] {
    &[
        ("GET", "/api/config"),
        ("PUT", "/api/config"),
        ("GET", "/api/events"),
        ("GET", "/api/stats"),
        ("POST", "/api/allowlist"),
        ("DELETE", "/api/allowlist"),
        ("GET", "/api/allowlist"),
        ("POST", "/api/break-glass"),
        ("GET", "/api/policy"),
        ("PUT", "/api/policy"),
        ("GET", "/api/upstreams"),
        ("POST", "/api/upstreams"),
        ("DELETE", "/api/upstreams/{name}"),
        ("GET", "/api/packs"),
        ("POST", "/api/packs/install"),
        ("POST", "/api/packs/rollback"),
        ("POST", "/api/packs/enable"),
        ("POST", "/api/packs/disable"),
        ("POST", "/api/packs/update"),
        ("POST", "/api/reload"),
        ("POST", "/api/scan"),
        ("GET", "/api/dashboard"),
        ("GET", "/ui"),
    ]
}

/// Does `(method, path)` exist in the control-plane route table? The
/// parameterized upstream delete is matched by prefix.
#[must_use]
pub fn is_known_api_route(method: &str, path: &str) -> bool {
    known_api_routes().iter().any(|&(m, p)| {
        m == method
            && (p == path
                || (p == "/api/upstreams/{name}" && path.starts_with("/api/upstreams/") && path != "/api/upstreams"))
    })
}

/// Constant-time comparison (accumulated xor + loop sum) to avoid timing
/// attacks when validating the admin token. No short-circuit by position.
#[must_use]
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Admin token expected by the control plane: a non-empty `Some` means
/// authentication is active.
///
/// **R9-5/F6 dev-mode semantics: `None`/empty = the control plane is CLOSED
/// (every data route 401s) — never open.**
#[must_use]
pub fn expected_admin_token(cfg: &ProxyConfig) -> Option<&str> {
    cfg.admin_token.as_deref().filter(|t| !t.is_empty())
}

/// Does the request carry a valid admin token? Accepts `Authorization: Bearer <t>`
/// or `X-Cerberus-Admin-Token: <t>` (review v4 #2). Constant-time comparison
/// for both headers.
#[must_use]
pub(crate) fn authorized(headers: &hyper::HeaderMap, expected: &str) -> bool {
    let bearer = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map_or("", str::trim);
    if constant_time_eq(bearer, expected) {
        return true;
    }
    admin_token_header(headers).is_some_and(|t| constant_time_eq(t, expected))
}

/// Does the request authenticate via `X-Cerberus-Admin-Token`? (fix review
/// v4 #2: the data-plane bypass is ONLY honored by this header, never by
/// Bearer).
#[must_use]
pub(crate) fn admin_token_header_is_present(headers: &hyper::HeaderMap, expected: &str) -> bool {
    admin_token_header(headers).is_some_and(|t| constant_time_eq(t, expected))
}

/// (Trimmed) value of the `X-Cerberus-Admin-Token` header, if present.
fn admin_token_header(headers: &hyper::HeaderMap) -> Option<&str> {
    headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

/// Does this route expose data and therefore require auth? The dashboard is
/// PUBLIC static HTML without data → never requires auth (review v5 F6).
#[must_use]
fn route_serves_data(path: &str) -> bool {
    // `/ui` (F6.B) is a pure 302 to the dashboard — public HTML, no data.
    path != "/api/dashboard" && path != "/ui"
}

/// Control-plane authentication gate — **FAIL-CLOSED** (R9-5 / F6.1).
///
/// Every data `/api/*` route requires a valid admin token; the dashboard
/// (public HTML without data) is exempt. **Dev mode is CLOSED, not open:**
/// when no token is configured there is no valid credential, so every data
/// route answers 401 — loopback included (the old "None = open control
/// plane" was the R9-5 vulnerability: a DNS-rebinding page could drive the
/// API from a browser). `None` only for an allowed request.
#[must_use]
fn auth_gate(cfg: &ProxyConfig, path: &str, headers: &hyper::HeaderMap) -> Option<Response<Full<Bytes>>> {
    if !route_serves_data(path) {
        return None;
    }
    let authenticated = expected_admin_token(cfg).is_some_and(|expected| authorized(headers, expected));
    if !authenticated {
        return Some(json_response(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#));
    }
    None
}

/// Control-plane Host/Origin gate — anti-DNS-rebinding (R9-5 / F6.1).
///
/// Enforced on EVERY `/api/*` request (dashboard included) BEFORE the auth
/// gate: a rebound/evil Host or Origin is rejected 403 without ever reaching
/// the token check (defense-in-depth works even for an operator who happens
/// to hold a valid token in the attacked browser).
///
/// - `Host` must be in the exact allowlist ([`crate::host_origin`]); a
///   loopback bind defaults to `localhost`/`127.0.0.1`/`[::1]`, a public
///   bind is fail-closed (only configured entries).
/// - A present `Origin` must be same-origin or explicitly allowlisted
///   (`Origin: null` — sandboxed iframe — is always rejected).
/// - A browser mutation (Origin present) must not carry a form-submittable
///   "simple" content type (`text/plain`, urlencoded, multipart).
///
/// `None` = allowed (no policy installed: direct-handler tests only) or the
/// request passed all three checks.
#[must_use]
fn anti_rebinding_gate(
    ctx: &ApiContext,
    method: &str,
    path: &str,
    headers: &hyper::HeaderMap,
) -> Option<Response<Full<Bytes>>> {
    let policy = ctx.host_origin_policy()?;
    let forbidden = |msg: &str| {
        Some(json_response(
            StatusCode::FORBIDDEN,
            &format!(r#"{{"error":"forbidden","detail":"{msg}"}}"#),
        ))
    };

    let host_header = headers
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // A missing Host is itself malformed for a browser client (HTTP/1.1
    // requires it) and cannot be allowlisted → reject.
    if !policy.host_allowed(host_header) {
        return forbidden("host not allowed (anti-rebinding allowlist)");
    }

    let origin = headers
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !policy.origin_allowed(origin, host_header) {
        return forbidden("origin not allowed (same-origin/allowlist check)");
    }

    // Browser mutations must not use the form-submittable simple types.
    let is_mutation = matches!(method, "POST" | "PUT" | "PATCH" | "DELETE");
    if !origin.is_empty() && is_mutation {
        let ct = headers.get(hyper::header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
        if !crate::host_origin::HostOriginPolicy::mutation_content_type_allowed(ct) {
            return forbidden("form-submittable content type not allowed for mutations");
        }
    }

    let _ = path; // path is not part of the allowlist decision; kept for signature clarity
    None
}

/// Extract the `provider` query param (review v5 F6). `None` = no filter.
#[must_use]
fn query_provider(query: &str) -> Option<String> {
    query_param(query, "provider")
}

/// Extract a single query param (`name=value`), URL-decoded as far as the
/// wire format requires for our identifiers (plain tokens; `+` is NOT
/// decoded to space to keep the parser trivial and injection-free).
#[must_use]
fn query_param(query: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let mut found: Option<String> = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix(&prefix) {
            if !value.is_empty() {
                found = Some(value.to_string());
            }
        }
    }
    found
}

/// Filter events by provider when the query param is present.
#[must_use]
fn filter_by_provider(events: &[AuditEvent], provider: Option<String>) -> Vec<AuditEvent> {
    provider.map_or_else(
        || events.to_vec(),
        |p| events.iter().filter(|e| e.provider == p).cloned().collect(),
    )
}

/// Filter events by originating tool (Appendix B B.5 `--tool`).
#[must_use]
fn filter_by_tool(events: &[AuditEvent], tool: Option<String>) -> Vec<AuditEvent> {
    tool.map_or_else(
        || events.to_vec(),
        |t| events.iter().filter(|e| e.tool == t).cloned().collect(),
    )
}

/// Filter events recorded at or after `since` (unix epoch seconds; Appendix
/// B B.5 `--since`). The CLI accepts RFC 3339 or `30m/2h/1d` shorthand and
/// normalizes to epoch seconds on the wire.
#[must_use]
fn filter_since(events: &[AuditEvent], since_unix: Option<i64>) -> Vec<AuditEvent> {
    since_unix.map_or_else(
        || events.to_vec(),
        |s| events.iter().filter(|e| e.ts_unix >= s).cloned().collect(),
    )
}

/// Handle an API request.
///
/// # Errors
///
/// Returns an error if the handler fails.
pub async fn handle_api_request(
    req: Request<hyper::body::Incoming>,
    ctx: &ApiContext,
) -> Result<Response<Full<Bytes>>, String> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let method = parts.method.clone();

    // -- Control plane anti-rebinding gate (P0, R9-5/F6.1) -------------------
    // FIRST gate: a rebound/evil Host or Origin is 403'd before anything
    // else (including before the token check), so a DNS-rebinding page can
    // never reach the auth layer at all.
    {
        if let Some(denied) = anti_rebinding_gate(ctx, method.as_str(), &path, &parts.headers) {
            return Ok(denied);
        }
    }

    // -- Control plane auth (P0, R9-5/F6.1) ----------------------------------
    // FAIL-CLOSED: if an admin token is configured, all DATA routes `/api/*`
    // require authentication; the dashboard (public HTML without data) is
    // exempt. With NO configured token the control plane is CLOSED (401) —
    // loopback included; the old dev-mode "open API" was the R9-5 finding.
    {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        if let Some(denied) = auth_gate(&cfg, &path, &parts.headers) {
            return Ok(denied);
        }
    }

    // Query param `provider` for per-provider filters (review v5 F6).
    // F6.B (Appendix B B.5): `tool` and `since` (unix epoch seconds) extend
    // the same filter surface for `cerberus events` / `cerberus stats`.
    let query = parts.uri.query().map_or_else(String::new, |q| q.to_string());
    let provider = query_provider(&query);
    let tool = query_param(&query, "tool");
    let since_unix = query_param(&query, "since").and_then(|s| s.parse::<i64>().ok());

    // Upstream CRUD (review v6 F6): DELETE carries the name in the path. It
    // is resolved BEFORE the static match because `/api/upstreams/{name}` is
    // not a fixed route. Authenticated by the control-plane gate (above).
    if let Some(name) = upstream_name_from_path(&path) {
        if method == "DELETE" {
            return handle_delete_upstream(ctx, name).await;
        }
        return Ok(not_found());
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/api/config") => handle_get_config(ctx).await,
        ("PUT", "/api/config") => handle_put_config(ctx, body).await,
        ("GET", "/api/events") => handle_get_events(ctx, provider, tool, since_unix).await,
        ("GET", "/api/stats") => handle_get_stats(ctx, provider, tool, since_unix).await,
        ("POST", "/api/allowlist") => handle_post_allowlist(ctx, body).await,
        ("POST", "/api/break-glass") => handle_post_break_glass(ctx, body).await,
        ("GET", "/api/allowlist") => handle_get_allowlist(ctx).await,
        ("DELETE", "/api/allowlist") => handle_delete_allowlist(ctx, body).await,
        ("GET", "/api/policy") => handle_get_policy(ctx).await,
        ("PUT", "/api/policy") => handle_put_policy(ctx, body).await,
        ("GET", "/api/upstreams") => handle_get_upstreams(ctx).await,
        ("POST", "/api/upstreams") => handle_post_upstreams(ctx, body).await,
        ("GET", "/api/packs") => handle_pack_mode(ctx, PackKind::List).await,
        ("POST", "/api/packs/install") => handle_pack_install(ctx, body).await,
        ("POST", "/api/packs/rollback") => handle_pack_mode(ctx, PackKind::Rollback).await,
        // F6.B (Appendix B B.3): per-pack enable/disable and the update
        // (verify + hot-reload) contract; the pack worker owns the manifest.
        ("POST", "/api/packs/enable") => handle_pack_enable_disable(ctx, body, true).await,
        ("POST", "/api/packs/disable") => handle_pack_enable_disable(ctx, body, false).await,
        ("POST", "/api/packs/update") => handle_pack_mode(ctx, PackKind::Update).await,
        // F6.B (Appendix B B.7): hot-reload of the on-disk config.
        ("POST", "/api/reload") => handle_reload(ctx).await,
        // F6.B (Appendix B B.4): dry-run scan for the dashboard "Test
        // detection" box. Scans with the LIVE engine; nothing is persisted.
        ("POST", "/api/scan") => handle_api_scan(ctx, body).await,
        (_, "/api/dashboard") => handle_dashboard(ctx),
        // Public redirect so the documented `http://localhost:8787/ui`
        // (Appendix B B.6 `cerberus dashboard`) resolves to the dashboard.
        (_, "/ui") => Ok(redirect_dashboard()),
        _ => Ok(not_found()),
    }
}

/// Pack command kind to the daemon worker (real hot-reload, F7 v5).
enum PackKind {
    List,
    Rollback,
    /// Verify + hot-reload installed packs (`packs update` F6 contract).
    Update,
}

/// Send a (bodyless) pack command to the worker and wait for its reply.
async fn handle_pack_mode(ctx: &ApiContext, kind: PackKind) -> Result<Response<Full<Bytes>>, String> {
    let Some(worker) = ctx.pack_worker.as_ref() else {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker not connected"}"#,
        ));
    };
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    // `Update` is a config mutation (verify + hot-reload) and gets an audit
    // event; List is read-only.
    let is_update = matches!(kind, PackKind::Update);
    let cmd = match kind {
        PackKind::List => PackCommand::List { reply: reply_tx },
        PackKind::Rollback => PackCommand::Rollback { reply: reply_tx },
        PackKind::Update => PackCommand::Update { reply: reply_tx },
    };
    if worker.send(cmd).await.is_err() {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker not running"}"#,
        ));
    }
    match tokio::time::timeout(std::time::Duration::from_secs(30), reply_rx).await {
        Ok(Ok(Ok(text))) => {
            if is_update {
                // Audit the applied mutation (F6.B attempt 2, security P2-1).
                let mode = live_operation_mode(ctx);
                audit_config_mutation(ctx, &mode, "pack-update", "").await;
            }
            Ok(json_response(
                StatusCode::OK,
                &format!(r#"{{"status":"ok","message":{text:?}}}"#),
            ))
        }
        Ok(Ok(Err(e))) => Ok(json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":{e:?}}}"#))),
        Ok(Err(_)) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker disconnected"}"#,
        )),
        Err(_) => Ok(json_response(
            StatusCode::REQUEST_TIMEOUT,
            r#"{"error":"pack worker timed out"}"#,
        )),
    }
}

/// Core of `POST /api/packs/enable|disable` (F6.B, Appendix B B.3): sends
/// `PackCommand::Enable/Disable` to the worker, which owns the manifest.
async fn apply_pack_enable_disable(ctx: &ApiContext, body_bytes: &[u8], enable: bool) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct PackNameRequest {
        name: String,
    }
    let parsed: PackNameRequest = match serde_json::from_slice(body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"invalid request: expected {{\"name\": \"<pack>\"}}","detail":"{e}"}}"#),
            );
        }
    };
    let Some(worker) = ctx.pack_worker.as_ref() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker not connected"}"#,
        );
    };
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let pack_name = parsed.name.clone();
    let cmd = if enable {
        PackCommand::Enable {
            name: parsed.name,
            reply: reply_tx,
        }
    } else {
        PackCommand::Disable {
            name: parsed.name,
            reply: reply_tx,
        }
    };
    if worker.try_send(cmd).is_err() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker not running"}"#,
        );
    }
    match reply_rx.await {
        Ok(Ok(message)) => {
            // Audit the applied mutation (F6.B attempt 2, security P2-1):
            // the pack name is manifest metadata, never a secret.
            let mode = live_operation_mode(ctx);
            let action = if enable { "pack-enable" } else { "pack-disable" };
            audit_config_mutation(ctx, &mode, action, &pack_name).await;
            json_response(StatusCode::OK, &format!(r#"{{"status":"ok","message":{message:?}}}"#))
        }
        Ok(Err(e)) => json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":{e:?}}}"#)),
        Err(_) => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker disconnected"}"#,
        ),
    }
}

async fn handle_pack_enable_disable(
    ctx: &ApiContext,
    body: hyper::body::Incoming,
    enable: bool,
) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    Ok(apply_pack_enable_disable(ctx, &body_bytes, enable).await)
}

/// Core of `POST /api/reload` (F6.B, Appendix B B.7): re-reads the config
/// file from disk, validates it, and hot-swaps the live config + policy
/// engine WITHOUT restarting the proxy. The listen address is intentionally
/// NOT reloaded (the socket is already bound); a changed `admin_token`
/// takes effect immediately (the auth gate reads the live config).
///
/// Requires a `config_path` wired at boot (the daemon always wires it;
/// API-only test contexts may not have one → 503).
fn apply_reload(ctx: &ApiContext) -> Response<Full<Bytes>> {
    let Some(path) = ctx.config_path.as_ref() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"no config path wired at boot: reload is unavailable"}"#,
        );
    };
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"cannot read {}: {e}"}}"#, path.display()),
            );
        }
    };
    let loaded: ProxyConfig = match serde_yaml::from_str(&raw) {
        Ok(c) => c,
        Err(e) => return invalid_config_response(&format!("config does not parse: {e}")),
    };
    let mut candidate = loaded;
    // Preserve the RUNNING port: a listen change in the file cannot move a
    // bound socket; the operator restarts for that. Everything else reloads.
    {
        let live = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        candidate.listen.clone_from(&live.listen);
    }
    if let Err(e) = candidate.policy.validate() {
        return invalid_config_response(&format!("policy in {} is invalid: {e}", path.display()));
    }
    // Anti-lockout (fail-closed preserved): the live daemon was booted with
    // a token (product wiring); a reload that would REMOVE it silently
    // closes the control plane mid-session and locks the operator out
    // (every /api/* answers 401, including reload itself). Reject the
    // reload instead — the operator edits the file or restarts. Changing
    // to a DIFFERENT token is applied immediately (the gate reads the live
    // config).
    {
        let live = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        // Use the auth-layer's token semantics (expected_admin_token filters
        // Some("") to None): an EMPTY token in the candidate would close the
        // plane exactly like a removed one (re-verification finding, F6.B
        // attempt 2). A live empty token means "already closed" — no-op
        // reloads stay allowed, opening stays allowed.
        if expected_admin_token(&live).is_some() && expected_admin_token(&candidate).is_none() {
            return invalid_config_response(
                "reload would remove or clear the admin token and CLOSE the control plane \
                 (fail-closed); keep a non-empty admin_token in the file or restart the daemon",
            );
        }
    }
    let (published, mode) = {
        let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
        if live.upstreams.is_empty() && candidate.upstreams.is_empty() {
            return invalid_config_response("reload would leave zero upstreams; fix the file first");
        }
        let compiled = match ctx.engine.as_ref() {
            Some(engine) => match engine.compile(&candidate.policy) {
                Ok(c) => Some(engine.publish(c)),
                Err(e) => return invalid_config_response(&format!("policy does not compile: {e}")),
            },
            None => None,
        };
        // Persist is NOT performed: the file on disk IS the source we just
        // read (Mode A IaC semantics; B.7 "config before deploying").
        *live = candidate;
        let mode = format!("{:?}", live.mode).to_lowercase();
        (compiled, mode)
    };
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "status": "ok",
            "message": "config reloaded from disk (listen unchanged, hot-reload applied)",
            "mode": mode,
            "engine_rules": published,
        })
        .to_string(),
    )
}

async fn handle_reload(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let resp = apply_reload(ctx);
    // Audit ONLY the applied mutations (a 400 left the live config intact).
    if resp.status() == StatusCode::OK {
        let mode = live_operation_mode(ctx);
        audit_config_mutation(ctx, &mode, "config-reload", "").await;
    }
    Ok(resp)
}

/// Core of `POST /api/scan` (F6.B, Appendix B B.4 — dashboard "Test
/// detection"): dry-runs the LIVE engine over the body text and returns the
/// findings (flags, counts, action, keyed hashes). NOTHING is persisted and
/// raw input is NEVER echoed — the response mirrors the event schema's
/// no-leak contract.
fn apply_api_scan(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct ScanRequest {
        text: String,
    }
    let parsed: ScanRequest = match serde_json::from_slice(body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"invalid request: expected {{\"text\": \"...\"}}","detail":"{e}"}}"#),
            );
        }
    };
    let Some(engine_control) = ctx.engine.as_ref() else {
        return json_response(StatusCode::SERVICE_UNAVAILABLE, r#"{"error":"engine not wired"}"#);
    };
    let mode = {
        let live = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        live.mode
    };
    let engine = engine_control.live_snapshot();
    let output = engine.scan(&parsed.text);
    let findings = output.findings;
    // Enforce reports the effective action of the highest finding; shadow
    // only reports what WOULD happen (warn, nothing applied).
    let action_taken = if findings.is_empty() {
        cerberus_engine::rule::Action::Allow
    } else if mode == crate::config::OperationMode::Enforce {
        output.action_overall
    } else {
        cerberus_engine::rule::Action::Warn
    };
    let mut counts = std::collections::BTreeMap::new();
    for f in &findings {
        *counts.entry(f.flag.clone()).or_insert(0usize) += 1;
    }
    let hashed: Vec<String> = findings.iter().map(|f| f.hashed_value.clone()).collect();
    let body = serde_json::json!({
        "status": "ok",
        "action": action_taken.to_string(),
        "finding_count": findings.len(),
        "flags": counts,
        "hashed_values": hashed,
    });
    json_response(StatusCode::OK, &body.to_string())
}

async fn handle_api_scan(ctx: &ApiContext, body: hyper::body::Incoming) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    Ok(apply_api_scan(ctx, &body_bytes))
}

/// 302 to the dashboard so the documented `http://localhost:8787/ui`
/// (Appendix B B.6) resolves. Public: HTML only, no data.
fn redirect_dashboard() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", "/api/dashboard")
        .header("content-security-policy", "default-src 'none'; frame-ancestors 'none'")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| not_found())
}

async fn handle_pack_install(ctx: &ApiContext, body: hyper::body::Incoming) -> Result<Response<Full<Bytes>>, String> {
    let cmd_body = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    let request = match PackInstallRequest::parse_body(&cmd_body) {
        Ok(request) => request,
        Err(error) => {
            let message =
                serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "\"invalid pack request\"".to_string());
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":{message}}}"#),
            ));
        }
    };
    let Some(worker) = ctx.pack_worker.as_ref() else {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker not connected"}"#,
        ));
    };
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if worker
        .send(PackCommand::Install {
            request,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker not running"}"#,
        ));
    }
    match tokio::time::timeout(std::time::Duration::from_secs(30), reply_rx).await {
        Ok(Ok(Ok(text))) => Ok(json_response(
            StatusCode::OK,
            &format!(r#"{{"status":"ok","message":{text:?}}}"#),
        )),
        Ok(Ok(Err(e))) => Ok(json_response(StatusCode::BAD_REQUEST, &format!(r#"{{"error":{e:?}}}"#))),
        Ok(Err(_)) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker disconnected"}"#,
        )),
        Err(_) => Ok(json_response(
            StatusCode::REQUEST_TIMEOUT,
            r#"{"error":"pack worker timed out"}"#,
        )),
    }
}

/// Read-only view of the config for `GET /api/config` (review v6.1).
///
/// DTO **separate** from [`ProxyConfig`]: by construction it has NO
/// `admin_token` field, so no new field in `ProxyConfig` can leak the
/// secret via this route (before it was manually redacted on the serialized
/// JSON, and that deletion had to be remembered). `admin_token_configured`
/// is a **derived, read-only** boolean: the `PUT` ignores it (see
/// [`ConfigPatch`]).
#[derive(serde::Serialize)]
struct ConfigView<'a> {
    listen: &'a str,
    mode: crate::config::OperationMode,
    fail_policy: crate::config::FailPolicy,
    upstreams: &'a std::collections::HashMap<String, UpstreamConfig>,
    log_level: &'a str,
    health_path: &'a str,
    max_body_bytes: Option<usize>,
    /// Derived: does the control plane require a token? NEVER the token value.
    admin_token_configured: bool,
}

impl<'a> ConfigView<'a> {
    fn from_config(cfg: &'a ProxyConfig) -> Self {
        Self {
            listen: &cfg.listen,
            mode: cfg.mode,
            fail_policy: cfg.fail_policy,
            upstreams: &cfg.upstreams,
            log_level: &cfg.log_level,
            health_path: &cfg.health_path,
            max_body_bytes: cfg.max_body_bytes,
            admin_token_configured: expected_admin_token(cfg).is_some(),
        }
    }
}

/// Patch field with the THREE states an optional key can have in the JSON
/// body. The type documents the semantics an `Option<Option<T>>` leaves
/// implicit, and is what distinguishes "don't touch my token" from "delete it".
#[derive(Default)]
enum PatchField<T> {
    /// The key was not in the body → preserve the live value.
    #[default]
    Absent,
    /// The key was `null` → delete the value.
    Clear,
    /// The key had a value → replace.
    Set(T),
}

impl<T> PatchField<T> {
    /// Resolve the field against the live value (`live`).
    fn resolve(self, live: Option<T>) -> Option<T> {
        match self {
            Self::Absent => live,
            Self::Clear => None,
            Self::Set(v) => Some(v),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PatchField<T> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(de).map(|v| v.map_or(Self::Clear, Self::Set))
    }
}

/// Body of `PUT /api/config` (review v6.1). DTO **separate** from
/// [`ProxyConfig`] with patch semantics: **every absent field is preserved**.
///
/// - `admin_token` absent ⇒ the live token is preserved (it never has to
///   be resent, and `GET` does not reveal it). Explicit `null` ⇒ it is
///   deleted **at the DTO level only**: `handle_put_config` REJECTS the
///   patch with 400 when the live config has a token (anti-lockout, F6.B
///   attempt 2 finding F1 — removal must never close/persist a closed
///   control plane). Changing to a DIFFERENT token stays allowed.
/// - `admin_token_configured` is accepted (so a GET→modify→PUT cycle from
///   the client does not fail) but it is READ-ONLY: it is ignored
///   completely, it cannot enable or disable authentication.
/// - Any other key is rejected (`deny_unknown_fields`): a typo like
///   `admin_tokens` fails loudly instead of being silently ignored.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConfigPatch {
    listen: Option<String>,
    mode: Option<crate::config::OperationMode>,
    fail_policy: Option<crate::config::FailPolicy>,
    upstreams: Option<std::collections::HashMap<String, UpstreamConfig>>,
    log_level: Option<String>,
    health_path: Option<String>,
    #[serde(default)]
    max_body_bytes: PatchField<usize>,
    #[serde(default)]
    admin_token: PatchField<String>,
    /// READ-ONLY field. Declared to accept it in the body and NEVER read:
    /// the authentication state is derived from `admin_token`.
    #[allow(dead_code)]
    #[serde(default)]
    admin_token_configured: Option<bool>,
}

impl ConfigPatch {
    /// Apply the patch over `base` and return the CANDIDATE config (not yet
    /// validated or published). Absent fields ⇒ value from `base`.
    fn apply(self, base: &ProxyConfig) -> ProxyConfig {
        ProxyConfig {
            listen: self.listen.unwrap_or_else(|| base.listen.clone()),
            mode: self.mode.unwrap_or(base.mode),
            fail_policy: self.fail_policy.unwrap_or(base.fail_policy),
            upstreams: self.upstreams.unwrap_or_else(|| base.upstreams.clone()),
            log_level: self.log_level.unwrap_or_else(|| base.log_level.clone()),
            health_path: self.health_path.unwrap_or_else(|| base.health_path.clone()),
            max_body_bytes: self.max_body_bytes.resolve(base.max_body_bytes),
            admin_token: self.admin_token.resolve(base.admin_token.clone()),
            // Host/Origin allowlists (R9-5/F6.1) are not hot-toggleable via
            // this route: they are boot-time security config (the policy is
            // built once per boot from the listen address), so the YAML/
            // startup values are always preserved here.
            allowed_hosts: base.allowed_hosts.clone(),
            allowed_origins: base.allowed_origins.clone(),
            // The detection policy is NOT touched via this route: it has its own
            // door (`PUT /api/policy`), which validates the rules and
            // recompiles the engine. Here it is always preserved.
            policy: base.policy.clone(),
            // Reversible redaction (F2.2, opt-in §9 #4) is not hot-toggleable
            // through this route; the YAML/startup value is preserved.
            reversible_redaction: base.reversible_redaction,
        }
    }
}

/// Does the `listen` string point to a loopback interface?
///
/// Mirrors `proxy::check_listen_security` (which operates on the bind
/// `SocketAddr`) but on the text that arrives via the API. **For security the
/// default is "non loopback"**: if the string does not resolve to a literal
/// loopback IP (or `localhost`), it is treated as public and a strong token
/// is required.
#[must_use]
fn listen_is_loopback(listen: &str) -> bool {
    if let Ok(addr) = listen.parse::<std::net::SocketAddr>() {
        return addr.ip().is_loopback();
    }
    let host = listen.rsplit_once(':').map_or(listen, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Revalidate that the candidate config does not leave the control plane
/// exposed (review v6.1): if `listen` is not loopback, it requires an admin
/// token of at least [`ADMIN_TOKEN_MIN_BYTES`].
///
/// It is the SAME rule `proxy::check_listen_security` applies when binding,
/// but checked **before** mutating memory or writing the YAML: so a config
/// the daemon would reject on startup also cannot be persisted (we avoided
/// the open bind, not the "it gets saved and does not start").
fn validate_control_plane_exposure(cfg: &ProxyConfig) -> Result<(), String> {
    if listen_is_loopback(&cfg.listen) {
        return Ok(());
    }
    let listen = &cfg.listen;
    match expected_admin_token(cfg) {
        Some(t) if t.len() >= ADMIN_TOKEN_MIN_BYTES => Ok(()),
        Some(t) => Err(format!(
            "refusing config with non-loopback listen {listen}: admin token too short ({len} < {min} bytes)",
            len = t.len(),
            min = ADMIN_TOKEN_MIN_BYTES
        )),
        None => Err(format!(
            "refusing config with non-loopback listen {listen}: no admin token configured (set a token of at least {ADMIN_TOKEN_MIN_BYTES} characters)"
        )),
    }
}

/// 400 response with the config validation error.
fn invalid_config_response(err: &str) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::BAD_REQUEST,
        &format!(r#"{{"status":"error","error":{err:?}}}"#),
    )
}

/// 500 response when persistence fails. The live config was NOT touched.
fn persist_failed_response(err: &str) -> Response<Full<Bytes>> {
    json_response_close(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!(r#"{{"status":"error","error":{err:?},"note":"nothing was applied: the live config is unchanged"}}"#),
    )
}

async fn handle_get_config(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    // Review v6.1: the DTO is serialized, not `ProxyConfig`. The `admin_token`
    // does not exist in `ConfigView`, so there is nothing to redact or forget.
    let json = serde_json::to_string(&ConfigView::from_config(&config)).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

/// Atomically replace `path` with `content`, enforcing mode **0600** on the
/// RESULT (F6.A attempt 2, P1/P2 fix — F5 F-1 discipline).
///
/// The tmp file is removed if stale, then created EXCLUSIVELY with mode 0600
/// AT CREATION on unix (no umask window — the content carries the admin
/// token), and only then renamed over `path`. Because the rename replaces
/// any pre-existing file, the final mode is 0600 regardless of what it was
/// before (a re-init or later write REPAIRS a regressed 0644 config instead
/// of preserving it).
///
/// Every `Result` is handled: on any failure the tmp is removed and the
/// error returned — the previous file is left untouched (rename is atomic).
///
/// # Errors
///
/// Propagates the tmp creation/write or rename error.
pub fn write_config_file_0600(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    // Temp in the SAME directory so the rename is atomic.
    let tmp = std::path::PathBuf::from(format!("{}.tmp", path.to_string_lossy()));
    // A stale tmp from a crashed writer must not be reused at its old mode:
    // remove it BEFORE the exclusive create (the F-1 pattern).
    let _ = std::fs::remove_file(&tmp);
    let write = write_tmp_0600(&tmp, content);
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Create the tmp file EXCLUSIVELY (`create_new`) with `0600` applied at
/// creation (unix) and write `content`. Exclusive create + creation-time
/// mode ⇒ there is NO window where the credential-carrying tmp exists at a
/// umask-derived mode, and a concurrent writer cannot interleave.
fn write_tmp_0600(tmp: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)?;
        f.write_all(content.as_bytes())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(tmp)?;
        f.write_all(content.as_bytes())
    }
}

/// Persist the shared config to YAML at `ctx.config_path` (review v6 F6).
///
/// Atomic write (temp + rename) so the file is not corrupted on a cutoff.
/// F6.A attempt 2 (P1): the write goes through [`write_config_file_0600`]
/// so EVERY control-plane write leaves `config.yaml` at 0600 — the old plain
/// tmp write regressed a 0600 config to umask 0644 (the file carries the
/// admin token). `None` (tests/dev) → no-op without error. If the write
/// fails, `Err` is returned; the caller decides whether to roll back the
/// in-memory change.
fn persist_config(ctx: &ApiContext, config: &ProxyConfig) -> Result<(), String> {
    let Some(path) = ctx.config_path.as_ref() else {
        return Ok(());
    };
    let yaml = serde_yaml::to_string(config).map_err(|e| format!("config yaml serialize error: {e}"))?;
    write_config_file_0600(path, &yaml).map_err(|e| format!("config write failed: {e}"))
}

/// Control-plane body limited to 1 MiB (review v4 #4). Distinguishes the
/// limit cutoff (413) from generic read errors.
enum ApiBodyError {
    TooLarge,
    Read(String),
}

async fn collect_api_body(body: hyper::body::Incoming) -> Result<Bytes, ApiBodyError> {
    use http_body_util::BodyExt;
    match http_body_util::Limited::new(body, CONTROL_PLANE_MAX_BYTES)
        .collect()
        .await
    {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) if e.is::<http_body_util::LengthLimitError>() => Err(ApiBodyError::TooLarge),
        Err(e) => Err(ApiBodyError::Read(format!("api body read error: {e}"))),
    }
}

async fn handle_put_config(ctx: &ApiContext, body: hyper::body::Incoming) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response_close(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response_close(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    let patch: ConfigPatch = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => return Ok(invalid_config_response(&format!("invalid config: {e}"))),
    };

    // The WRITE lock is taken before computing the candidate and is not
    // released until publishing (or aborting): nobody cuts in midway, and the
    // order is validate → persist → publish. Transactional from the in-memory
    // perspective: if validation or disk fail, the live config did not change.
    // The guard is scoped LEXICALLY (block) so the future stays `Send` — the
    // audit emission below awaits AFTER the lock is released.
    let (requires_restart, mode_now) = {
        let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
        let candidate = patch.apply(&live);

        // Anti-lockout (F6.B attempt 2, finding F1 — the SAME invariant
        // `apply_reload` already enforces): a running daemon booted with an
        // admin token; a PUT that would REMOVE it (explicit
        // `"admin_token":null`) closes every `/api/*` route mid-session
        // (all 401, including for the operator who just sent the PUT), and
        // because the candidate is persisted the closure would survive
        // `cerberus restart` — recovery would require a hand edit of the
        // YAML. Reject BEFORE persisting or publishing: the live config and
        // the on-disk file keep the old token. Changing the token to a
        // DIFFERENT value stays allowed and applies immediately (documented
        // rotation semantics, live-verified).
        // Same auth-layer semantics as the reload guard: an EMPTY token in
        // the candidate closes the plane exactly like a removed one
        // (re-verification finding, F6.B attempt 2). A live empty token
        // means "already closed" — no-op PUTs stay allowed, opening stays
        // allowed.
        if expected_admin_token(&live).is_some() && expected_admin_token(&candidate).is_none() {
            return Ok(invalid_config_response(
                "config update would remove or clear the admin token and CLOSE the control plane \
                 (fail-closed); omit admin_token to keep it or PUT a new non-empty value to \
                 rotate it",
            ));
        }

        // Exposure revalidation BEFORE persisting/mutating (review v6.1).
        if let Err(e) = validate_control_plane_exposure(&candidate) {
            return Ok(invalid_config_response(&e));
        }
        // Persistence first: if the YAML cannot be written, we publish
        // nothing (before, it was applied in memory and diverged from disk).
        if let Err(e) = persist_config(ctx, &candidate) {
            return Ok(persist_failed_response(&e));
        }

        // Review v6 F6: if `listen` changed, the LIVE socket cannot rebind;
        // we return `requires_restart:true` so the UI warns that the new
        // listen applies on the NEXT startup (the `listen` is already
        // persisted).
        let requires_restart = live.listen != candidate.listen;
        let mode_now = format!("{:?}", candidate.mode).to_lowercase();
        // Publish: write the SAME config the hot path reads (hot-reload, P0-5).
        *live = candidate;
        (requires_restart, mode_now)
    };

    // Audit the applied mutation (F6.B attempt 2, security P2-1). The body
    // is NEVER echoed (it may carry the rotated token) — only the honest
    // action name.
    audit_config_mutation(ctx, &mode_now, "config-update", "").await;

    let message = if requires_restart {
        r#"{"status":"ok","requires_restart":true,"message":"config updated (listen change applies on next restart)"}"#
    } else {
        r#"{"status":"ok","requires_restart":false,"message":"config updated"}"#
    };
    Ok(json_response(StatusCode::OK, message))
}

/// Event snapshots: memory (live) + `SQLite` store (persistence).
/// The view after restart recovers the history (review 2, P1 #9).
async fn events_snapshot(ctx: &ApiContext, limit: usize) -> Vec<AuditEvent> {
    let mut by_id: std::collections::HashMap<String, AuditEvent> = std::collections::HashMap::new();
    {
        let events = ctx.events.lock().await;
        for e in events.iter() {
            by_id.insert(e.id.clone(), e.clone());
        }
    }
    if let Some(ref store) = ctx.store {
        for e in store.recent_events(limit).await {
            by_id.entry(e.id.clone()).or_insert(e);
        }
    }
    let mut all: Vec<AuditEvent> = by_id.into_values().collect();
    all.sort_by_key(|e| std::cmp::Reverse(e.ts_unix));
    all.truncate(limit);
    all
}

async fn handle_get_events(
    ctx: &ApiContext,
    provider: Option<String>,
    tool: Option<String>,
    since_unix: Option<i64>,
) -> Result<Response<Full<Bytes>>, String> {
    let events = events_snapshot(ctx, 10_000).await;
    let events = filter_by_provider(&events, provider);
    let events = filter_by_tool(&events, tool);
    let events = filter_since(&events, since_unix);
    let json = serde_json::to_string(&events).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

async fn handle_get_stats(
    ctx: &ApiContext,
    provider: Option<String>,
    tool: Option<String>,
    since_unix: Option<i64>,
) -> Result<Response<Full<Bytes>>, String> {
    let events = events_snapshot(ctx, 10_000).await;
    let events = filter_by_provider(&events, provider);
    let events = filter_by_tool(&events, tool);
    let events = filter_since(&events, since_unix);
    let s = stats::summary(&events);
    let json = serde_json::to_string(&s).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

/// Extract the upstream name from a `/api/upstreams/{name}` path (review
/// v6 F6). `None` if there is no name (e.g. the exact path `/api/upstreams`).
#[must_use]
fn upstream_name_from_path(path: &str) -> Option<&str> {
    path.strip_prefix("/api/upstreams/").filter(|n| !n.is_empty())
}

/// Body for adding an upstream via `POST /api/upstreams` (review v6 F6).
#[derive(Deserialize)]
struct UpstreamPayload {
    name: String,
    url: String,
    auth_header: Option<String>,
    /// Per-upstream operation mode (R9-11): `shadow` | `enforce`. `None`
    /// (absent) → inherit the global mode, exactly like the YAML.
    mode: Option<crate::config::OperationMode>,
}

async fn handle_get_upstreams(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    let items: Vec<String> = config
        .upstreams
        .iter()
        .map(|(name, up)| {
            format!(
                r#"{{"name":{name:?},"url":{url:?},"auth_header":{auth:?},"mode":{mode}}}"#,
                url = up.url,
                auth = up.auth_header,
                mode = match up.mode {
                    None => "null".to_string(),
                    Some(crate::config::OperationMode::Shadow) => r#""shadow""#.to_string(),
                    Some(crate::config::OperationMode::Enforce) => r#""enforce""#.to_string(),
                },
            )
        })
        .collect();
    let joined = items.join(",");
    Ok(json_response(StatusCode::OK, format!("[{joined}]")))
}

/// Add/update an upstream. Hot mutation + YAML persistence (same policy as
/// `PUT /api/config`, review v6 F6).
async fn handle_post_upstreams(ctx: &ApiContext, body: hyper::body::Incoming) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response_close(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response_close(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    // F6.A attempt 2 (P3-1): a malformed JSON body must answer 400 like
    // every other parse arm — the old `?` surfaced the serde error as a
    // handler `Err`, so hyper logged "error from user's Service" and closed
    // the connection (curl HTTP=000) instead of answering.
    let payload: UpstreamPayload = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => return Ok(invalid_config_response(&format!("invalid upstream payload: {e}"))),
    };
    if payload.name.is_empty() {
        return Ok(json_response(StatusCode::BAD_REQUEST, r#"{"error":"missing 'name'"}"#));
    }
    if payload.url.is_empty() {
        return Ok(json_response(StatusCode::BAD_REQUEST, r#"{"error":"missing 'url'"}"#));
    }

    // Same transaction as PUT /api/config (review v6.1): candidate →
    // validate → persist → publish, with the write lock held (scoped
    // LEXICALLY — the audit emission awaits after the lock is released).
    let (mode_now, saved_name) = {
        let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
        let mut candidate = live.clone();
        candidate.upstreams.insert(
            payload.name.clone(),
            UpstreamConfig {
                url: payload.url.clone(),
                path_prefix: None,
                auth_header: payload.auth_header.unwrap_or_else(|| "authorization".to_string()),
                mode: payload.mode,
                expected_auth: None,
            },
        );
        if let Err(e) = validate_control_plane_exposure(&candidate) {
            return Ok(invalid_config_response(&e));
        }
        if let Err(e) = persist_config(ctx, &candidate) {
            return Ok(persist_failed_response(&e));
        }
        let mode_now = format!("{:?}", candidate.mode).to_lowercase();
        *live = candidate;
        (mode_now, payload.name.clone())
    };

    // Audit the applied mutation (F6.B attempt 2, security P2-1). The name
    // is operator-chosen metadata, not a secret; the URL/auth are NOT
    // echoed.
    audit_config_mutation(ctx, &mode_now, "upstream-add", &saved_name).await;

    Ok(json_response(
        StatusCode::OK,
        format!(
            r#"{{"status":"ok","name":{name:?},"message":"upstream saved"}}"#,
            name = payload.name
        ),
    ))
}

/// Remove a provider by name. Denies removing the LAST upstream (the config
/// requires at least one to route). Persists after removing.
async fn handle_delete_upstream(ctx: &ApiContext, name: &str) -> Result<Response<Full<Bytes>>, String> {
    // Same transaction as PUT /api/config (review v6.1). The guards are
    // evaluated on the candidate; the live config only changes at the end.
    // The write guard is scoped LEXICALLY (the audit emission below awaits
    // after the lock is released).
    let (mode_now, removed) = {
        let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
        if live.upstreams.contains_key(name) && live.upstreams.len() <= 1 {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"cannot remove the last upstream","name":{name:?}}}"#),
            ));
        }
        let mut candidate = live.clone();
        if candidate.upstreams.remove(name).is_none() {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &format!(r#"{{"error":"upstream not found","name":{name:?}}}"#),
            ));
        }
        if let Err(e) = persist_config(ctx, &candidate) {
            return Ok(persist_failed_response(&e));
        }
        let mode_now = format!("{:?}", candidate.mode).to_lowercase();
        *live = candidate;
        (mode_now, name.to_string())
    };

    // Audit the applied mutation (F6.B attempt 2, security P2-1).
    audit_config_mutation(ctx, &mode_now, "upstream-remove", &removed).await;

    Ok(json_response(
        StatusCode::OK,
        &format!(r#"{{"status":"ok","deleted":{removed:?}}}"#),
    ))
}

// ─── F6: persistent detection policy (fix review v6.1) ────────────────────
//
// Before, this section was an in-memory overlay (`PolicyOverlay`) that
// returned `"persisted": false` and never reached the engine: on restart it
// was lost and the detection did not change. Now the policy lives in
// `ProxyConfig.policy` (and therefore in the YAML) and each mutation
// follows the SAME transaction as `PUT /api/config`:
//
//     candidate = current policy + patch
//       → validate (400)
//       → compile the effective engine (400 if a pattern does not compile)
//       → persist YAML (500)
//       → publish to memory + engine hot-swap
//
// If anything fails before the last step, neither the YAML nor the live
// config nor the dataplane engine change.

use crate::detection_policy::{
    parse_action, parse_category, DetectionPolicy, EngineControl, POLICY_ACTIONS, POLICY_CATEGORIES,
};

/// Policy document returned by `GET/PUT /api/policy`.
///
/// Wire names stable with respect to v6.1 (`rules` = per-flag overrides) and
/// `persisted: true`: what you see here is in the YAML.
fn policy_document(
    policy: &DetectionPolicy,
    engine_rules: Option<usize>,
    effective_rules: Option<&[serde_json::Value]>,
) -> serde_json::Value {
    serde_json::json!({
        "categories": policy
            .categories
            .iter()
            .map(|(c, a)| (c.to_string(), a.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>(),
        "rules": policy
            .rule_actions
            .iter()
            .map(|(f, a)| (f.clone(), a.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>(),
        "custom_rules": policy.custom_rules,
        "allowlist": policy.allowlist,
        "valid_actions": POLICY_ACTIONS,
        "valid_categories": POLICY_CATEGORIES,
        "persisted": true,
        "engine_rules": engine_rules,
        "effective_rules": effective_rules,
    })
}

/// Body of `PUT /api/policy`.
///
/// - `categories` / `rules`: patch by key (`null` DELETES the entry, an
///   absent key leaves it intact) — v6.1 semantics, unchanged for the UI.
/// - `custom_rules` / `allowlist`: **full list replacement** (`[]` empties
///   it). They are ordered collections with no natural key in the wire; an
///   index-based patch would be ambiguous. Add/remove of a single allowlist
///   entry stays on `POST`/`DELETE /api/allowlist`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPatch {
    #[serde(default)]
    categories: std::collections::BTreeMap<String, Option<String>>,
    #[serde(default)]
    rules: std::collections::BTreeMap<String, Option<String>>,
    #[serde(default)]
    custom_rules: Option<Vec<cerberus_engine::rule::Rule>>,
    #[serde(default)]
    allowlist: Option<Vec<String>>,
}

impl PolicyPatch {
    /// Apply the patch over `base` and return the CANDIDATE policy (not yet
    /// validated or published). Validates **before mutating** each category
    /// and each action, so a patch with an invalid entry does not leave the
    /// policy half-applied.
    fn apply(self, base: &DetectionPolicy) -> Result<DetectionPolicy, String> {
        // Phase 1: parse the WHOLE patch (any error aborts without mutating).
        let mut category_ops = Vec::with_capacity(self.categories.len());
        for (key, action) in self.categories {
            let category = parse_category(&key)?;
            let action = match action {
                Some(a) => Some(parse_action(&a).map_err(|e| format!("{e} for category {key:?}"))?),
                None => None,
            };
            category_ops.push((category, action));
        }
        let mut rule_ops = Vec::with_capacity(self.rules.len());
        for (flag, action) in self.rules {
            let action = match action {
                Some(a) => Some(parse_action(&a).map_err(|e| format!("{e} for rule {flag:?}"))?),
                None => None,
            };
            rule_ops.push((flag, action));
        }

        // Phase 2: build the candidate on a copy.
        let mut candidate = base.clone();
        for (category, action) in category_ops {
            match action {
                Some(a) => candidate.categories.insert(category, a),
                None => candidate.categories.remove(&category),
            };
        }
        for (flag, action) in rule_ops {
            match action {
                Some(a) => candidate.rule_actions.insert(flag, a),
                None => candidate.rule_actions.remove(&flag),
            };
        }
        if let Some(custom_rules) = self.custom_rules {
            candidate.custom_rules = custom_rules;
        }
        if let Some(allowlist) = self.allowlist {
            candidate.allowlist = allowlist;
        }
        Ok(candidate)
    }
}

/// Apply a candidate policy transactionally: validate → compile the engine
/// → persist the YAML → publish (live config + hot-swap).
///
/// Returns the number of rules of the published engine (`None` if no engine
/// is connected), or the already-formed error response.
fn commit_policy(
    ctx: &ApiContext,
    live: &mut ProxyConfig,
    candidate_policy: DetectionPolicy,
) -> Result<Option<usize>, Box<Response<Full<Bytes>>>> {
    if let Err(e) = candidate_policy.validate() {
        return Err(Box::new(invalid_config_response(&e)));
    }
    let mut candidate_config = live.clone();
    candidate_config.policy = candidate_policy;

    // Compile BEFORE writing: a pattern that does not compile is a 400, not a
    // persisted YAML that would later take down startup.
    let compiled = match ctx.engine.as_ref() {
        Some(engine) => match engine.compile(&candidate_config.policy) {
            Ok(c) => Some(c),
            Err(e) => {
                return Err(Box::new(invalid_config_response(&format!(
                    "policy does not compile: {e}"
                ))))
            }
        },
        None => None,
    };

    if let Err(e) = persist_config(ctx, &candidate_config) {
        return Err(Box::new(persist_failed_response(&e)));
    }

    *live = candidate_config;
    Ok(match (ctx.engine.as_ref(), compiled) {
        (Some(engine), Some(compiled)) => Some(engine.publish(compiled)),
        _ => None,
    })
}

/// Current policy (categories, overrides, custom rules and allowlist).
async fn handle_get_policy(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    // F6.B (Appendix B B.3 `rules list`): the EFFECTIVE rule set (base pack
    // rules + operator overrides + custom rules) exactly as the dataplane
    // runs it, so the CLI/dashboard list what is really live.
    let effective = ctx.engine.as_ref().map(|e| {
        e.live_snapshot()
            .rules()
            .iter()
            .map(|r| {
                serde_json::json!({
                    "flag": r.flag,
                    "category": r.category.to_string(),
                    "action": r.action.to_string(),
                })
            })
            .collect::<Vec<_>>()
    });
    let json = serialize_policy_document(
        &config.policy,
        ctx.engine.as_ref().map(EngineControl::live_rules),
        effective.as_deref(),
    );
    Ok(json_response(StatusCode::OK, json))
}

/// Policy patch. Persists to YAML and publishes the effective engine to the
/// dataplane without restarting (see [`commit_policy`]).
async fn handle_put_policy(ctx: &ApiContext, body: hyper::body::Incoming) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response_close(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response_close(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    Ok(apply_policy_patch(ctx, &body_bytes))
}

/// Core of `PUT /api/policy` over the already-collected bytes (separated
/// from the handler so the transaction is testable without a socket).
fn apply_policy_patch(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    let patch: PolicyPatch = match serde_json::from_slice(body_bytes) {
        Ok(p) => p,
        Err(e) => return invalid_config_response(&format!("invalid policy patch: {e}")),
    };

    // The WRITE lock is held from the candidate calculation until
    // publication: nobody cuts in between validate, persist and publish.
    let (doc, engine_rules) = {
        let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
        let candidate = match patch.apply(&live.policy) {
            Ok(c) => c,
            Err(e) => return invalid_config_response(&e),
        };
        match commit_policy(ctx, &mut live, candidate) {
            Ok(rules) => (live.policy.clone(), rules),
            Err(resp) => return *resp,
        }
    };
    let engine_rules = engine_rules.or_else(|| ctx.engine.as_ref().map(EngineControl::live_rules));
    let effective = ctx.engine.as_ref().map(|e| {
        e.live_snapshot()
            .rules()
            .iter()
            .map(|r| {
                serde_json::json!({
                    "flag": r.flag,
                    "category": r.category.to_string(),
                    "action": r.action.to_string(),
                })
            })
            .collect::<Vec<_>>()
    });
    json_response(
        StatusCode::OK,
        serialize_policy_document(&doc, engine_rules, effective.as_deref()),
    )
}

/// Serialize the policy document; if `serde_json` failed (it cannot with
/// this document), a minimal JSON is returned instead of an opaque 500.
fn serialize_policy_document(
    policy: &DetectionPolicy,
    engine_rules: Option<usize>,
    effective_rules: Option<&[serde_json::Value]>,
) -> String {
    serde_json::to_string(&policy_document(policy, engine_rules, effective_rules))
        .unwrap_or_else(|_| r#"{"error":"policy serialize failed"}"#.to_string())
}

/// Current allowlist (FP triage: the UI lists and removes entries).
async fn handle_get_allowlist(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    let json = serde_json::to_string(&config.policy.allowlist).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

/// Add a value to the allowlist (one-click FP triage). Persists to the YAML
/// and affects the scan path immediately (the hot path reads the allowlist
/// from the shared config).
async fn handle_post_allowlist(ctx: &ApiContext, body: hyper::body::Incoming) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response_close(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response_close(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    let resp = apply_allowlist_add(ctx, &body_bytes);
    // Audit the applied mutation (F6.B attempt 2, security P2-1). The event
    // carries NO fingerprint: the raw value is already HMAC'd for the
    // config; the audit trail needs only the honest action name.
    if resp.status() == StatusCode::OK {
        let mode = live_operation_mode(ctx);
        audit_config_mutation(ctx, &mode, "allowlist-add", "").await;
    }
    Ok(resp)
}

/// `POST /api/break-glass` — issue a one-shot bypass token (F2.3/R9-8).
///
/// Authenticated by the control-plane gate (`X-Cerberus-Admin-Token` /
/// `Authorization: Bearer` when an admin token is configured): **no valid
/// admin token → no break-glass token**. Body:
/// `{"reason": "...", "provider": "openai"|null, "ttl_secs": 60}`.
/// The raw reason is NEVER stored — only its truncated+hashed form. The
/// returned nonce is redeemed exactly once on the data plane via
/// `X-Cerberus-Bypass: break-glass:<nonce>`.
async fn handle_post_break_glass(
    ctx: &ApiContext,
    body: hyper::body::Incoming,
) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response_close(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response_close(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    Ok(apply_break_glass_issue(ctx, &body_bytes))
}

/// Core of `POST /api/break-glass` (testable without a socket).
fn apply_break_glass_issue(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct BreakGlassRequest {
        /// Reason for the bypass (required, non-empty). Stored only hashed.
        reason: String,
        /// Optional provider scope. Absent/null → explicit global scope.
        provider: Option<String>,
        /// Optional TTL override in seconds (clamped to [1, 3600]).
        ttl_secs: Option<u64>,
    }
    let parsed: BreakGlassRequest = match serde_json::from_slice(body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"invalid break-glass request","detail":"{e}"}}"#),
            );
        }
    };
    if parsed.reason.trim().is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid break-glass request","detail":"reason must be non-empty"}"#,
        );
    }
    let scope = parsed.provider.map_or_else(
        cerberus_engine::break_glass::BreakGlassScope::global,
        cerberus_engine::break_glass::BreakGlassScope::for_provider,
    );
    let ttl = parsed.ttl_secs.map(std::time::Duration::from_secs);
    let token = ctx.break_glass.issue(scope, &parsed.reason, ttl);
    tracing::info!(
        "break-glass token issued (scope={}, ttl={}s); raw reason is not stored",
        token.scope,
        token.ttl_secs
    );
    // The nonce is the ONLY copy of the bearer credential returned to the
    // operator; the ledger keeps the scope + reason hash, never the reason.
    let body = format!(
        r#"{{"status":"ok","nonce":"{}","reason_hash":"{}","scope":"{}","ttl_secs":{},"expires_at_nanos":{}}}"#,
        token.nonce, token.reason_hash, token.scope, token.ttl_secs, token.expires_at_nanos
    );
    json_response(StatusCode::OK, body)
}

/// Core of `POST /api/allowlist` (testable without a socket).
///
/// R9-7/F6.3: the body carries the RAW value (`{"value": "sk-..."}`); only
/// its **HMAC fingerprint** (`cerberus:allowlist:v1` domain, installation
/// key) is persisted — the raw value is NEVER stored, echoed back in the
/// response, or logged. Requires the installation audit key (product wiring
/// always keys).
fn apply_allowlist_add(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    let value = match allowlist_value(body_bytes) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Some(key) = ctx.audit_hash_key() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"installation key not wired: the allowlist persists HMAC fingerprints (R9-7) and cannot run unkeyed"}"#,
        );
    };
    let fingerprint = crate::allowlist::fingerprint(key, &value);

    let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
    if live.policy.allowlist.contains(&fingerprint) {
        // Idempotent: it was already there, we do not rewrite the YAML.
        return json_response(
            StatusCode::OK,
            &format!(r#"{{"status":"ok","fingerprint":"{fingerprint}","already_present":true}}"#),
        );
    }
    let mut candidate = live.policy.clone();
    candidate.allowlist.push(fingerprint.clone());
    if let Err(resp) = commit_policy(ctx, &mut live, candidate) {
        return *resp;
    }
    json_response(
        StatusCode::OK,
        &format!(r#"{{"status":"ok","fingerprint":"{fingerprint}"}}"#),
    )
}

/// Extract `{"value": "…"}` from the body of the allowlist routes.
fn allowlist_value(body_bytes: &[u8]) -> Result<String, Box<Response<Full<Bytes>>>> {
    let entry: serde_json::Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(e) => return Err(Box::new(invalid_config_response(&format!("invalid request: {e}")))),
    };
    entry.get("value").and_then(|v| v.as_str()).map_or_else(
        || {
            Err(Box::new(json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"missing 'value'"}"#,
            )))
        },
        |v| Ok(v.to_string()),
    )
}

/// Remove an allowlist entry. The value goes in the body
/// (`{"value":"…"}`) so it does not have to be percent-decoded from the path.
async fn handle_delete_allowlist(
    ctx: &ApiContext,
    body: hyper::body::Incoming,
) -> Result<Response<Full<Bytes>>, String> {
    let body_bytes = match collect_api_body(body).await {
        Ok(b) => b,
        Err(ApiBodyError::TooLarge) => {
            return Ok(json_response_close(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ));
        }
        Err(ApiBodyError::Read(msg)) => {
            return Ok(json_response_close(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"{msg}"}}"#),
            ));
        }
    };
    let resp = apply_allowlist_remove(ctx, &body_bytes);
    // Audit the applied mutation (F6.B attempt 2, security P2-1); NO
    // fingerprint in the event (honest action name only).
    if resp.status() == StatusCode::OK {
        let mode = live_operation_mode(ctx);
        audit_config_mutation(ctx, &mode, "allowlist-remove", "").await;
    }
    Ok(resp)
}

/// Core of `DELETE /api/allowlist` (testable without a socket).
///
/// R9-7/F6.3: the body value may be the RAW value (its fingerprint is
/// computed and removed) or an already-persisted fingerprint. Error and ok
/// responses carry the FINGERPRINT only — never the raw value.
fn apply_allowlist_remove(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    let value = match allowlist_value(body_bytes) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Either the caller passes the fingerprint itself (the dashboard lists
    // fingerprints) or the raw value (compute its fingerprint here).
    let fingerprint = if crate::allowlist::is_fingerprint(&value) {
        value
    } else {
        let Some(key) = ctx.audit_hash_key() else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"installation key not wired: the allowlist persists HMAC fingerprints (R9-7) and cannot run unkeyed"}"#,
            );
        };
        crate::allowlist::fingerprint(key, &value)
    };

    let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
    if !live.policy.allowlist.contains(&fingerprint) {
        return json_response(
            StatusCode::NOT_FOUND,
            &format!(r#"{{"error":"not in allowlist","fingerprint":"{fingerprint}"}}"#),
        );
    }
    let mut candidate = live.policy.clone();
    candidate.allowlist.retain(|v| *v != fingerprint);
    if let Err(resp) = commit_policy(ctx, &mut live, candidate) {
        return *resp;
    }
    json_response(
        StatusCode::OK,
        &format!(r#"{{"status":"ok","removed":"{fingerprint}"}}"#),
    )
}

// ─── Effective CSP of the dashboard (review v6.1) ───────────────────────

/// Dashboard HTML, embedded in the binary.
const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

/// Content of the FIRST `<tag …>` … `</tag>` of `html`.
///
/// Used to hash the dashboard's inline blocks; the HTML is a build asset
/// (`include_str!`), so the parsing is on fixed input and the tests verify
/// that both blocks are found.
fn inline_block<'a>(html: &'a str, tag: &str) -> Option<&'a str> {
    let open = html.find(&format!("<{tag}"))?;
    let start = open + html[open..].find('>')? + 1;
    let end = start + html[start..].find(&format!("</{tag}>"))?;
    Some(&html[start..end])
}

/// `Content-Security-Policy` header of the dashboard, computed once.
static DASHBOARD_CSP: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| build_dashboard_csp(DASHBOARD_HTML));

/// Build the dashboard CSP **without `unsafe-inline`**.
///
/// The dashboard is a single asset served by `/api/dashboard`, so instead
/// of opening `script-src`/`style-src` to everything inline, it authorizes
/// exactly the block served by its `sha256`. Since it is derived from the
/// same `include_str!` that is sent, the hash and content cannot
/// desynchronize. The HTML carries no inline handlers (`onclick=`) or
/// `style=` attributes, which would need `'unsafe-hashes'`; a test watches
/// that.
///
/// `frame-ancestors` only has effect in the header (a `<meta>` ignores it),
/// which is the main reason to serve the CSP over HTTP.
fn build_dashboard_csp(html: &str) -> String {
    let script = inline_block(html, "script").unwrap_or_default();
    let style = inline_block(html, "style").unwrap_or_default();
    format!(
        "default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'sha256-{style_hash}'; \
         connect-src 'self'; img-src 'self' data:; font-src 'none'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'; object-src 'none'",
        script_hash = csp_hash::base64(&csp_hash::sha256(script.as_bytes())),
        style_hash = csp_hash::base64(&csp_hash::sha256(style.as_bytes())),
    )
}

/// Minimal SHA-256 + Base64 for the CSP hashes.
///
/// Implemented here (safe Rust, ~60 lines) to avoid adding a dependency to
/// the proxy crate for a single consumer: the `Content-Security-Policy`
/// header, which needs `'sha256-<base64>'` of the served inline block.
/// Verified against the FIPS 180-4 vectors in the tests.
mod csp_hash {
    /// SHA-256 round constants (FIPS 180-4 §4.2.2).
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    /// SHA-256 of `data`.
    #[allow(clippy::needless_range_loop, clippy::chunks_exact_to_as_chunks)]
    pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let bit_len = (data.len() as u64) * 8;
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for block in msg.chunks_exact(64) {
            let mut w = [0_u32; 64];
            for (i, word) in block.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }
            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let choose = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(choose)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let major = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(major);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }
            for (acc, x) in h.iter_mut().zip(v) {
                *acc = acc.wrapping_add(x);
            }
        }
        let mut out = [0_u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Standard Base64 alphabet (RFC 4648), the one the CSP expects.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Standard Base64 with padding.
    pub(super) fn base64(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b1 = u32::from(chunk[0]);
            let b2 = u32::from(chunk.get(1).copied().unwrap_or(0));
            let b3 = u32::from(chunk.get(2).copied().unwrap_or(0));
            let n = (b1 << 16) | (b2 << 8) | b3;
            out.push(char::from(ALPHABET[(n >> 18) as usize & 63]));
            out.push(char::from(ALPHABET[(n >> 12) as usize & 63]));
            out.push(if chunk.len() > 1 {
                char::from(ALPHABET[(n >> 6) as usize & 63])
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                char::from(ALPHABET[n as usize & 63])
            } else {
                '='
            });
        }
        out
    }
}

/// Serve the dashboard (review v5 F6): public static HTML WITHOUT data. It
/// does not require auth (the `/api/*` routing exempts it) and NEVER embeds
/// the token in the DOM; the client asks for it via the login card and sends
/// it via the `X-Cerberus-Admin-Token` header.
/// Review v6.1: the CSP travels in the HEADER (a `<meta>` cannot apply
/// `frame-ancestors`) and without `unsafe-inline`: the served inline block
/// of the asset is authorized by its `sha256`. See [`build_dashboard_csp`].
fn handle_dashboard(_ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-security-policy", DASHBOARD_CSP.as_str())
        // Defense in depth for clients that ignore `frame-ancestors`.
        .header("x-frame-options", "DENY")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        // The dashboard is embedded static HTML: it is not cached so a
        // binary upgrade does not serve the old UI against the new API.
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(DASHBOARD_HTML)))
        .map_err(|e| e.to_string())
}

fn json_response(status: StatusCode, body: impl AsRef<str>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.as_ref().to_string())))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(r#"{"error":"response build failed"}"#)))
                .unwrap()
        })
}

/// JSON response with `Connection: close`. Used when rejecting an oversized
/// body (413) or any control-plane error: the client must not reuse a
/// connection whose body was left undrained (fix review v5 — robustness
/// against flaky smokes).
#[must_use]
fn json_response_close(status: StatusCode, body: impl AsRef<str>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(body.as_ref().to_string())))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(r#"{"error":"response build failed"}"#)))
                .unwrap()
        })
}

fn not_found() -> Response<Full<Bytes>> {
    json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)
}

/// Record an audit event in the API context.
pub async fn record_event(ctx: &ApiContext, event: AuditEvent) {
    let mut events = ctx.events.lock().await;
    events.push(event.clone());
    // Keep only the last 10000 events in memory
    if events.len() > 10_000 {
        events.remove(0);
    }
    // Write to the SQLite store if available
    if let Some(ref store) = ctx.store {
        store.write_event_async(event).await;
    }
}

/// Audit a successful control-plane CONFIG MUTATION (F6.B attempt 2,
/// security P2-1): emit the event (visible via `GET /api/events`) AND a tee
/// log line. Reload used to swap the whole live config with zero trace; the
/// same gap covered config PUT, allowlist CRUD, upstream CRUD and the pack
/// mutations.
///
/// `mode` = the live operation mode at mutation time; `detail` = optional
/// non-secret metadata (a pack/upstream name). NEVER a token, a raw
/// allowlist value or a fingerprint — the event must stay secret-free.
async fn audit_config_mutation(ctx: &ApiContext, mode: &str, action: &str, detail: &str) {
    tracing::info!(action = %action, detail = %detail, "control-plane config mutation applied");
    let event = AuditEvent::control_plane(mode, action, detail);
    record_event(ctx, event).await;
}

/// Live operation mode as a lowercase string (the event `mode` field).
fn live_operation_mode(ctx: &ApiContext) -> String {
    let live = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    format!("{:?}", live.mode).to_lowercase()
}

/// Extract the provider from the request path.
///
/// E.g. "/openai/v1/chat" → "openai", "/anthropic/v1/messages" → "anthropic".
#[must_use]
pub fn extract_provider(path: &str) -> String {
    let patterns: &[&str] = &["/openai/", "/anthropic/", "/gemini/", "/mistral/", "/groq/"];
    for pattern in patterns {
        if path.starts_with(pattern) {
            let prefix = &pattern[1..];
            let provider_end = prefix.find('/').unwrap_or(prefix.len());
            return prefix[..provider_end].to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "x"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn authorized_accepts_bearer_and_alt_header() {
        use hyper::http::HeaderValue;
        let mut headers = hyper::HeaderMap::new();
        assert!(!authorized(&headers, "tok"));
        headers.insert(hyper::header::AUTHORIZATION, HeaderValue::from_static("Bearer tok"));
        assert!(authorized(&headers, "tok"));
        assert!(!authorized(&headers, "other"));

        let mut h2 = hyper::HeaderMap::new();
        h2.insert("x-cerberus-admin-token", HeaderValue::from_static("foo"));
        assert!(authorized(&h2, "foo"));
        assert!(!authorized(&h2, "bar"));
    }

    #[test]
    fn admin_token_header_via_constant_is_used() {
        use hyper::http::HeaderValue;
        let mut headers = hyper::HeaderMap::new();
        assert!(!admin_token_header_is_present(&headers, "tok"));
        headers.insert(ADMIN_TOKEN_HEADER, HeaderValue::from_static("valid-token"));
        assert!(admin_token_header_is_present(&headers, "valid-token"));
        assert!(!admin_token_header_is_present(&headers, "other"));
        // With space: it is trimmed.
        let mut h2 = hyper::HeaderMap::new();
        h2.insert(ADMIN_TOKEN_HEADER, HeaderValue::from_static("  spaced  "));
        assert!(admin_token_header_is_present(&h2, "spaced"));
    }

    #[test]
    fn dashboard_served_without_auth_when_token_set() {
        // Review v5 F6: the dashboard is public static HTML without data. With
        // an admin token configured auth is NOT required and the token is NOT
        // embedded in the DOM (the login card lives in the JS).
        let cfg = ProxyConfig {
            admin_token: Some("tok<&>\"'".to_string()),
            ..ProxyConfig::default()
        };
        let ctx = ApiContext::new(Arc::new(RwLock::new(cfg)));

        // The dashboard route is exempt from the auth gate...
        assert!(!route_serves_data("/api/dashboard"));
        // ...while every data route requires auth.
        assert!(route_serves_data("/api/events"));
        assert!(route_serves_data("/api/stats"));
        assert!(route_serves_data("/api/config"));

        // The HTML is served (200) without the token embedded in the DOM.
        let resp = handle_dashboard(&ctx).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().into_inner().expect("body").to_vec();
        let text = String::from_utf8(body).unwrap();
        assert!(
            !text.contains(r#"<var id="cerberus-token""#),
            "token var must never be embedded"
        );
        assert!(!text.contains("tok&lt;"), "no escaped token content");
        assert!(!text.contains("tok<&>\""), "raw token leaked into HTML");
    }

    #[test]
    fn config_get_and_put_requires_token() {
        use hyper::http::HeaderValue;
        let cfg = ProxyConfig {
            admin_token: Some("correct-horse-battery-staple".to_string()),
            ..ProxyConfig::default()
        };
        let empty = hyper::HeaderMap::new();

        // GET/PUT /api/config without token → 401 (they share the same gate).
        let denied = auth_gate(&cfg, "/api/config", &empty).expect("config must be denied");
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        // With a valid token (via X-Cerberus-Admin-Token) → allowed.
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            ADMIN_TOKEN_HEADER,
            HeaderValue::from_static("correct-horse-battery-staple"),
        );
        assert!(auth_gate(&cfg, "/api/config", &headers).is_none());

        // /api/dashboard stays exempt even without a token.
        assert!(auth_gate(&cfg, "/api/dashboard", &empty).is_none());
    }

    #[tokio::test]
    async fn stats_filters_by_provider_query_param() {
        let cfg = Arc::new(RwLock::new(ProxyConfig::default()));
        let ctx = ApiContext::new(cfg);
        {
            let mut events = ctx.events.lock().await;
            events.push(AuditEvent::from_findings(
                &[],
                cerberus_engine::rule::Action::Block,
                "api",
                "opencode",
                "openai",
            ));
            events.push(AuditEvent::from_findings(
                &[],
                cerberus_engine::rule::Action::Block,
                "api",
                "claude-code",
                "anthropic",
            ));
        }

        let s = handle_get_stats(&ctx, Some("openai".to_string()), None, None)
            .await
            .unwrap()
            .into_body()
            .into_inner()
            .expect("body")
            .to_vec();
        let s = String::from_utf8(s).unwrap();
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(json["total"].as_u64(), Some(1), "only openai counted: {json}");
        assert_eq!(
            json["by_provider"][0]["provider"].as_str(),
            Some("openai"),
            "filtered provider: {json}"
        );

        // Without provider → counts both.
        let all = handle_get_stats(&ctx, None, None, None)
            .await
            .unwrap()
            .into_body()
            .into_inner()
            .expect("body")
            .to_vec();
        let all = String::from_utf8(all).unwrap();
        let all_json: serde_json::Value = serde_json::from_str(&all).unwrap();
        assert_eq!(all_json["total"].as_u64(), Some(2));
    }

    #[test]
    fn query_provider_parses_request_query() {
        assert_eq!(query_provider(""), None);
        assert_eq!(query_provider("provider=openai"), Some("openai".to_string()));
        assert_eq!(
            query_provider("a=1&provider=anthropic&b=2"),
            Some("anthropic".to_string())
        );
        assert_eq!(query_provider("provider="), None);
        assert_eq!(query_provider("mode=shadow"), None);
    }

    #[test]
    fn control_plane_max_bytes_is_1_mibe() {
        assert_eq!(CONTROL_PLANE_MAX_BYTES, 1 << 20);
        assert!(
            cerberus_packs::wire::MAX_PACK_BYTES
                .saturating_mul(2)
                .saturating_add(1024)
                <= CONTROL_PLANE_MAX_BYTES,
            "the maximum wire v2 envelope must fit in the HTTP collector"
        );
    }

    #[test]
    fn admin_token_min_bytes_is_24() {
        assert_eq!(ADMIN_TOKEN_MIN_BYTES, 24);
        assert_eq!(ADMIN_TOKEN_HEADER, "x-cerberus-admin-token");
    }

    #[test]
    fn expected_admin_token_filters_empty() {
        let mut cfg = ProxyConfig::default();
        assert!(expected_admin_token(&cfg).is_none());
        cfg.admin_token = Some("tok".to_string());
        assert_eq!(expected_admin_token(&cfg), Some("tok"));
        cfg.admin_token = Some(String::new());
        assert!(expected_admin_token(&cfg).is_none());
    }

    // ─── Review v6.1: config DTOs ─────────────────────────────────────────────

    /// A 28-byte token: passes the [`ADMIN_TOKEN_MIN_BYTES`] threshold.
    const STRONG_TOKEN: &str = "correct-horse-battery-stapl0";

    fn cfg_with_token(token: &str) -> ProxyConfig {
        ProxyConfig {
            admin_token: Some(token.to_string()),
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn config_view_never_carries_the_admin_token() {
        // The GET DTO does NOT HAVE an `admin_token` field, so there is nothing
        // to redact: only the derived boolean.
        let cfg = cfg_with_token(STRONG_TOKEN);
        let json = serde_json::to_string(&ConfigView::from_config(&cfg)).unwrap();
        assert!(!json.contains(STRONG_TOKEN), "token leaked in ConfigView: {json}");
        assert!(
            !json.contains("\"admin_token\""),
            "ConfigView must not have the key: {json}"
        );
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["admin_token_configured"].as_bool(), Some(true));
        // Without a configured token the boolean goes down.
        let open = ProxyConfig::default();
        let json = serde_json::to_string(&ConfigView::from_config(&open)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["admin_token_configured"].as_bool(), Some(false));
    }

    #[test]
    fn config_view_round_trips_into_config_patch() {
        // Client contract: the GET body can be resent as-is to the PUT (the
        // dashboard does GET → edit → PUT).
        let cfg = cfg_with_token(STRONG_TOKEN);
        let json = serde_json::to_string(&ConfigView::from_config(&cfg)).unwrap();
        let patch: ConfigPatch = serde_json::from_str(&json).expect("GET body must be a valid PUT body");
        let applied = patch.apply(&cfg);
        assert_eq!(applied.admin_token.as_deref(), Some(STRONG_TOKEN), "token preserved");
    }

    #[test]
    fn config_patch_preserves_omitted_fields() {
        let mut base = cfg_with_token(STRONG_TOKEN);
        base.upstreams.insert(
            "openai".to_string(),
            UpstreamConfig {
                url: "https://api.openai.com".to_string(),
                path_prefix: None,
                auth_header: "authorization".to_string(),
                mode: None,
                expected_auth: None,
            },
        );
        let patch: ConfigPatch = serde_json::from_str(r#"{"mode":"shadow"}"#).unwrap();
        let applied = patch.apply(&base);
        assert_eq!(
            applied.mode,
            crate::config::OperationMode::Shadow,
            "patched field applies"
        );
        // Everything else is preserved — especially the token, which GET does
        // not reveal.
        assert_eq!(applied.admin_token.as_deref(), Some(STRONG_TOKEN));
        assert_eq!(applied.listen, base.listen);
        assert_eq!(applied.log_level, base.log_level);
        assert_eq!(applied.health_path, base.health_path);
        assert_eq!(applied.max_body_bytes, base.max_body_bytes);
        assert_eq!(applied.upstreams.len(), 1, "upstreams are not lost in a partial patch");
    }

    #[test]
    fn config_patch_ignores_read_only_admin_token_configured() {
        // Adversarial: a client tries to DISABLE auth via the read-only
        // boolean. The body is accepted and the field is ignored.
        let base = cfg_with_token(STRONG_TOKEN);
        let patch: ConfigPatch = serde_json::from_str(r#"{"admin_token_configured":false}"#).unwrap();
        let applied = patch.apply(&base);
        assert_eq!(
            applied.admin_token.as_deref(),
            Some(STRONG_TOKEN),
            "admin_token_configured is read-only: it cannot clear the token"
        );
        assert!(expected_admin_token(&applied).is_some(), "auth is still active");
    }

    #[test]
    fn config_patch_explicit_null_clears_the_token() {
        // Explicit `null` DOES delete (unlike omitting): it is the way to switch
        // to dev mode from the API, and is only allowed on loopback (see the
        // exposure test).
        let base = cfg_with_token(STRONG_TOKEN);
        let patch: ConfigPatch = serde_json::from_str(r#"{"admin_token":null}"#).unwrap();
        assert!(patch.apply(&base).admin_token.is_none());
        // And a new value replaces it.
        let patch: ConfigPatch = serde_json::from_str(r#"{"admin_token":"another-24-byte-token-min"}"#).unwrap();
        assert_eq!(
            patch.apply(&base).admin_token.as_deref(),
            Some("another-24-byte-token-min")
        );
    }

    #[test]
    fn config_patch_distinguishes_null_from_omitted_max_body_bytes() {
        let base = ProxyConfig::default();
        assert!(base.max_body_bytes.is_some());
        let omitted: ConfigPatch = serde_json::from_str("{}").unwrap();
        assert_eq!(omitted.apply(&base).max_body_bytes, base.max_body_bytes);
        let nulled: ConfigPatch = serde_json::from_str(r#"{"max_body_bytes":null}"#).unwrap();
        assert!(nulled.apply(&base).max_body_bytes.is_none(), "null = no limit");
    }

    #[test]
    fn config_patch_rejects_unknown_fields() {
        // A typo in the field name fails loudly, not silently.
        let err = serde_json::from_str::<ConfigPatch>(r#"{"admin_tokens":"x"}"#);
        assert!(err.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn listen_is_loopback_is_safe_by_default() {
        assert!(listen_is_loopback("127.0.0.1:8787"));
        assert!(listen_is_loopback("127.9.9.9:1"));
        assert!(listen_is_loopback("[::1]:8787"));
        assert!(listen_is_loopback("localhost:8787"));
        assert!(listen_is_loopback("LocalHost:8787"));
        assert!(!listen_is_loopback("0.0.0.0:8080"));
        assert!(!listen_is_loopback("10.0.0.5:8080"));
        assert!(!listen_is_loopback("[::]:8080"));
        // What does not resolve to loopback is treated as PUBLIC.
        assert!(!listen_is_loopback("proxy.internal:8080"));
        assert!(!listen_is_loopback(""));
    }

    #[test]
    fn validate_control_plane_exposure_matches_the_bind_rule() {
        // Loopback: tokenless dev mode allowed (same as on bind).
        assert!(validate_control_plane_exposure(&ProxyConfig::default()).is_ok());

        let public = |token: Option<&str>| ProxyConfig {
            listen: "0.0.0.0:8080".to_string(),
            admin_token: token.map(ToString::to_string),
            ..ProxyConfig::default()
        };
        assert!(validate_control_plane_exposure(&public(None)).is_err(), "no token");
        assert!(
            validate_control_plane_exposure(&public(Some("change-me"))).is_err(),
            "short token"
        );
        let short = "x".repeat(ADMIN_TOKEN_MIN_BYTES - 1);
        assert!(
            validate_control_plane_exposure(&public(Some(&short))).is_err(),
            "23 bytes"
        );
        let exact = "x".repeat(ADMIN_TOKEN_MIN_BYTES);
        assert!(
            validate_control_plane_exposure(&public(Some(&exact))).is_ok(),
            "24 bytes"
        );
        assert!(validate_control_plane_exposure(&public(Some(STRONG_TOKEN))).is_ok());
    }

    #[test]
    fn patch_that_would_open_the_control_plane_is_rejected() {
        // The case the gate must catch BEFORE persisting: moving `listen` to a
        // public interface while deleting the token.
        let base = cfg_with_token(STRONG_TOKEN);
        let patch: ConfigPatch = serde_json::from_str(r#"{"listen":"0.0.0.0:8080","admin_token":null}"#).unwrap();
        let candidate = patch.apply(&base);
        assert!(validate_control_plane_exposure(&candidate).is_err());
        // …and with the token intact (omitted) the same listen change passes.
        let patch: ConfigPatch = serde_json::from_str(r#"{"listen":"0.0.0.0:8080"}"#).unwrap();
        assert!(validate_control_plane_exposure(&patch.apply(&base)).is_ok());
    }

    #[test]
    fn persist_config_is_a_noop_without_a_path() {
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default())));
        assert!(persist_config(&ctx, &ProxyConfig::default()).is_ok());
    }

    #[test]
    fn persist_config_fails_on_an_unwritable_path() {
        // The 500 from PUT depends on this failing: nonexistent directory.
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default())))
            .with_config_path(std::path::PathBuf::from("/nonexistent-cerberus-dir/config.yaml"));
        assert!(persist_config(&ctx, &ProxyConfig::default()).is_err());
    }

    /// F6.A attempt 2 (P1 regression): a control-plane write on a 0600
    /// fixture must leave config.yaml at 0600 — the file carries the admin
    /// token, and the old plain tmp write replaced it with a umask 0644 file
    /// on the first PUT. `persist_config` is the writer behind every
    /// mutation (PUT /api/config, PUT /api/policy, POST /api/allowlist,
    /// upstream CRUD).
    #[test]
    fn persist_config_keeps_0600_on_an_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "cerberus_f6a2_persist_existing_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("config.yaml");
        std::fs::write(&path, "listen: 127.0.0.1:8787\nadmin_token: stale-token\n").expect("fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod fixture");
        }

        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default()))).with_config_path(path.clone());
        persist_config(&ctx, &ProxyConfig::default()).expect("persist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "config.yaml must stay 0600 after a control-plane write, got {mode:o}"
            );
        }
        assert!(
            !dir.join("config.yaml.tmp").exists(),
            "no tmp residue may be left behind"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// F6.A attempt 2 (P1): the first write on a fresh path must create the
    /// file at 0600 from birth too (no umask-derived creation).
    #[test]
    fn persist_config_creates_the_file_at_0600() {
        let dir = std::env::temp_dir().join(format!(
            "cerberus_f6a2_persist_fresh_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("config.yaml");
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default()))).with_config_path(path.clone());
        persist_config(&ctx, &ProxyConfig::default()).expect("persist");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "a created config.yaml must be 0600, got {mode:o}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // ─── F6 v6.1 fix: persistent detection policy ───────────────────────────

    /// Minimal valid custom rule.
    fn custom_rule(flag: &str, category: &str, action: &str, pattern: &str) -> serde_json::Value {
        serde_json::json!({
            "flag": flag,
            "category": category,
            "severity": "high",
            "action": action,
            "patterns": [pattern],
        })
    }

    /// Context with YAML persistence and a connected live engine (what the real
    /// daemon has). R9-7: the installation audit-hash key is wired (like the
    /// daemon) — the allowlist fingerprints require it.
    fn policy_ctx(dir: &std::path::Path) -> (ApiContext, crate::detection_policy::EngineControl) {
        let base = vec![crate::detection_policy::tests_support::base_rule("pack.token")];
        let engine =
            crate::detection_policy::build_engine(&base, &ProxyConfig::default().policy, None).expect("boot engine");
        let live = Arc::new(RwLock::new(Arc::new(engine)));
        let control = crate::detection_policy::EngineControl::new(live, base, None);
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default())))
            .with_config_path(dir.join("config.yaml"))
            .with_engine(control.clone())
            .with_audit_hash_key(TEST_INSTALLATION_KEY.to_vec());
        (ctx, control)
    }

    /// Deterministic test installation key (R9-7 fingerprints).
    const TEST_INSTALLATION_KEY: &[u8] = b"cerberus-test-installation-key-0123456789ab";

    /// The fingerprint `apply_allowlist_add` persists for `raw` under
    /// [`TEST_INSTALLATION_KEY`].
    fn test_fingerprint(raw: &str) -> String {
        crate::allowlist::fingerprint(TEST_INSTALLATION_KEY, raw)
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "cerberus_api_policy_{tag}_{}_{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
        ));
        std::fs::create_dir_all(&d).expect("tmpdir");
        d
    }

    fn put_policy(ctx: &ApiContext, body: &serde_json::Value) -> (StatusCode, serde_json::Value) {
        decode(apply_policy_patch(ctx, body.to_string().as_bytes()))
    }

    fn decode(resp: Response<Full<Bytes>>) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = resp.into_body().into_inner().expect("body").to_vec();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[test]
    fn policy_defaults_are_inherited_rule_actions() {
        let p = ProxyConfig::default().policy;
        assert!(p.categories.is_empty(), "absent categories = inherit the rule action");
        assert!(p.rule_actions.is_empty());
        assert!(p.custom_rules.is_empty());
    }

    #[test]
    fn policy_patch_rejects_bad_actions_and_categories_before_mutating() {
        let base = DetectionPolicy::seeded();

        let bad_action: PolicyPatch = serde_json::from_str(r#"{"rules":{"a.b":"nuke"}}"#).unwrap();
        let err = bad_action.apply(&base).expect_err("invalid action");
        assert!(err.contains("nuke") && err.contains("allow|warn|redact|block"), "{err}");

        let bad_category: PolicyPatch = serde_json::from_str(r#"{"categories":{"secretos":"block"}}"#).unwrap();
        let err = bad_category.apply(&base).expect_err("invalid category");
        assert!(
            err.contains("secretos") && err.contains("secrets|pii|internal_code"),
            "{err}"
        );

        // A patch with one valid entry and one invalid one applies NONE.
        let mixed: PolicyPatch = serde_json::from_str(r#"{"categories":{"secrets":"block","pii":"nuke"}}"#).unwrap();
        assert!(mixed.apply(&base).is_err());
        assert!(base.categories.is_empty(), "the base policy was not touched");

        // Unknown key = 400, not silence.
        assert!(serde_json::from_str::<PolicyPatch>(r#"{"nope":{}}"#).is_err());
        // `admin_token` does not sneak in through this door.
        assert!(serde_json::from_str::<PolicyPatch>(r#"{"admin_token":"x"}"#).is_err());
    }

    #[test]
    fn policy_patch_preserves_absent_keys_and_deletes_on_null() {
        let mut base = DetectionPolicy::seeded();
        base.categories.insert(
            cerberus_engine::rule::Category::Secrets,
            cerberus_engine::rule::Action::Redact,
        );
        base.categories.insert(
            cerberus_engine::rule::Category::Pii,
            cerberus_engine::rule::Action::Warn,
        );
        base.rule_actions
            .insert("secret.keep".to_string(), cerberus_engine::rule::Action::Block);
        base.allowlist.push("keep-me".to_string());

        let patch: PolicyPatch = serde_json::from_str(r#"{"categories":{"pii":null}}"#).unwrap();
        let out = patch.apply(&base).expect("apply");
        assert!(
            !out.categories.contains_key(&cerberus_engine::rule::Category::Pii),
            "null deletes"
        );
        assert!(
            out.categories.contains_key(&cerberus_engine::rule::Category::Secrets),
            "absent key is preserved"
        );
        assert_eq!(out.rule_actions.len(), 1, "the overrides are preserved");
        assert_eq!(out.allowlist, vec!["keep-me".to_string()], "the allowlist is preserved");
    }

    #[test]
    fn policy_patch_replaces_custom_rules_and_allowlist_wholesale() {
        let mut base = DetectionPolicy::seeded();
        base.allowlist.push("old".to_string());
        let patch: PolicyPatch = serde_json::from_str(r#"{"allowlist":[],"custom_rules":[]}"#).unwrap();
        let out = patch.apply(&base).expect("apply");
        assert!(out.allowlist.is_empty(), "[] empties the list");
        assert!(out.custom_rules.is_empty());
    }

    #[test]
    fn put_policy_persists_the_yaml_and_swaps_the_live_engine() {
        let dir = tmpdir("persist");
        let (ctx, control) = policy_ctx(&dir);
        assert_eq!(control.live_rules(), 1, "starts with the pack rule");

        let fp = test_fingerprint("sk-EXAMPLE");
        let (status, doc) = put_policy(
            &ctx,
            &serde_json::json!({
                "categories": {"secrets": "block"},
                "rules": {"pack.token": "warn"},
                "custom_rules": [custom_rule("custom.badge", "internal_code", "block", r"BADGE-\d{4}")],
                "allowlist": [fp],
            }),
        );
        assert_eq!(status, StatusCode::OK, "{doc}");
        assert_eq!(doc["persisted"].as_bool(), Some(true), "no longer an in-memory overlay");
        assert_eq!(doc["categories"]["secrets"].as_str(), Some("block"));
        assert_eq!(doc["rules"]["pack.token"].as_str(), Some("warn"));
        assert_eq!(doc["custom_rules"][0]["flag"].as_str(), Some("custom.badge"));
        assert_eq!(
            doc["allowlist"][0].as_str(),
            Some(test_fingerprint("sk-EXAMPLE")).as_deref()
        );

        // Live engine: the pack rule is STILL there and the custom one was added.
        assert_eq!(control.live_rules(), 2, "packs + custom, without losing any");
        assert_eq!(doc["engine_rules"].as_u64(), Some(2));

        // YAML: it can be re-read and rebuilds the SAME policy (restart).
        let yaml = std::fs::read_to_string(dir.join("config.yaml")).expect("written yaml");
        let reloaded = ProxyConfig::parse(&yaml).expect("reparse");
        assert_eq!(reloaded.policy, ctx.config.read().unwrap().policy);
        assert_eq!(reloaded.policy.custom_rules.len(), 1);
        assert_eq!(reloaded.policy.allowlist, vec![test_fingerprint("sk-EXAMPLE")]);
        assert!(
            !yaml.contains("sk-EXAMPLE\""),
            "raw value never lands in the YAML: {yaml}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_policy_with_a_broken_pattern_is_400_and_changes_nothing() {
        let dir = tmpdir("broken");
        let (ctx, control) = policy_ctx(&dir);
        let (status, doc) = put_policy(
            &ctx,
            &serde_json::json!({ "custom_rules": [custom_rule("custom.bad", "secrets", "block", "([unclosed")] }),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST, "{doc}");
        assert!(
            doc["error"].as_str().unwrap_or_default().contains("do not compile"),
            "{doc}"
        );
        assert_eq!(control.live_rules(), 1, "the live engine did not change");
        assert!(ctx.config.read().unwrap().policy.custom_rules.is_empty());
        assert!(!dir.join("config.yaml").exists(), "an invalid policy is not persisted");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_policy_persist_failure_leaves_config_and_engine_untouched() {
        let base = vec![crate::detection_policy::tests_support::base_rule("pack.token")];
        let engine =
            crate::detection_policy::build_engine(&base, &ProxyConfig::default().policy, None).expect("engine");
        let control = crate::detection_policy::EngineControl::new(Arc::new(RwLock::new(Arc::new(engine))), base, None);
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default())))
            .with_config_path(std::path::PathBuf::from("/nonexistent-cerberus-dir/config.yaml"))
            .with_engine(control.clone());

        let (status, doc) = put_policy(
            &ctx,
            &serde_json::json!({ "custom_rules": [custom_rule("custom.ok", "secrets", "block", "OK-[0-9]+")] }),
        );
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{doc}");
        assert_eq!(
            control.live_rules(),
            1,
            "an engine that could not be persisted is not published"
        );
        assert!(ctx.config.read().unwrap().policy.custom_rules.is_empty());
    }

    #[tokio::test]
    async fn policy_and_allowlist_are_exposed_together() {
        let dir = tmpdir("together");
        let (ctx, _control) = policy_ctx(&dir);
        let raw = "sk-EXAMPLE-do-not-flag";
        let (status, doc) = decode(apply_allowlist_add(&ctx, br#"{"value":"sk-EXAMPLE-do-not-flag"}"#));
        assert_eq!(status, StatusCode::OK, "{doc}");
        // R9-7: the response carries the FINGERPRINT, never the raw value.
        assert_eq!(doc["fingerprint"].as_str(), Some(test_fingerprint(raw)).as_deref());
        assert!(!doc.to_string().contains(raw), "raw value must not be echoed: {doc}");

        let body = handle_get_policy(&ctx)
            .await
            .unwrap()
            .into_body()
            .into_inner()
            .expect("body")
            .to_vec();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["categories"].as_object().map(serde_json::Map::len),
            Some(0),
            "without an explicit override, the API exposes inherited categories as absent"
        );
        assert_eq!(json["allowlist"][0].as_str(), Some(test_fingerprint(raw)).as_deref());
        assert_eq!(json["valid_actions"].as_array().map(Vec::len), Some(4));
        assert_eq!(json["valid_categories"].as_array().map(Vec::len), Some(3));
        assert_eq!(json["persisted"].as_bool(), Some(true), "the policy is in the YAML");

        // The allowlist FINGERPRINT ended up in the YAML (survives restart);
        // the raw value does not exist anywhere on disk (R9-7).
        let yaml = std::fs::read_to_string(dir.join("config.yaml")).expect("yaml");
        assert!(yaml.contains(test_fingerprint(raw).as_str()), "{yaml}");
        assert!(!yaml.contains(raw), "raw value never persisted: {yaml}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn allowlist_add_is_idempotent_and_delete_is_404_when_absent() {
        let dir = tmpdir("idem");
        let (ctx, _control) = policy_ctx(&dir);
        for _ in 0..2 {
            let (status, _) = decode(apply_allowlist_add(&ctx, br#"{"value":"dup"}"#));
            assert_eq!(status, StatusCode::OK);
        }
        assert_eq!(
            ctx.config.read().unwrap().policy.allowlist,
            vec![test_fingerprint("dup")],
            "it is not duplicated"
        );

        let (status, doc) = decode(apply_allowlist_remove(&ctx, br#"{"value":"ghost"}"#));
        assert_eq!(status, StatusCode::NOT_FOUND, "{doc}");
        // R9-7: the 404 echoes the computed FINGERPRINT, never the raw value.
        assert!(
            !doc.to_string().contains("ghost"),
            "the raw value must not be echoed back: {doc}"
        );
        assert_eq!(
            doc["fingerprint"].as_str(),
            Some(test_fingerprint("ghost")).as_deref(),
            "the fingerprint identifies the entry"
        );

        let (status, _) = decode(apply_allowlist_remove(&ctx, br#"{"value":"dup"}"#));
        assert_eq!(status, StatusCode::OK);
        assert!(ctx.config.read().unwrap().policy.allowlist.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_config_patch_never_clobbers_the_policy() {
        // `ConfigPatch::apply` is the only way `PUT /api/config` builds the
        // candidate config: the policy must come out intact.
        let mut base = ProxyConfig::default();
        base.policy
            .custom_rules
            .push(serde_json::from_value(custom_rule("custom.keep", "secrets", "block", "KEEP-[0-9]+")).unwrap());
        let patch: ConfigPatch = serde_json::from_str(r#"{"log_level":"debug"}"#).unwrap();
        let candidate = patch.apply(&base);
        assert_eq!(candidate.log_level, "debug");
        assert_eq!(
            candidate.policy, base.policy,
            "PUT /api/config does not clobber the policy"
        );
    }

    #[test]
    fn config_view_does_not_expose_the_policy_so_a_get_put_cycle_still_works() {
        // `ConfigPatch` is `deny_unknown_fields`: if `ConfigView` returned
        // `policy`, resending the GET verbatim in a PUT would be a 400.
        let cfg = ProxyConfig::default();
        let json = serde_json::to_string(&ConfigView::from_config(&cfg)).expect("serialize");
        assert!(!json.contains(r#""policy""#), "{json}"); // `fail_policy` yes, `policy` no
        if let Err(e) = serde_json::from_str::<ConfigPatch>(&json) {
            panic!("GET→PUT verbatim must still be valid: {e} — {json}");
        }
    }

    // ─── Review v6.1: dashboard CSP ───────────────────────────────────────────

    #[test]
    fn sha256_matches_fips_180_4_vectors() {
        use std::fmt::Write as _;
        let hex = |b: &[u8]| {
            b.iter().fold(String::new(), |mut acc, x| {
                let _ = write!(acc, "{x:02x}");
                acc
            })
        };
        assert_eq!(
            hex(&csp_hash::sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&csp_hash::sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 56 bytes: forces the second padding block.
        assert_eq!(
            hex(&csp_hash::sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&csp_hash::sha256(&b"a".repeat(1_000_000))),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        assert_eq!(csp_hash::base64(b""), "");
        assert_eq!(csp_hash::base64(b"f"), "Zg==");
        assert_eq!(csp_hash::base64(b"fo"), "Zm8=");
        assert_eq!(csp_hash::base64(b"foo"), "Zm9v");
        assert_eq!(csp_hash::base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(csp_hash::base64(&[0xff, 0xef, 0xfe]), "/+/+");
    }

    #[test]
    fn inline_block_extracts_the_dashboard_blocks() {
        let html = "<head><style>a{}</style><script>var x=1;</script></head>";
        assert_eq!(inline_block(html, "style"), Some("a{}"));
        assert_eq!(inline_block(html, "script"), Some("var x=1;"));
        assert_eq!(inline_block(html, "nope"), None);
        // The real dashboard has exactly one block of each.
        assert_eq!(DASHBOARD_HTML.matches("<script").count(), 1);
        assert_eq!(DASHBOARD_HTML.matches("<style").count(), 1);
        assert!(inline_block(DASHBOARD_HTML, "script").is_some_and(|b| b.contains("loadData")));
        assert!(inline_block(DASHBOARD_HTML, "style").is_some_and(|b| b.contains(".card")));
    }

    #[test]
    fn dashboard_html_has_no_inline_event_handlers() {
        // With the hash-based CSP, an `onclick=` or a `style=` would need
        // 'unsafe-hashes'. This test prevents them from coming back through
        // the back door.
        let html = DASHBOARD_HTML;
        for attr in ["onclick=\"", "onchange=\"", "oninput=\"", "onsubmit=\"", "style=\""] {
            assert!(!html.contains(attr), "inline attribute {attr} breaks the CSP");
        }
        assert!(
            !html.contains("http-equiv=\"Content-Security-Policy\""),
            "the CSP is emitted by the header; a copy in <meta> desynchronizes from the hash"
        );

        // Review v6.1 P1: the dashboard must build the same wire v2 as the
        // CLI. A local path can never reappear in the request.
        assert!(html.contains(r#"<input type="file" id="pack-file""#));
        assert!(!html.contains("pack-path"));
        let install_pack = html
            .split_once("async function installPack()")
            .and_then(|(_, rest)| rest.split_once("async function rollbackPack()"))
            .map(|(body, _)| body)
            .expect("installPack must still be inspectable by the contract test");
        assert!(
            !install_pack.contains("path"),
            "installPack cannot transport a local path again: {install_pack}"
        );
        assert!(html.contains("await file.arrayBuffer()"));
        assert!(html.contains("new TextDecoder('utf-8', { fatal: true })"));
        assert!(html.contains(&format!(
            "const PACK_WIRE_VERSION = {};",
            cerberus_packs::wire::PACK_WIRE_VERSION
        )));
        assert!(html.contains(&format!(
            "const MAX_PACK_BYTES = {};",
            cerberus_packs::wire::MAX_PACK_BYTES
        )));
        assert_eq!(install_pack.matches("const request =").count(), 1);
        assert!(!install_pack.contains("origin_name"));
        assert!(install_pack.contains("const request = { wire_version: PACK_WIRE_VERSION, pack };"));
        assert!(install_pack.contains("sendJson('POST', '/api/packs/install', request)"));

        let representative = serde_json::json!({
            "wire_version": cerberus_packs::wire::PACK_WIRE_VERSION,
            "pack": serde_json::json!({
                "pack_json": "{}",
                "signature_hex": "aa",
                "signer_public_key_hex": "bb"
            })
            .to_string()
        })
        .to_string();
        PackInstallRequest::parse_body(representative.as_bytes())
            .expect("the exact form produced by the dashboard must be accepted by parse_body");
    }

    #[test]
    fn dashboard_csp_has_no_unsafe_inline_and_hashes_the_served_blocks() {
        let csp = build_dashboard_csp(DASHBOARD_HTML);
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        assert!(!csp.contains("unsafe-hashes"), "{csp}");
        // `frame-ancestors` is the reason to emit it via header: a <meta> ignores it.
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        assert!(csp.contains("object-src 'none'"), "{csp}");
        assert!(csp.contains("base-uri 'none'"), "{csp}");

        // The hash corresponds EXACTLY to the block that is served.
        let script = inline_block(DASHBOARD_HTML, "script").unwrap();
        let expected = format!("'sha256-{}'", csp_hash::base64(&csp_hash::sha256(script.as_bytes())));
        assert!(csp.contains(&format!("script-src {expected}")), "{csp}");
        let style = inline_block(DASHBOARD_HTML, "style").unwrap();
        let expected = format!("'sha256-{}'", csp_hash::base64(&csp_hash::sha256(style.as_bytes())));
        assert!(csp.contains(&format!("style-src {expected}")), "{csp}");
        // Changing a comma of the block changes the hash: it cannot go stale.
        let tampered = build_dashboard_csp("<style>a{}</style><script>var x=2;</script>");
        assert_ne!(tampered, csp);
    }

    #[test]
    fn dashboard_response_carries_the_csp_header() {
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default())));
        let resp = handle_dashboard(&ctx).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let csp = resp
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .expect("CSP header must be present");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert_eq!(
            resp.headers().get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
    }
}
