//! Reverse proxy core — escanea y redacta requests LLM antes de
//! reenviarlos al upstream (§4.1, §4.2, §4.4 del build plan).
#![allow(
    clippy::needless_borrows_for_generic_args,
    clippy::redundant_closure_for_method_calls
)]
//!
//! Fixes post-review:
//! - **TLS**: cliento conecta a upstreams `https://` vía hiper-rustls
//!   (webpki-roots). Adiós al `HttpConnector` sin TLS (P0-1).
//! - **JSON-safe redaction** on the AST, not the concatenated text (P0-2).
//! - **Body limit** defensivo (memory-exhaustion, P1-11); streaming resp.
//!   sigue fuera de MVP (documentado).
//! - **Routing provider-agnostic** por `path_prefix` explícito, con stripping
//!   del prefijo y conservación del query string (P0-6).
//! - **Hot-reload real**: la config vive en un `Arc<RwLock>` compartido entre
//!   el proxy y la Config API (P0-5).
//! - **Allowlist** consultada en la ruta de scanning; bypass auditado por
//!   header `X-Cerberus-Bypass` (P1-7); header de feedback (P1-7).
//! - Los request limpios no contaminan la métricas (P1-12).

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

/// Headers hop-by-hop que nunca se reenvían al upstream (fix P1: list extended
/// con `te`, `trailer` y `proxy-authorization`, además de la lista estándar).
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

/// Cabeceras hop-by-hop que se filtran de la RESPUESTA del upstream antes de
/// copiarlas al cliente (fix P1: incluye `te`, `trailer`, `proxy-authenticate`).
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

/// Resultado de resolver la ruta de un request.
struct UpstreamRoute {
    /// Base URL del upstream, e.g. `https://api.openai.com`.
    base: String,
    /// Path que se reenvía (sin el prefijo de ruta).
    rest_path: String,
    /// Nombre del proveedor (auditoría consistente con el destino).
    provider: String,
}

/// Destino directo fijado por el forward proxy una vez que un `CONNECT` fue
/// validado contra su allowlist exacta. Nunca se construye desde headers del
/// request TLS ya interceptado: el authority autorizado del túnel es la única
/// fuente de verdad, evitando confused-deputy/SSRF entre hosts.
#[derive(Clone, Debug)]
pub(crate) struct DirectUpstream {
    pub(crate) base: String,
    pub(crate) provider: String,
}

/// Compartido del proxy.
pub struct ProxyContext {
    /// Configuración compartida con la Config API (hot-reload).
    pub config: Arc<RwLock<ProxyConfig>>,
    /// Engine de detección compilado, intercambiable atómicamente (fix review
    /// v5: hot-reload de packs). El `RwLock` permite que un pack instalado en
    /// caliente sustituya las reglas sin reiniciar el proxy; la lectura en el
    /// hot path es muy corta (un `read()` que toma una referencia al Arc).
    pub engine: Arc<RwLock<Arc<CompiledEngine>>>,
    /// Opciones de redacción.
    pub redact_options: RedactOptions,
    /// Contexto de la API (dashboard, config, stats).
    pub api: ApiContext,
    /// Último upstream name usado para routing (provider tracking).
    pub last_upstream: Arc<std::sync::Mutex<Option<String>>>,
}

/// ¿La dirección de escucha es loopback (127.0.0.0/8 o `::1`)?
#[must_use]
const fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Validar que un arranque en interfaz NO-loopback exige un admin token fuerte
/// (review v4 #1). En loopback se permite dev-mode abierto (documentado).
///
/// # Errors
///
/// `Err` si `listen` no es loopback y el token es `None` o < 24 bytes.
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
    // Fix P0 (review v4 #1): el control plane NO puede quedar abierto en una
    // interfaz no-loopback; exigimos un admin token fuerte (≥24 bytes) ahí.
    // La validación ocurre ANTES del bind, para que el arranque falle limpio.
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

/// Tokens declarados dinámicamente en el header `Connection` (hop-by-hop).
fn connection_tokens(headers: &hyper::HeaderMap) -> Vec<String> {
    headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default()
}

/// Bufferear el body aplicando `max_body_bytes` DURANTE la lectura
/// (`http_body_util::Limited`), de modo que un body excesivo no se materialice
/// jamás en memoria (revisión 2, P1 #5).
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

/// Filtrar las cabeceras hop-by-hop de una respuesta upstream antes de
/// copiarlas al cliente: lista fija + tokens dinámicos de `Connection`.
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

/// Truncar el motivo de bypass a máximo 200 bytes sin cortar un char UTF-8
/// a mitad (el hash se hace luego sobre el trunco; el secreto jamás se guarda).
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

/// Error al leer el body de la respuesta upstream con limit aplicado.
enum RespBodyError {
    TooLarge,
    Read(String),
}

/// Bufferear la respuesta del upstream con `max_body`, distinguiendo el corte
/// por límite (`LengthLimitError`) de los errores de lectura genéricos.
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

/// Decisión resultante del fallo de redacción según la política (review v4 #5).
#[derive(Debug)]
enum RedactDecision {
    Forward(Vec<u8>),
    Reject(StatusCode, String),
}

/// Aplicar `fail_policy` a un fallo de redacción. Closed → 502 con
/// `{"error":"redact failure",...}` (el secreto crudo NUNCA se manda);
/// Open → reenviar el body ORIGINAL y marcar warn (fail-open real).
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

/// Handler principal del proxy.
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

    // Límite de body aplicado DURANTE el buffering, no después (revisión 2, P1 #5).
    let (max_body, mode, fail_policy) = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        (cfg.max_body_bytes, cfg.mode, cfg.fail_policy)
    };
    // Errores de lectura del body (fix P1): demasiado grande → 413; el resto
    // de errores de lectura → 502 (no hay body que forwardear).
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

    // Break-glass auditado: el header `X-Cerberus-Bypass` solo se honra cuando
    // el control plane está protegido Y la request trae el admin token válido
    // **vía `X-Cerberus-Admin-Token`** (fix review v4 #2). El auth por
    // `Authorization: Bearer` vale para `/api/*`, pero en el DATA PLANE
    // exigimos exclusivamente el header propio, para no arriesgar a sustituir
    // la key del proveedor (que viaja en `Authorization`) por el admin token.
    // Con token configurado y auth ausente/inválida el header se IGNORA (no
    // bloquea) y se registra un warn. Sin token configurado (dev mode) el
    // bypass queda abierto (P0).
    let bypass_reason: Option<String> = {
        let present = parts
            .headers
            .get(BYPASS_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        present.filter(|_| {
            let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
            match api::expected_admin_token(&cfg) {
                // Dev mode: sin token configurado, bypass abierto.
                None => true,
                // Token config: el bypass del data plane se honra SOLO por el
                // header `X-Cerberus-Admin-Token` (no por `Authorization`).
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

    // Decodificar y escanear, envolviendo la fase del motor en la política de
    // fallo (fix P1 #2): fail_policy=Open → si el motor no puede decodificar/
    // redactar se reenvía el body ORIGINAL intacto; Closed → 502.
    let content_type_hint = parts.headers.get("content-type").and_then(|v| v.to_str().ok());
    let decoded = decode(&body_bytes, content_type_hint);
    // Fallo de decode: content-type declara JSON pero el body no es JSON válido.
    let json_hint = content_type_hint.is_some_and(|h| h.to_ascii_lowercase().contains("json"));
    let decode_failed = json_hint && decoded.content_type != ContentType::Json;
    if decode_failed && fail_policy == FailPolicy::Closed {
        return json_status(StatusCode::BAD_GATEWAY, r#"{"error":"cannot decode"}"#);
    }
    if decode_failed {
        // fail_policy=Open: no se puede escanear un body no decodificable; se
        // reenvía intacto y se marca en el log.
        tracing::warn!("decode failed for json content-type; fail_policy=open — forwarding original body");
    }
    // Snapshot del engine para todo el request (hot-reload): se clona el Arc
    // bajo el lock breve; scan+redact usan el mismo snapshot → ningún pack
    // intercambiado a medias es visible en medio de un request.
    let engine_snap = ctx.engine.read().unwrap_or_else(|p| p.into_inner()).clone();
    let scan_result = if decode_failed {
        ScanOutput {
            findings: Vec::new(),
            action_overall: cerberus_engine::rule::Action::Allow,
        }
    } else {
        let mut s = engine_snap.scan(&decoded.text);
        // Allowlist (triage de falsos positivos) — aplicada en la ruta real (P0-5).
        apply_allowlist(ctx, &decoded.text, &mut s);
        s
    };

    let mode_result = shadow::apply_mode(&scan_result, mode);
    let has_findings = !scan_result.findings.is_empty();

    // Block (Enforce + crítico) — salvo bypass.
    let blocked = bypass_reason.is_none() && !mode_result.should_forward();
    if blocked {
        let flag = scan_result.findings.first().map_or("unknown", |f| f.flag.as_str());
        log_security_event(
            SecurityEvent::Blocked,
            &scan_result.findings,
            scan_result.action_overall,
        );
        // Registrar evento en el store.
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

    // Enforce: aplicar redacción (solo en enforce; shadow pasa intacto).
    // Si la redacción interna falla, la política de fallo decide: Open →
    // reenviar el body original (fail-open real); Closed → 502 (fix review v4
    // #5: antes el error de `apply_redaction` se tragaba en json_redact y el
    // secreto crudo pasaba aunque la JSON fallara).
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

    // Log sec event (por tipo de intervención).
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

    // Registrar evento en el store si hay hallazgos (limpios no cuentan — P1-12).
    let provider = direct_upstream
        .as_ref()
        .map_or_else(|| provider_of(path.as_str(), ctx), |direct| direct.provider.clone());
    if has_findings {
        let is_bypass = bypass_reason.is_some();
        if is_bypass {
            // Break-glass auditado (revisión 2, P1 #6): la fuga autorizada se
            // persiste como "bypass" con su motivo — no como un block falso.
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
            // El motivo NUNCA se persiste crudo (fuga de secretos, fix P1):
            // en `flags` solo va el marcador "bypass"; el motivo (trucado a
            // 200 bytes) se guarda hasheado en `hashed_values` como
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

    // Resolver upstream (con stripping del prefijo de ruta).
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
    // Reenviar headers hop-by-hop de forma correcta: omitir los fijos y además
    // los tokens declarados dinámicamente en "Connection" (revisión 2, P1 #10).
    // El admin token (`X-Cerberus-Admin-Token`) NUNCA se reenvía al upstream
    // (fix review v4 #2): es exclusivo del control plane / bypass.
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

    // Timeout de upstream (revisión 2, P1 #10): 30s por request.
    //
    // Semántica fail_policy en fallo de UPSTREAM (conexión/timeout): la
    // política Open/Closed se aplica al fallo del MOTOR (decode/scan/redact,
    // arriba). Para un upstream caído no hay forma de forwardear el request,
    // así que ambos modos rechazan pero con distinta semántica de proxy:
    // Closed → 503 (el proxy es parte de la cadena y decide rechazar);
    // Open → 502 (bad gateway: el destino no respondió).
    let resp = match tokio::time::timeout(std::time::Duration::from_secs(30), client.request(up_req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            // fail_policy Closed → 503 (fallo del proxy); Open → 502 y pasamos
            // el error visible (revisión 2, P1 #7).
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
    // Límite en la respuesta también (revisión 2, P1 #5). Si el upstream
    // supera `max_body_bytes`, devolvemos 502 JSON en lugar de propagar el
    // error y cortar la conexión (fix P1 #4).
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
    // Filtrar cabeceras hop-by-hop de la respuesta (fix P1 #6): tokens de
    // `Connection` + lista fija (te, trailer, proxy-authenticate, ...).
    *response.headers_mut() = filter_response_headers(&resp_parts.headers);
    add_feedback_headers(&mut response, &scan_result, bypass_reason.as_deref());
    Ok(response)
}

/// Filtrar findings cuyo valor está en la allowlist (elimina falsos positivos).
///
/// La allowlist se lee de la config compartida (`policy.allowlist`, fix review
/// v6.1): es la MISMA que persiste el control plane, así que un triage de FP
/// desde el dashboard surte efecto en el siguiente request sin reiniciar y
/// sobrevive al reinicio.
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
    // Recalcular la acción global con los findings que quedaron.
    scan.action_overall = scan
        .findings
        .iter()
        .map(|f| f.action)
        .max()
        .unwrap_or(cerberus_engine::rule::Action::Allow);
}

/// Proveedor del path (para tracking de stats). Consistente con el destino
/// de reenvío (revisión 2, P1 #10): usa el MISMO orden que `resolve_route`.
fn provider_of(path: &str, ctx: &ProxyContext) -> String {
    resolve_route(ctx, path).provider
}

/// Ruta de reenvío determinista. Prioridad (longest-match primero):
/// - `path_prefix` explícito
/// - tabla built-in
/// - upstream `default`
///
/// El prefijo se quita antes del reenvío y el query string se conserva.
fn resolve_route(ctx: &ProxyContext, path: &str) -> UpstreamRoute {
    // Snapshot determinista de los upstreams (guarda drop del RwLock temprano).
    let upstreams = {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        cfg.upstreams.clone()
    };

    // 1) path_prefix explícito, longest-match primero (fix P1 #3): se ordena por
    //    la longitud del PREFIX, no por la del nombre, con desempate
    //    determinista por nombre.
    let mut explicit: Vec<(&String, &crate::config::UpstreamConfig)> = upstreams.iter().collect();
    explicit.sort_by(|(a_name, a_up), (b_name, b_up)| {
        let a_len = a_up.path_prefix.as_deref().map_or(0, str::len);
        let b_len = b_up.path_prefix.as_deref().map_or(0, str::len);
        b_len.cmp(&a_len).then_with(|| a_name.cmp(b_name))
    });
    for (name, up) in explicit {
        if let Some(prefix) = &up.path_prefix {
            if let Some(rest) = path.strip_prefix(prefix.as_str()) {
                // Normalizar la barra inicial del resto: un prefijo con slash
                // final (`/openai/`) deja `rest` sin `/` — siempre re-añadimos
                // la suya para que el URI de reenvío sea correcto (P1 #7).
                let rest = rest.trim_start_matches('/');
                return UpstreamRoute {
                    base: up.url.clone(),
                    rest_path: format!("/{rest}"),
                    provider: name.clone(),
                };
            }
        }
    }

    // 2) built-in prefixes hacia upstreams con el nombre correspondiente.
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

    // 3) fallback determinista: upstream llamado "default".
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

/// Adjuntar headers de feedback/bypass a la respuesta.
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
        // El proxy conecta a upstreams HTTPS vía rustls (webpki-roots).
        // Este test comprueba que el conector TLS construye sin errores.
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
        // P1 #3: ordenar por longitud del PREFIX (no del nombre). "short"
        // tiene prefijo `/v1` y "longer" `/v1/admin`; con nombres cortos un
        // sort por longitud del nombre rompía el longest-match.
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
        // P1 #6: la respuesta debe filtrar los tokens de `Connection` y la
        // lista hop-by-hop fija (connection, te, trailer, etc).
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
        let short = "corto".to_string();
        assert_eq!(truncate_bypass_reason(&short), "corto");
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
        // Review v4 #1: en interfaz no-loopback el control plane no puede
        // quedar abierto. Sin token o con token < 24 bytes → Err al desplegar.
        let non_loop: SocketAddr = "0.0.0.0:0".parse().unwrap();

        // Sin token → Err.
        let ctx = Arc::new(test_ctx_with_admin_token(None));
        let err = spawn_proxy(non_loop, ctx).await.unwrap_err().to_string();
        assert!(err.contains("admin token"), "got: {err}");

        // Token corto (14 chars, como "change-me") → Err en no-loopback.
        let ctx = Arc::new(test_ctx_with_admin_token(Some("change-me-123")));
        let err = spawn_proxy(non_loop, ctx).await.unwrap_err().to_string();
        assert!(err.contains("too short"), "got: {err}");

        // Token fuerte (≥24) → Ok.
        let ctx = Arc::new(test_ctx_with_admin_token(Some("012345678901234567890123456789")));
        let (_addr, _h) = spawn_proxy(non_loop, ctx).await.expect("strong token binds on 0.0.0.0");

        // Loopback sin token (dev mode abierto, documentado) → Ok.
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
        // Review v4 #5: si la redacción falla y fail_policy=Closed, la
        // respuesta es 502 JSON y el secreto crudo jamás va en el cuerpo.
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
        // Review v4 #5: fail_policy=Open → se reenvía el body ORIGINAL intacto
        // (marcado warn) y un redact OK se reenvía tal cual.
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
