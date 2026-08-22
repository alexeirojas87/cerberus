//! Config API — HTTP handlers for reading/writing proxy configuration
//! and querying audit events / stats (§4.6 del build plan).
//!
//! Rutas:
//! - `GET  /api/config` — obtener config actual (`admin_token` redactado,
//!   review v6 F6: nunca se filtra el valor; se expone `admin_token_configured`)
//! - `PUT  /api/config` — actualizar config (hot-reload **real**; review v6 F6:
//!   persiste a YAML si `ApiContext.config_path` está fijado, y reporta
//!   `requires_restart:true` cuando `listen` cambió — el rebind NO es en vivo)
//! - `GET  /api/events` — eventos recientes (con filtros opcionales)
//! - `GET  /api/stats` — estadísticas agregadas
//! - `POST /api/allowlist` — añadir a allowlist (triage de FP)
//! - `GET  /api/upstreams` — listar upstreams/providers `{name,url,auth_header}`
//! - `POST /api/upstreams` — alta de un upstream `{name,url,auth_header?}`
//! - `DELETE /api/upstreams/{name}` — baja de un provider (no el último)
//!   (CRUD de upstreams: review v6 F6, paridad UI/API. Cada mutación persiste
//!   a YAML con la MISMA política que `PUT /api/config`.)
//! - `GET  /api/policy` — overlay de política: categorías, reglas propias,
//!   allowlist y acciones válidas (F6 «pantallas-config», §4.6 del plan)
//! - `PUT  /api/policy` — patch del overlay (`null` en un valor lo borra)
//! - `GET  /api/allowlist` — allowlist actual (triage de FP en un click)
//! - `DELETE /api/allowlist` — quitar una entrada (`{"value":"…"}`)
//!
//! ## Review v6.1 — config como DTO y persistencia transaccional
//!
//! `GET`/`PUT /api/config` NO usan [`ProxyConfig`] como tipo de la API:
//! - [`ConfigView`] es la respuesta del `GET`. Por construcción no tiene campo
//!   `admin_token`, así que el secreto no puede filtrarse por olvido; expone
//!   el booleano derivado `admin_token_configured`.
//! - [`ConfigPatch`] es el body del `PUT`. Los campos ausentes se PRESERVAN
//!   (semántica de patch): omitir `admin_token` deja el token vivo intacto y
//!   `admin_token_configured` se acepta pero se IGNORA (sólo lectura).
//! - Antes de tocar memoria o disco se revalida la exposición del control
//!   plane (`listen` no-loopback ⇒ token ≥ 24 bytes), la misma regla que
//!   aplica `proxy::check_listen_security` al bindear.
//! - La persistencia es **transaccional desde la perspectiva en memoria**: se
//!   calcula el candidato, se valida, se escribe a YAML y SÓLO si todo eso
//!   sale bien se publica en memoria. Si algo falla, la config viva queda
//!   exactamente como estaba.
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

/// Comando de operación de rule packs. El control plane lo envía al worker
/// del daemon (fix review v5: hot-reload real y rollback durable).
///
/// `reply` es un oneshot que transporta el resultado de vuelta al caller.
#[derive(Debug)]
pub enum PackCommand {
    /// Instalar el contenido firmado recibido por el control plane; el worker
    /// nunca interpreta rutas del filesystem del cliente.
    Install {
        /// Request wire v2 ya validada y acotada por tamaño.
        request: PackInstallRequest,
        /// oneshot que devuelve el resultado al caller del control plane.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Revertir a la última activación persistida (rollback durable).
    Rollback {
        /// oneshot que devuelve el resultado al caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Listar packs con estado.
    List {
        /// oneshot que devuelve el resultado al caller.
        reply: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
}

/// Header canónico para el admin token. Aceptado SIEMPRE en `/api/*` y en el
/// bypass del data plane (review v4 #2). Nunca se reenvía al upstream.
pub const ADMIN_TOKEN_HEADER: &str = "x-cerberus-admin-token";

/// Longitud mínima (bytes) exigida al admin token en interfaces no-loopback
/// (review v4 #1).
///
/// Un token por debajo de este umbral deja el control plane abierto; en
/// loopback se permite dev-mode sin token (documentado).
pub const ADMIN_TOKEN_MIN_BYTES: usize = 24;

/// Límite máximo de body para las rutas del control plane `/api/*` (1 MiB,
/// review v4 #4). El límite del data plane (`max_body_bytes`) aplica por
/// separado y no se toca.
const CONTROL_PLANE_MAX_BYTES: usize = MAX_PACK_BODY_BYTES;

/// Contexto compartido para la API.
#[derive(Clone)]
pub struct ApiContext {
    /// Configuración actual del proxy (compartida con el hot-path).
    pub config: Arc<RwLock<ProxyConfig>>,
    /// Lista de eventos de auditoría en memoria.
    pub events: Arc<Mutex<Vec<AuditEvent>>>,
    /// Store `SQLite` para persistencia de eventos (opcional).
    pub store: Option<Arc<AuditStore>>,
    /// Canal al worker de rule packs del daemon (F7). Cuando está presente,
    /// se activan las rutas `/api/packs/*` (install/rollback/list) con
    /// hot-reload real del engine activo (fix review v5).
    pub pack_worker: Option<tokio::sync::mpsc::Sender<PackCommand>>,
    /// Ruta del archivo YAML de config (review v6 F6). Cuando es `Some`, toda
    /// mutación de configuración (PUT /api/config y CRUD de upstreams) hace un
    /// `serde_yaml::to_string` + escritura atómica (temp + rename) en esa ruta.
    /// `None` (tests/dev) = no persiste (no falla).
    pub config_path: Option<std::path::PathBuf>,

    /// Mando del engine vivo del dataplane (fix review v6.1). Cuando es
    /// `Some`, un cambio de política (categorías, reglas custom, overrides) se
    /// **compila y publica** en el engine que lee el hot-path: el dataplane
    /// cambia de reglas sin reiniciar y sin perder las reglas de los packs.
    /// `None` (tests/dev) = la política se valida y persiste, pero no hay
    /// engine que actualizar.
    pub engine: Option<crate::detection_policy::EngineControl>,
}

impl ApiContext {
    /// Crear un nuevo contexto API sin store.
    #[must_use]
    pub fn new(config: Arc<RwLock<ProxyConfig>>) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            store: None,
            pack_worker: None,
            config_path: None,
            engine: None,
        }
    }

    /// Crear un contexto API con store.
    #[must_use]
    pub fn with_store(config: Arc<RwLock<ProxyConfig>>, store: Arc<AuditStore>) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            store: Some(store),
            pack_worker: None,
            config_path: None,
            engine: None,
        }
    }

    /// Crear un contexto API con store opcional.
    #[must_use]
    pub fn with_store_opt(config: Arc<RwLock<ProxyConfig>>, store: Option<Arc<AuditStore>>) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            store,
            pack_worker: None,
            config_path: None,
            engine: None,
        }
    }

    /// Conectar el worker de rule packs del daemon (F7 hot-reload).
    #[must_use]
    pub fn with_pack_worker(mut self, pack_worker: tokio::sync::mpsc::Sender<PackCommand>) -> Self {
        self.pack_worker = Some(pack_worker);
        self
    }

    /// Fijar la ruta YAML donde persistir la config (review v6 F6).
    #[must_use]
    pub fn with_config_path(mut self, config_path: std::path::PathBuf) -> Self {
        self.config_path = Some(config_path);
        self
    }

    /// Conectar el mando del engine vivo (fix review v6.1): sin esto la
    /// política se persiste pero el dataplane no se actualiza en caliente.
    #[must_use]
    pub fn with_engine(mut self, engine: crate::detection_policy::EngineControl) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Crear un contexto API sin store (fallback).
    #[must_use]
    pub fn without_store(config: Arc<RwLock<ProxyConfig>>) -> Self {
        Self::new(config)
    }
}

/// Determinar si una ruta pertenece a la API.
#[must_use]
pub fn is_api_path(path: &str) -> bool {
    path.starts_with("/api/")
}

/// Comparación constante en tiempo (xor acumulado + suma de bucle) para evitar
/// timing attacks al validar el admin token. No usa short-circuit por posición.
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

/// Admin token esperado por el control plane: `Some` no vacío significa que
/// la autenticación está activa (`None` o vacío = dev mode, API abierta).
#[must_use]
pub(crate) fn expected_admin_token(cfg: &ProxyConfig) -> Option<&str> {
    cfg.admin_token.as_deref().filter(|t| !t.is_empty())
}

/// ¿La request trae un admin token válido? Acepta `Authorization: Bearer <t>`
/// o `X-Cerberus-Admin-Token: <t>` (review v4 #2). Comparación constante en
/// tiempo para ambos headers.
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

/// ¿La request autentica vía `X-Cerberus-Admin-Token`? (fix review v4 #2: el
/// bypass del data plane SOLO se honra por este header, nunca por Bearer).
#[must_use]
pub(crate) fn admin_token_header_is_present(headers: &hyper::HeaderMap, expected: &str) -> bool {
    admin_token_header(headers).is_some_and(|t| constant_time_eq(t, expected))
}

/// Valor (trimmeado) del header `X-Cerberus-Admin-Token`, si existe.
fn admin_token_header(headers: &hyper::HeaderMap) -> Option<&str> {
    headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

/// ¿Esta ruta expone datos y por tanto exige auth? El dashboard es HTML
/// estático PÚBLICO sin datos → nunca exige auth (review v5 F6).
#[must_use]
fn route_serves_data(path: &str) -> bool {
    path != "/api/dashboard"
}

/// Gate de autenticación del control plane (review v5 F6).
///
/// `None` = permitir (token válido, ruta exenta, o dev mode sin token).
/// `Some(resp)` = rechazar con esa respuesta (401 cuando falta el token).
#[must_use]
fn auth_gate(cfg: &ProxyConfig, path: &str, headers: &hyper::HeaderMap) -> Option<Response<Full<Bytes>>> {
    if let Some(expected) = expected_admin_token(cfg) {
        if route_serves_data(path) && !authorized(headers, expected) {
            return Some(json_response(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#));
        }
    }
    None
}

/// Extraer el query param `provider` (review v5 F6). `None` = sin filtro.
#[must_use]
fn query_provider(query: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("provider=") {
            if !value.is_empty() {
                found = Some(value.to_string());
            }
        }
    }
    found
}

/// Filtrar eventos por proveedor cuando el query param está presente.
#[must_use]
fn filter_by_provider(events: &[AuditEvent], provider: Option<String>) -> Vec<AuditEvent> {
    provider.map_or_else(
        || events.to_vec(),
        |p| events.iter().filter(|e| e.provider == p).cloned().collect(),
    )
}

/// Manejar una request de API.
///
/// # Errors
///
/// Devuelve error si el handler falla.
pub async fn handle_api_request(
    req: Request<hyper::body::Incoming>,
    ctx: &ApiContext,
) -> Result<Response<Full<Bytes>>, String> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let method = parts.method.clone();

    // -- Control plane auth (P0, review v5 F6) ------------------------------
    // Si hay admin token configurado, todas las rutas de DATOS `/api/*`
    // exigen autenticación; el dashboard (HTML público sin datos) está exento.
    // Sin token configurado (dev mode / tests) el control plane queda abierto.
    {
        let cfg = ctx.config.read().unwrap_or_else(|p| p.into_inner());
        if let Some(denied) = auth_gate(&cfg, &path, &parts.headers) {
            return Ok(denied);
        }
    }

    // Query param `provider` para filtros por proveedor (review v5 F6).
    let query = parts.uri.query().map_or_else(String::new, |q| q.to_string());
    let provider = query_provider(&query);

    // CRUD de upstreams (review v6 F6): DELETE lleva nombre en el path. Se
    // resuelve ANTES del match estático porque `/api/upstreams/{name}` no es
    // una ruta fija. Autenticado por el gate del control plane (más arriba).
    if let Some(name) = upstream_name_from_path(&path) {
        if method == "DELETE" {
            return handle_delete_upstream(ctx, name).await;
        }
        return Ok(not_found());
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/api/config") => handle_get_config(ctx).await,
        ("PUT", "/api/config") => handle_put_config(ctx, body).await,
        ("GET", "/api/events") => handle_get_events(ctx, provider).await,
        ("GET", "/api/stats") => handle_get_stats(ctx, provider).await,
        ("POST", "/api/allowlist") => handle_post_allowlist(ctx, body).await,
        ("GET", "/api/allowlist") => handle_get_allowlist(ctx).await,
        ("DELETE", "/api/allowlist") => handle_delete_allowlist(ctx, body).await,
        ("GET", "/api/policy") => handle_get_policy(ctx).await,
        ("PUT", "/api/policy") => handle_put_policy(ctx, body).await,
        ("GET", "/api/upstreams") => handle_get_upstreams(ctx).await,
        ("POST", "/api/upstreams") => handle_post_upstreams(ctx, body).await,
        ("GET", "/api/packs") => handle_pack_mode(ctx, PackKind::List).await,
        ("POST", "/api/packs/install") => handle_pack_install(ctx, body).await,
        ("POST", "/api/packs/rollback") => handle_pack_mode(ctx, PackKind::Rollback).await,
        (_, "/api/dashboard") => handle_dashboard(ctx),
        _ => Ok(not_found()),
    }
}

/// Tipo de comando de pack al worker del daemon (hot-reload real, F7 v5).
enum PackKind {
    List,
    Rollback,
}

/// Enviar un comando de pack (sin body) al worker y esperar su reply.
async fn handle_pack_mode(ctx: &ApiContext, kind: PackKind) -> Result<Response<Full<Bytes>>, String> {
    let Some(worker) = ctx.pack_worker.as_ref() else {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"pack worker not connected"}"#,
        ));
    };
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let cmd = match kind {
        PackKind::List => PackCommand::List { reply: reply_tx },
        PackKind::Rollback => PackCommand::Rollback { reply: reply_tx },
    };
    if worker.send(cmd).await.is_err() {
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

/// Vista de sólo lectura de la config para `GET /api/config` (review v6.1).
///
/// DTO **separado** de [`ProxyConfig`]: por construcción NO tiene campo
/// `admin_token`, así que ningún campo nuevo en `ProxyConfig` puede filtrar el
/// secreto por esta ruta (antes se redactaba a mano sobre el JSON serializado,
/// y ese borrado había que recordarlo). `admin_token_configured` es un booleano
/// **derivado y de sólo lectura**: el `PUT` lo ignora (ver [`ConfigPatch`]).
#[derive(serde::Serialize)]
struct ConfigView<'a> {
    listen: &'a str,
    mode: crate::config::OperationMode,
    fail_policy: crate::config::FailPolicy,
    upstreams: &'a std::collections::HashMap<String, UpstreamConfig>,
    log_level: &'a str,
    health_path: &'a str,
    max_body_bytes: Option<usize>,
    /// Derivado: ¿el control plane exige token? NUNCA el valor del token.
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

/// Campo de patch con los TRES estados que puede tener una clave opcional en
/// el body JSON. El tipo documenta la semántica que un `Option<Option<T>>` deja
/// implícita, y es lo que distingue "no me toques el token" de "bórralo".
#[derive(Default)]
enum PatchField<T> {
    /// La clave no venía en el body → preservar el valor vivo.
    #[default]
    Absent,
    /// La clave venía como `null` → borrar el valor.
    Clear,
    /// La clave venía con valor → reemplazar.
    Set(T),
}

impl<T> PatchField<T> {
    /// Resolver el campo contra el valor vivo (`live`).
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

/// Body de `PUT /api/config` (review v6.1). DTO **separado** de
/// [`ProxyConfig`] con semántica de patch: **todo campo ausente se preserva**.
///
/// - `admin_token` ausente ⇒ se preserva el token vivo (nunca hay que
///   reenviarlo, y el `GET` no lo revela). `null` explícito ⇒ se borra.
/// - `admin_token_configured` se acepta (para que un ciclo
///   GET→modificar→PUT del cliente no falle) pero es de SÓLO LECTURA: se
///   ignora por completo, no puede activar ni desactivar la autenticación.
/// - Cualquier otra clave se rechaza (`deny_unknown_fields`): un typo como
///   `admin_tokens` falla en voz alta en vez de silenciarse.
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
    /// Campo de SÓLO LECTURA. Se declara para aceptarlo en el body y NO se lee
    /// nunca: el estado de la autenticación se deriva de `admin_token`.
    #[allow(dead_code)]
    #[serde(default)]
    admin_token_configured: Option<bool>,
}

impl ConfigPatch {
    /// Aplicar el patch sobre `base` y devolver la config CANDIDATA (aún no
    /// validada ni publicada). Campos ausentes ⇒ valor de `base`.
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
            // La política de detección NO se toca por esta ruta: tiene su
            // propia puerta (`PUT /api/policy`), que valida las reglas y
            // recompila el engine. Aquí se preserva siempre.
            policy: base.policy.clone(),
        }
    }
}

/// ¿La cadena `listen` apunta a una interfaz loopback?
///
/// Espeja `proxy::check_listen_security` (que opera sobre el `SocketAddr` del
/// bind) pero sobre el texto que llega por la API. **Por seguridad el default
/// es "no loopback"**: si la cadena no se resuelve a una IP loopback literal
/// (ni a `localhost`), se trata como pública y se exige token fuerte.
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

/// Revalidar que la config candidata no deja el control plane expuesto
/// (review v6.1): si `listen` no es loopback, exige un admin token de al menos
/// [`ADMIN_TOKEN_MIN_BYTES`].
///
/// Es la MISMA regla que `proxy::check_listen_security` aplica al bindear,
/// pero comprobada **antes** de mutar memoria o escribir el YAML: así una
/// config que el daemon rechazaría al arrancar tampoco se puede persistir
/// (evitábamos el bind abierto, no el "queda guardado y no arranca").
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

/// Respuesta 400 con el error de validación de la config.
fn invalid_config_response(err: &str) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::BAD_REQUEST,
        &format!(r#"{{"status":"error","error":{err:?}}}"#),
    )
}

/// Respuesta 500 cuando la persistencia falla. La config viva NO se tocó.
fn persist_failed_response(err: &str) -> Response<Full<Bytes>> {
    json_response_close(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!(r#"{{"status":"error","error":{err:?},"note":"nothing was applied: the live config is unchanged"}}"#),
    )
}

async fn handle_get_config(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    // Review v6.1: se serializa el DTO, no `ProxyConfig`. El `admin_token` no
    // existe en `ConfigView`, así que no hay nada que redactar ni que olvidar.
    let json = serde_json::to_string(&ConfigView::from_config(&config)).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

/// Persistir la config compartida a YAML en `ctx.config_path` (review v6 F6).
///
/// Escritura atómica (temp + rename) para no corromper el archivo ante un
/// corte. `None` (tests/dev) → no-op sin error. Si falla la escritura, se
/// devuelve `Err`; el caller decide si revierte el cambio en memoria.
fn persist_config(ctx: &ApiContext, config: &ProxyConfig) -> Result<(), String> {
    let Some(path) = ctx.config_path.as_ref() else {
        return Ok(());
    };
    let yaml = serde_yaml::to_string(config).map_err(|e| format!("config yaml serialize error: {e}"))?;
    // Temp en el MISMO directorio para que el rename sea atómico.
    let tmp = std::path::PathBuf::from(format!("{}.tmp", path.to_string_lossy()));
    std::fs::write(&tmp, yaml).map_err(|e| format!("config write failed: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("config commit failed: {e}"))?;
    Ok(())
}

/// Cuerpo del control plane limitado a 1 MiB (review v4 #4). Distingue el
/// corte por límite (413) de los errores de lectura genéricos.
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

    // El lock de ESCRITURA se toma antes de calcular el candidato y no se
    // suelta hasta publicar (o abortar): nadie se cuela en medio, y el orden
    // es validar → persistir → publicar. Transaccional desde la perspectiva en
    // memoria: si la validación o el disco fallan, la config viva no cambió.
    let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
    let candidate = patch.apply(&live);

    // Revalidación de exposición ANTES de persistir/mutar (review v6.1).
    if let Err(e) = validate_control_plane_exposure(&candidate) {
        return Ok(invalid_config_response(&e));
    }
    // Persistencia primero: si el YAML no se puede escribir, no publicamos
    // nada (antes se aplicaba en memoria y quedaba divergiendo del disco).
    if let Err(e) = persist_config(ctx, &candidate) {
        return Ok(persist_failed_response(&e));
    }

    // Review v6 F6: si `listen` cambió, el socket VIVO no puede rebindearse;
    // devolvemos `requires_restart:true` para que la UI advierta que el nuevo
    // listen aplica en el SIGUIENTE arranque (el `listen` ya queda persistido).
    let requires_restart = live.listen != candidate.listen;
    // Publicar: escribe la MISMA config que lee el hot path (hot-reload, P0-5).
    *live = candidate;
    drop(live);

    let message = if requires_restart {
        r#"{"status":"ok","requires_restart":true,"message":"config updated (listen change applies on next restart)"}"#
    } else {
        r#"{"status":"ok","requires_restart":false,"message":"config updated"}"#
    };
    Ok(json_response(StatusCode::OK, message))
}

/// Snapshots de eventos: memoria (live) + store `SQLite` (persistencia).
/// La vista tras reiniciar recupera el histórico (revisión 2, P1 #9).
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

async fn handle_get_events(ctx: &ApiContext, provider: Option<String>) -> Result<Response<Full<Bytes>>, String> {
    let events = events_snapshot(ctx, 10_000).await;
    let events = filter_by_provider(&events, provider);
    let json = serde_json::to_string(&events).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

async fn handle_get_stats(ctx: &ApiContext, provider: Option<String>) -> Result<Response<Full<Bytes>>, String> {
    let events = events_snapshot(ctx, 10_000).await;
    let events = filter_by_provider(&events, provider);
    let s = stats::summary(&events);
    let json = serde_json::to_string(&s).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

/// Extraer el nombre del upstream de un path `/api/upstreams/{name}` (review
/// v6 F6). `None` si no hay nombre (p.ej. el path exacto `/api/upstreams`).
#[must_use]
fn upstream_name_from_path(path: &str) -> Option<&str> {
    path.strip_prefix("/api/upstreams/").filter(|n| !n.is_empty())
}

/// Body de alta de un upstream via `POST /api/upstreams` (review v6 F6).
#[derive(Deserialize)]
struct UpstreamPayload {
    name: String,
    url: String,
    auth_header: Option<String>,
}

async fn handle_get_upstreams(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    let items: Vec<String> = config
        .upstreams
        .iter()
        .map(|(name, up)| {
            format!(
                r#"{{"name":{name:?},"url":{url:?},"auth_header":{auth:?}}}"#,
                url = up.url,
                auth = up.auth_header
            )
        })
        .collect();
    let joined = items.join(",");
    Ok(json_response(StatusCode::OK, format!("[{joined}]")))
}

/// Alta/actualización de un upstream. Mutación en caliente + persistencia YAML
/// (misma política que `PUT /api/config`, review v6 F6).
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
    let payload: UpstreamPayload =
        serde_json::from_slice(&body_bytes).map_err(|e| format!("invalid upstream payload: {e}"))?;
    if payload.name.is_empty() {
        return Ok(json_response(StatusCode::BAD_REQUEST, r#"{"error":"missing 'name'"}"#));
    }
    if payload.url.is_empty() {
        return Ok(json_response(StatusCode::BAD_REQUEST, r#"{"error":"missing 'url'"}"#));
    }

    // Misma transacción que PUT /api/config (review v6.1): candidato →
    // validar → persistir → publicar, con el lock de escritura tomado.
    let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
    let mut candidate = live.clone();
    candidate.upstreams.insert(
        payload.name.clone(),
        UpstreamConfig {
            url: payload.url.clone(),
            path_prefix: None,
            auth_header: payload.auth_header.unwrap_or_else(|| "authorization".to_string()),
        },
    );
    if let Err(e) = validate_control_plane_exposure(&candidate) {
        return Ok(invalid_config_response(&e));
    }
    if let Err(e) = persist_config(ctx, &candidate) {
        return Ok(persist_failed_response(&e));
    }
    *live = candidate;
    drop(live);

    Ok(json_response(
        StatusCode::OK,
        format!(
            r#"{{"status":"ok","name":{name:?},"message":"upstream saved"}}"#,
            name = payload.name
        ),
    ))
}

/// Baja de un provider por nombre. Deniega quitar el ÚLTIMO upstream (la config
/// exige al menos uno para rutear). Persiste tras quitar.
async fn handle_delete_upstream(ctx: &ApiContext, name: &str) -> Result<Response<Full<Bytes>>, String> {
    // Misma transacción que PUT /api/config (review v6.1). Los guards se
    // evalúan sobre el candidato; la config viva sólo cambia al final.
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
    *live = candidate;
    drop(live);

    Ok(json_response(
        StatusCode::OK,
        &format!(r#"{{"status":"ok","deleted":{name:?}}}"#),
    ))
}

// ─── F6: política de detección persistente (fix review v6.1) ──────────────
//
// Antes esta sección era un overlay en memoria (`PolicyOverlay`) que devolvía
// `"persisted": false` y NO llegaba al motor: al reiniciar se perdía y la
// detección no cambiaba. Ahora la política vive en `ProxyConfig.policy` (y por
// tanto en el YAML) y cada mutación sigue la MISMA transacción que
// `PUT /api/config`:
//
//     candidato = política vigente + patch
//       → validar (400)
//       → compilar el engine efectivo (400 si un patrón no compila)
//       → persistir YAML (500)
//       → publicar en memoria + hot-swap del engine
//
// Si algo falla antes del último paso, ni el YAML ni la config viva ni el
// engine del dataplane cambian.

use crate::detection_policy::{
    parse_action, parse_category, DetectionPolicy, EngineControl, POLICY_ACTIONS, POLICY_CATEGORIES,
};

/// Documento de política que devuelven `GET/PUT /api/policy`.
///
/// Nombres del wire estables respecto a v6.1 (`rules` = overrides por flag) y
/// `persisted: true`: lo que se ve aquí está en el YAML.
fn policy_document(policy: &DetectionPolicy, engine_rules: Option<usize>) -> serde_json::Value {
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
    })
}

/// Body de `PUT /api/policy`.
///
/// - `categories` / `rules`: patch por clave (`null` BORRA la entrada, clave
///   ausente la deja intacta) — semántica de v6.1, sin cambios para la UI.
/// - `custom_rules` / `allowlist`: **reemplazo de la lista completa** (`[]`
///   la vacía). Son colecciones ordenadas sin clave natural en el wire; un
///   patch por índice sería ambiguo. El add/remove de una sola entrada de
///   allowlist sigue en `POST`/`DELETE /api/allowlist`.
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
    /// Aplicar el patch sobre `base` y devolver la política CANDIDATA (aún no
    /// validada ni publicada). Valida **antes de mutar** cada categoría y cada
    /// acción, así que un patch con una entrada inválida no deja la política a
    /// medias.
    fn apply(self, base: &DetectionPolicy) -> Result<DetectionPolicy, String> {
        // Fase 1: parsear TODO el patch (cualquier error aborta sin mutar).
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

        // Fase 2: construir el candidato sobre una copia.
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

/// Aplicar una política candidata de forma transaccional: validar → compilar
/// el engine → persistir el YAML → publicar (config viva + hot-swap).
///
/// Devuelve el número de reglas del engine publicado (`None` si no hay engine
/// conectado), o la respuesta de error ya formada.
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

    // Compilar ANTES de escribir: un patrón que no compila es 400, no un
    // YAML persistido que después tumbaría el arranque.
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

/// Política vigente (categorías, overrides, reglas custom y allowlist).
async fn handle_get_policy(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    let json = serialize_policy_document(&config.policy, ctx.engine.as_ref().map(EngineControl::live_rules));
    Ok(json_response(StatusCode::OK, json))
}

/// Patch de la política. Persiste en el YAML y publica el engine efectivo en
/// el dataplane sin reiniciar (ver [`commit_policy`]).
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

/// Núcleo de `PUT /api/policy` sobre los bytes ya recogidos (separado del
/// handler para que la transacción sea testeable sin socket).
fn apply_policy_patch(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    let patch: PolicyPatch = match serde_json::from_slice(body_bytes) {
        Ok(p) => p,
        Err(e) => return invalid_config_response(&format!("invalid policy patch: {e}")),
    };

    // El lock de ESCRITURA se mantiene desde el cálculo del candidato hasta la
    // publicación: nadie se cuela entre validar, persistir y publicar.
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
    json_response(StatusCode::OK, serialize_policy_document(&doc, engine_rules))
}

/// Serializar el documento de política; si `serde_json` fallara (no puede con
/// este documento), se devuelve un JSON mínimo en vez de un 500 opaco.
fn serialize_policy_document(policy: &DetectionPolicy, engine_rules: Option<usize>) -> String {
    serde_json::to_string(&policy_document(policy, engine_rules))
        .unwrap_or_else(|_| r#"{"error":"policy serialize failed"}"#.to_string())
}

/// Allowlist actual (triage de FP: la UI lista y quita entradas).
async fn handle_get_allowlist(ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    let config = ctx.config.read().unwrap_or_else(|p| p.into_inner());
    let json = serde_json::to_string(&config.policy.allowlist).map_err(|e| format!("serialize error: {e}"))?;
    Ok(json_response(StatusCode::OK, json))
}

/// Añadir un valor a la allowlist (triage de FP en un click). Persiste en el
/// YAML y afecta a la ruta de escaneo inmediatamente (el hot-path lee la
/// allowlist de la config compartida).
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
    Ok(apply_allowlist_add(ctx, &body_bytes))
}

/// Núcleo de `POST /api/allowlist` (testeable sin socket).
fn apply_allowlist_add(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    let value = match allowlist_value(body_bytes) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
    if live.policy.allows(&value) {
        // Idempotente: ya estaba, no reescribimos el YAML.
        return json_response(
            StatusCode::OK,
            &format!(r#"{{"status":"ok","added":{value:?},"already_present":true}}"#),
        );
    }
    let mut candidate = live.policy.clone();
    candidate.allowlist.push(value.clone());
    if let Err(resp) = commit_policy(ctx, &mut live, candidate) {
        return *resp;
    }
    json_response(StatusCode::OK, &format!(r#"{{"status":"ok","added":{value:?}}}"#))
}

/// Extraer `{"value": "…"}` del body de las rutas de allowlist.
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

/// Quitar una entrada de la allowlist. El valor va en el body
/// (`{"value":"…"}`) para no tener que percent-decodificarlo del path.
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
    Ok(apply_allowlist_remove(ctx, &body_bytes))
}

/// Núcleo de `DELETE /api/allowlist` (testeable sin socket).
fn apply_allowlist_remove(ctx: &ApiContext, body_bytes: &[u8]) -> Response<Full<Bytes>> {
    let value = match allowlist_value(body_bytes) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    let mut live = ctx.config.write().unwrap_or_else(|p| p.into_inner());
    if !live.policy.allows(&value) {
        return json_response(
            StatusCode::NOT_FOUND,
            &format!(r#"{{"error":"not in allowlist","value":{value:?}}}"#),
        );
    }
    let mut candidate = live.policy.clone();
    candidate.allowlist.retain(|v| *v != value);
    if let Err(resp) = commit_policy(ctx, &mut live, candidate) {
        return *resp;
    }
    json_response(StatusCode::OK, &format!(r#"{{"status":"ok","removed":{value:?}}}"#))
}

// ─── CSP efectiva del dashboard (review v6.1) ─────────────────────────────

/// HTML del dashboard, embebido en el binario.
const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

/// Contenido de la PRIMERA etiqueta `<tag …>` … `</tag>` de `html`.
///
/// Se usa para hashear los bloques inline del dashboard; el HTML es un asset
/// de compilación (`include_str!`), así que el parseo es sobre entrada fija y
/// los tests verifican que ambos bloques se encuentran.
fn inline_block<'a>(html: &'a str, tag: &str) -> Option<&'a str> {
    let open = html.find(&format!("<{tag}"))?;
    let start = open + html[open..].find('>')? + 1;
    let end = start + html[start..].find(&format!("</{tag}>"))?;
    Some(&html[start..end])
}

/// Cabecera `Content-Security-Policy` del dashboard, calculada una vez.
static DASHBOARD_CSP: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| build_dashboard_csp(DASHBOARD_HTML));

/// Construir la CSP del dashboard **sin `unsafe-inline`**.
///
/// El dashboard es un único asset servido por `/api/dashboard`, así que en vez
/// de abrir `script-src`/`style-src` a todo lo inline se autoriza exactamente
/// el bloque servido por su `sha256`. Al derivarse del mismo `include_str!`
/// que se envía, hash y contenido no pueden desincronizarse. El HTML no lleva
/// handlers inline (`onclick=`) ni atributos `style=`, que necesitarían
/// `'unsafe-hashes'`; hay un test que lo vigila.
///
/// `frame-ancestors` sólo tiene efecto en la cabecera (un `<meta>` lo ignora),
/// que es la razón principal para servir la CSP por HTTP.
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

/// SHA-256 + Base64 mínimos para los hashes de la CSP.
///
/// Se implementan aquí (Rust seguro, ~60 líneas) para no añadir una
/// dependencia al crate del proxy por un único consumidor: la cabecera
/// `Content-Security-Policy`, que necesita `'sha256-<base64>'` del bloque
/// inline servido. Verificado contra los vectores de FIPS 180-4 en los tests.
mod csp_hash {
    /// Constantes de ronda de SHA-256 (FIPS 180-4 §4.2.2).
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

    /// SHA-256 de `data`.
    #[allow(clippy::needless_range_loop)]
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

    /// Alfabeto Base64 estándar (RFC 4648), el que espera la CSP.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Base64 estándar con padding.
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

/// Servir el dashboard (review v5 F6): HTML estático público SIN datos. No
/// exige auth (el routing `/api/*` lo exime) y NUNCA incrusta el token en el
/// DOM; el cliente lo pide por la card de login y lo manda vía header
/// `X-Cerberus-Admin-Token`.
/// Review v6.1: la CSP viaja en la CABECERA (un `<meta>` no puede aplicar
/// `frame-ancestors`) y sin `unsafe-inline`: el bloque inline del asset
/// servido se autoriza por su `sha256`. Ver [`build_dashboard_csp`].
fn handle_dashboard(_ctx: &ApiContext) -> Result<Response<Full<Bytes>>, String> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-security-policy", DASHBOARD_CSP.as_str())
        // Defensa en profundidad para clientes que ignoren `frame-ancestors`.
        .header("x-frame-options", "DENY")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        // El dashboard es HTML estático embebido: no se cachea para que un
        // upgrade del binario no sirva la UI vieja contra la API nueva.
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

/// Respuesta JSON con `Connection: close`. Se usa al rechazar un body
/// sobredimensionado (413) o cualquier error del control plane: el cliente no
/// debe reutilizar una conexión cuyo body quedó sin drenar (fix review v5 —
/// robustez contra smokes flaky).
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

/// Registrar un evento de auditoría en el contexto API.
pub async fn record_event(ctx: &ApiContext, event: AuditEvent) {
    let mut events = ctx.events.lock().await;
    events.push(event.clone());
    // Mantener solo los últimos 10000 eventos en memoria
    if events.len() > 10_000 {
        events.remove(0);
    }
    // Escribir al store SQLite si está disponible
    if let Some(ref store) = ctx.store {
        store.write_event_async(event).await;
    }
}

/// Extraer el provider del path de la request.
///
/// Ej: "/openai/v1/chat" → "openai", "/anthropic/v1/messages" → "anthropic".
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
        // Con espacio: se trimea.
        let mut h2 = hyper::HeaderMap::new();
        h2.insert(ADMIN_TOKEN_HEADER, HeaderValue::from_static("  spaced  "));
        assert!(admin_token_header_is_present(&h2, "spaced"));
    }

    #[test]
    fn dashboard_served_without_auth_when_token_set() {
        // Review v5 F6: el dashboard es HTML estático PUBLICO sin datos. Con
        // admin token configurado NO se exige auth y NO se incrusta el token
        // en el DOM (la card de login va en el JS).
        let cfg = ProxyConfig {
            admin_token: Some("tok<&>\"'".to_string()),
            ..ProxyConfig::default()
        };
        let ctx = ApiContext::new(Arc::new(RwLock::new(cfg)));

        // La ruta del dashboard está exenta del gate de auth...
        assert!(!route_serves_data("/api/dashboard"));
        // ...mientras toda ruta con datos exige auth.
        assert!(route_serves_data("/api/events"));
        assert!(route_serves_data("/api/stats"));
        assert!(route_serves_data("/api/config"));

        // El HTML se sirve (200) sin token incrustado en el DOM.
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

        // GET/PUT /api/config sin token → 401 (comparten el mismo gate).
        let denied = auth_gate(&cfg, "/api/config", &empty).expect("config must be denied");
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        // Con token válido (vía X-Cerberus-Admin-Token) → permitido.
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            ADMIN_TOKEN_HEADER,
            HeaderValue::from_static("correct-horse-battery-staple"),
        );
        assert!(auth_gate(&cfg, "/api/config", &headers).is_none());

        // /api/dashboard queda exento incluso sin token.
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

        let s = handle_get_stats(&ctx, Some("openai".to_string()))
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

        // Sin provider → cuenta ambos.
        let all = handle_get_stats(&ctx, None)
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
            "el envelope wire v2 máximo debe caber en el colector HTTP"
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

    // ─── Review v6.1: DTOs de config ──────────────────────────────────────

    /// Token de 28 bytes: pasa el umbral de [`ADMIN_TOKEN_MIN_BYTES`].
    const STRONG_TOKEN: &str = "correct-horse-battery-stapl0";

    fn cfg_with_token(token: &str) -> ProxyConfig {
        ProxyConfig {
            admin_token: Some(token.to_string()),
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn config_view_never_carries_the_admin_token() {
        // El DTO del GET no TIENE campo `admin_token`, así que no hay nada que
        // redactar: sólo el booleano derivado.
        let cfg = cfg_with_token(STRONG_TOKEN);
        let json = serde_json::to_string(&ConfigView::from_config(&cfg)).unwrap();
        assert!(!json.contains(STRONG_TOKEN), "token leaked in ConfigView: {json}");
        assert!(
            !json.contains("\"admin_token\""),
            "ConfigView must not have the key: {json}"
        );
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["admin_token_configured"].as_bool(), Some(true));
        // Sin token configurado el booleano baja.
        let open = ProxyConfig::default();
        let json = serde_json::to_string(&ConfigView::from_config(&open)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["admin_token_configured"].as_bool(), Some(false));
    }

    #[test]
    fn config_view_round_trips_into_config_patch() {
        // Contrato del cliente: el body del GET se puede reenviar tal cual al
        // PUT (el dashboard hace GET → editar → PUT).
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
            },
        );
        let patch: ConfigPatch = serde_json::from_str(r#"{"mode":"shadow"}"#).unwrap();
        let applied = patch.apply(&base);
        assert_eq!(
            applied.mode,
            crate::config::OperationMode::Shadow,
            "patched field applies"
        );
        // Todo lo demás se preserva — sobre todo el token, que el GET no revela.
        assert_eq!(applied.admin_token.as_deref(), Some(STRONG_TOKEN));
        assert_eq!(applied.listen, base.listen);
        assert_eq!(applied.log_level, base.log_level);
        assert_eq!(applied.health_path, base.health_path);
        assert_eq!(applied.max_body_bytes, base.max_body_bytes);
        assert_eq!(
            applied.upstreams.len(),
            1,
            "upstreams no se pierden en un patch parcial"
        );
    }

    #[test]
    fn config_patch_ignores_read_only_admin_token_configured() {
        // Adversarial: un cliente intenta DESACTIVAR la auth por el booleano
        // de sólo lectura. Se acepta el body y se ignora el campo.
        let base = cfg_with_token(STRONG_TOKEN);
        let patch: ConfigPatch = serde_json::from_str(r#"{"admin_token_configured":false}"#).unwrap();
        let applied = patch.apply(&base);
        assert_eq!(
            applied.admin_token.as_deref(),
            Some(STRONG_TOKEN),
            "admin_token_configured is read-only: it cannot clear the token"
        );
        assert!(expected_admin_token(&applied).is_some(), "auth sigue activa");
    }

    #[test]
    fn config_patch_explicit_null_clears_the_token() {
        // `null` explícito SÍ borra (distinto de omitir): es la forma de pasar
        // a dev mode desde la API, y sólo se permite en loopback (ver el test
        // de exposición).
        let base = cfg_with_token(STRONG_TOKEN);
        let patch: ConfigPatch = serde_json::from_str(r#"{"admin_token":null}"#).unwrap();
        assert!(patch.apply(&base).admin_token.is_none());
        // Y un valor nuevo lo reemplaza.
        let patch: ConfigPatch = serde_json::from_str(r#"{"admin_token":"otro-token-de-24-bytes-min"}"#).unwrap();
        assert_eq!(
            patch.apply(&base).admin_token.as_deref(),
            Some("otro-token-de-24-bytes-min")
        );
    }

    #[test]
    fn config_patch_distinguishes_null_from_omitted_max_body_bytes() {
        let base = ProxyConfig::default();
        assert!(base.max_body_bytes.is_some());
        let omitted: ConfigPatch = serde_json::from_str("{}").unwrap();
        assert_eq!(omitted.apply(&base).max_body_bytes, base.max_body_bytes);
        let nulled: ConfigPatch = serde_json::from_str(r#"{"max_body_bytes":null}"#).unwrap();
        assert!(nulled.apply(&base).max_body_bytes.is_none(), "null = sin límite");
    }

    #[test]
    fn config_patch_rejects_unknown_fields() {
        // Un typo en el nombre del campo falla en voz alta, no en silencio.
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
        // Lo que no se resuelve a loopback se trata como PÚBLICO.
        assert!(!listen_is_loopback("proxy.internal:8080"));
        assert!(!listen_is_loopback(""));
    }

    #[test]
    fn validate_control_plane_exposure_matches_the_bind_rule() {
        // Loopback: dev mode sin token permitido (igual que en el bind).
        assert!(validate_control_plane_exposure(&ProxyConfig::default()).is_ok());

        let public = |token: Option<&str>| ProxyConfig {
            listen: "0.0.0.0:8080".to_string(),
            admin_token: token.map(ToString::to_string),
            ..ProxyConfig::default()
        };
        assert!(validate_control_plane_exposure(&public(None)).is_err(), "sin token");
        assert!(
            validate_control_plane_exposure(&public(Some("change-me"))).is_err(),
            "token corto"
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
        // El caso que el gate tiene que atrapar ANTES de persistir: mover
        // `listen` a una interfaz pública borrando el token.
        let base = cfg_with_token(STRONG_TOKEN);
        let patch: ConfigPatch = serde_json::from_str(r#"{"listen":"0.0.0.0:8080","admin_token":null}"#).unwrap();
        let candidate = patch.apply(&base);
        assert!(validate_control_plane_exposure(&candidate).is_err());
        // …y con el token intacto (omitido) el mismo cambio de listen pasa.
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
        // El 500 del PUT depende de que esto falle: directorio inexistente.
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default())))
            .with_config_path(std::path::PathBuf::from("/nonexistent-cerberus-dir/config.yaml"));
        assert!(persist_config(&ctx, &ProxyConfig::default()).is_err());
    }

    // ─── F6 v6.1 fix: política de detección persistente ───────────────────

    /// Regla custom mínima válida.
    fn custom_rule(flag: &str, category: &str, action: &str, pattern: &str) -> serde_json::Value {
        serde_json::json!({
            "flag": flag,
            "category": category,
            "severity": "high",
            "action": action,
            "patterns": [pattern],
        })
    }

    /// Contexto con persistencia YAML y engine vivo conectado (lo que tiene el
    /// daemon real).
    fn policy_ctx(dir: &std::path::Path) -> (ApiContext, crate::detection_policy::EngineControl) {
        let base = vec![crate::detection_policy::tests_support::base_rule("pack.token")];
        let engine =
            crate::detection_policy::build_engine(&base, &ProxyConfig::default().policy, None).expect("boot engine");
        let live = Arc::new(RwLock::new(Arc::new(engine)));
        let control = crate::detection_policy::EngineControl::new(live, base, None);
        let ctx = ApiContext::new(Arc::new(RwLock::new(ProxyConfig::default())))
            .with_config_path(dir.join("config.yaml"))
            .with_engine(control.clone());
        (ctx, control)
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
        assert!(
            p.categories.is_empty(),
            "categorías ausentes = heredar acción de la regla"
        );
        assert!(p.rule_actions.is_empty());
        assert!(p.custom_rules.is_empty());
    }

    #[test]
    fn policy_patch_rejects_bad_actions_and_categories_before_mutating() {
        let base = DetectionPolicy::seeded();

        let bad_action: PolicyPatch = serde_json::from_str(r#"{"rules":{"a.b":"nuke"}}"#).unwrap();
        let err = bad_action.apply(&base).expect_err("acción inválida");
        assert!(err.contains("nuke") && err.contains("allow|warn|redact|block"), "{err}");

        let bad_category: PolicyPatch = serde_json::from_str(r#"{"categories":{"secretos":"block"}}"#).unwrap();
        let err = bad_category.apply(&base).expect_err("categoría inválida");
        assert!(
            err.contains("secretos") && err.contains("secrets|pii|internal_code"),
            "{err}"
        );

        // Un patch con una entrada válida y otra inválida no aplica NINGUNA.
        let mixed: PolicyPatch = serde_json::from_str(r#"{"categories":{"secrets":"block","pii":"nuke"}}"#).unwrap();
        assert!(mixed.apply(&base).is_err());
        assert!(base.categories.is_empty(), "la política base no se tocó");

        // Clave desconocida = 400, no silencio.
        assert!(serde_json::from_str::<PolicyPatch>(r#"{"nope":{}}"#).is_err());
        // `admin_token` no se cuela por esta puerta.
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
            "null borra"
        );
        assert!(
            out.categories.contains_key(&cerberus_engine::rule::Category::Secrets),
            "clave ausente se preserva"
        );
        assert_eq!(out.rule_actions.len(), 1, "los overrides se preservan");
        assert_eq!(out.allowlist, vec!["keep-me".to_string()], "la allowlist se preserva");
    }

    #[test]
    fn policy_patch_replaces_custom_rules_and_allowlist_wholesale() {
        let mut base = DetectionPolicy::seeded();
        base.allowlist.push("old".to_string());
        let patch: PolicyPatch = serde_json::from_str(r#"{"allowlist":[],"custom_rules":[]}"#).unwrap();
        let out = patch.apply(&base).expect("apply");
        assert!(out.allowlist.is_empty(), "[] vacía la lista");
        assert!(out.custom_rules.is_empty());
    }

    #[test]
    fn put_policy_persists_the_yaml_and_swaps_the_live_engine() {
        let dir = tmpdir("persist");
        let (ctx, control) = policy_ctx(&dir);
        assert_eq!(control.live_rules(), 1, "arranca con la regla del pack");

        let (status, doc) = put_policy(
            &ctx,
            &serde_json::json!({
                "categories": {"secrets": "block"},
                "rules": {"pack.token": "warn"},
                "custom_rules": [custom_rule("custom.badge", "internal_code", "block", r"BADGE-\d{4}")],
                "allowlist": ["sk-EXAMPLE"],
            }),
        );
        assert_eq!(status, StatusCode::OK, "{doc}");
        assert_eq!(doc["persisted"].as_bool(), Some(true), "ya no es un overlay en memoria");
        assert_eq!(doc["categories"]["secrets"].as_str(), Some("block"));
        assert_eq!(doc["rules"]["pack.token"].as_str(), Some("warn"));
        assert_eq!(doc["custom_rules"][0]["flag"].as_str(), Some("custom.badge"));
        assert_eq!(doc["allowlist"][0].as_str(), Some("sk-EXAMPLE"));

        // Engine vivo: la regla del pack SIGUE ahí y la custom se sumó.
        assert_eq!(control.live_rules(), 2, "packs + custom, sin perder ninguna");
        assert_eq!(doc["engine_rules"].as_u64(), Some(2));

        // YAML: se puede releer y reconstruye la MISMA política (reinicio).
        let yaml = std::fs::read_to_string(dir.join("config.yaml")).expect("yaml escrito");
        let reloaded = ProxyConfig::parse(&yaml).expect("reparse");
        assert_eq!(reloaded.policy, ctx.config.read().unwrap().policy);
        assert_eq!(reloaded.policy.custom_rules.len(), 1);
        assert_eq!(reloaded.policy.allowlist, vec!["sk-EXAMPLE".to_string()]);
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
        assert_eq!(control.live_rules(), 1, "el engine vivo no cambió");
        assert!(ctx.config.read().unwrap().policy.custom_rules.is_empty());
        assert!(
            !dir.join("config.yaml").exists(),
            "una política inválida no se persiste"
        );
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
            "no se publica un engine que no se pudo persistir"
        );
        assert!(ctx.config.read().unwrap().policy.custom_rules.is_empty());
    }

    #[tokio::test]
    async fn policy_and_allowlist_are_exposed_together() {
        let dir = tmpdir("together");
        let (ctx, _control) = policy_ctx(&dir);
        let (status, _) = decode(apply_allowlist_add(&ctx, br#"{"value":"sk-EXAMPLE-do-not-flag"}"#));
        assert_eq!(status, StatusCode::OK);

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
            "sin override explícito, la API expone categorías heredadas como ausentes"
        );
        assert_eq!(json["allowlist"][0].as_str(), Some("sk-EXAMPLE-do-not-flag"));
        assert_eq!(json["valid_actions"].as_array().map(Vec::len), Some(4));
        assert_eq!(json["valid_categories"].as_array().map(Vec::len), Some(3));
        assert_eq!(json["persisted"].as_bool(), Some(true), "la política está en el YAML");

        // La allowlist quedó en el YAML (sobrevive al reinicio).
        let yaml = std::fs::read_to_string(dir.join("config.yaml")).expect("yaml");
        assert!(yaml.contains("sk-EXAMPLE-do-not-flag"), "{yaml}");
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
            vec!["dup".to_string()],
            "no se duplica"
        );

        let (status, doc) = decode(apply_allowlist_remove(&ctx, br#"{"value":"ghost"}"#));
        assert_eq!(status, StatusCode::NOT_FOUND, "{doc}");

        let (status, _) = decode(apply_allowlist_remove(&ctx, br#"{"value":"dup"}"#));
        assert_eq!(status, StatusCode::OK);
        assert!(ctx.config.read().unwrap().policy.allowlist.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_config_patch_never_clobbers_the_policy() {
        // `ConfigPatch::apply` es la única vía por la que `PUT /api/config`
        // construye la config candidata: la política debe salir intacta.
        let mut base = ProxyConfig::default();
        base.policy
            .custom_rules
            .push(serde_json::from_value(custom_rule("custom.keep", "secrets", "block", "KEEP-[0-9]+")).unwrap());
        let patch: ConfigPatch = serde_json::from_str(r#"{"log_level":"debug"}"#).unwrap();
        let candidate = patch.apply(&base);
        assert_eq!(candidate.log_level, "debug");
        assert_eq!(candidate.policy, base.policy, "PUT /api/config no pisa la política");
    }

    #[test]
    fn config_view_does_not_expose_the_policy_so_a_get_put_cycle_still_works() {
        // `ConfigPatch` es `deny_unknown_fields`: si `ConfigView` devolviera
        // `policy`, reenviar el GET verbatim en un PUT sería un 400.
        let cfg = ProxyConfig::default();
        let json = serde_json::to_string(&ConfigView::from_config(&cfg)).expect("serialize");
        assert!(!json.contains(r#""policy""#), "{json}"); // `fail_policy` sí, `policy` no
        if let Err(e) = serde_json::from_str::<ConfigPatch>(&json) {
            panic!("GET→PUT verbatim debe seguir siendo válido: {e} — {json}");
        }
    }

    // ─── Review v6.1: CSP del dashboard ───────────────────────────────────

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
        // 56 bytes: fuerza el segundo bloque de padding.
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
        // El dashboard real tiene exactamente un bloque de cada uno.
        assert_eq!(DASHBOARD_HTML.matches("<script").count(), 1);
        assert_eq!(DASHBOARD_HTML.matches("<style").count(), 1);
        assert!(inline_block(DASHBOARD_HTML, "script").is_some_and(|b| b.contains("loadData")));
        assert!(inline_block(DASHBOARD_HTML, "style").is_some_and(|b| b.contains(".card")));
    }

    #[test]
    fn dashboard_html_has_no_inline_event_handlers() {
        // Con la CSP basada en hash, un `onclick=` o un `style=` necesitaría
        // 'unsafe-hashes'. Este test evita que vuelvan por la puerta de atrás.
        let html = DASHBOARD_HTML;
        for attr in ["onclick=\"", "onchange=\"", "oninput=\"", "onsubmit=\"", "style=\""] {
            assert!(!html.contains(attr), "inline attribute {attr} breaks the CSP");
        }
        assert!(
            !html.contains("http-equiv=\"Content-Security-Policy\""),
            "la CSP la emite la cabecera; una copia en <meta> se desincroniza del hash"
        );

        // Review v6.1 P1: el dashboard debe construir el mismo wire v2 que el
        // CLI. Una ruta local nunca puede reaparecer en el request.
        assert!(html.contains(r#"<input type="file" id="pack-file""#));
        assert!(!html.contains("pack-path"));
        let install_pack = html
            .split_once("async function installPack()")
            .and_then(|(_, rest)| rest.split_once("async function rollbackPack()"))
            .map(|(body, _)| body)
            .expect("installPack debe seguir siendo inspeccionable por el test de contrato");
        assert!(
            !install_pack.contains("path"),
            "installPack no puede volver a transportar una ruta local: {install_pack}"
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
            .expect("la forma exacta producida por el dashboard debe ser aceptada por parse_body");
    }

    #[test]
    fn dashboard_csp_has_no_unsafe_inline_and_hashes_the_served_blocks() {
        let csp = build_dashboard_csp(DASHBOARD_HTML);
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        assert!(!csp.contains("unsafe-hashes"), "{csp}");
        // `frame-ancestors` es la razón de emitirla por cabecera: un <meta> lo ignora.
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        assert!(csp.contains("object-src 'none'"), "{csp}");
        assert!(csp.contains("base-uri 'none'"), "{csp}");

        // El hash corresponde EXACTAMENTE al bloque que se sirve.
        let script = inline_block(DASHBOARD_HTML, "script").unwrap();
        let expected = format!("'sha256-{}'", csp_hash::base64(&csp_hash::sha256(script.as_bytes())));
        assert!(csp.contains(&format!("script-src {expected}")), "{csp}");
        let style = inline_block(DASHBOARD_HTML, "style").unwrap();
        let expected = format!("'sha256-{}'", csp_hash::base64(&csp_hash::sha256(style.as_bytes())));
        assert!(csp.contains(&format!("style-src {expected}")), "{csp}");
        // Cambiar una coma del bloque cambia el hash: no puede quedar obsoleto.
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
