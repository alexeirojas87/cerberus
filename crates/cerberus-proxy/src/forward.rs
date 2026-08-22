//! Forward proxy TLS opt-in for endpoints that do not allow changing their
//! base URL.
//!
//! The listener is deliberately independent of the reverse proxy: it can
//! only listen on loopback, only accepts `CONNECT host:443`, and only
//! issues a certificate for exact hosts configured by the user. The CA
//! must exist before startup; this module never installs it in a trust
//! store.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::proxy::{proxy_handler, DirectUpstream, ProxyContext};

const MAX_ALLOWED_HOSTS: usize = 64;
const MAX_CONNECTIONS: usize = 128;
const LISTEN_BACKLOG: u32 = (MAX_CONNECTIONS * 2) as u32;
const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

type UpstreamClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;
type ConnectionPermit = Arc<Mutex<Option<OwnedSemaphorePermit>>>;
type TunnelJob = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Local CA material. Paths are received explicitly so the core does not
/// depend on a home directory or create state implicitly.
#[derive(Clone, Debug)]
pub struct CaPaths {
    /// Public PEM certificate.
    pub cert: PathBuf,
    /// PEM private key.
    pub key: PathBuf,
}

/// Effective configuration of the forward/MITM listener.
#[derive(Clone, Debug)]
pub struct ForwardProxyConfig {
    listen: SocketAddr,
    allowed_hosts: Vec<String>,
    ca: CaPaths,
    #[cfg(test)]
    upstream_overrides: HashMap<String, String>,
}

impl ForwardProxyConfig {
    /// Builds a safe configuration. Rejects public interfaces, persisted
    /// ephemeral ports and empty/too-large allowlists.
    pub fn new(listen: SocketAddr, allowed_hosts: &[String], ca: CaPaths) -> Result<Self, String> {
        if !listen.ip().is_loopback() {
            return Err("MITM forward proxy only accepts loopback listen addresses".to_string());
        }
        if listen.port() == 0 {
            return Err("MITM forward proxy requires a non-zero listen port".to_string());
        }
        let allowed_hosts = normalize_allowed_hosts(allowed_hosts)?;
        Ok(Self {
            listen,
            allowed_hosts,
            ca,
            #[cfg(test)]
            upstream_overrides: HashMap::new(),
        })
    }

    #[cfg(test)]
    fn for_test(listen: SocketAddr, allowed_hosts: &[String], ca: CaPaths) -> Result<Self, String> {
        let mut cfg = Self::new(SocketAddr::new(listen.ip(), listen.port().max(1)), allowed_hosts, ca)?;
        cfg.listen = listen;
        Ok(cfg)
    }
}

/// Normalize and validate an exact DNS allowlist. Wildcards, IPs, URLs,
/// ports and implicit suffixes are not allowed.
pub fn normalize_allowed_hosts(hosts: &[String]) -> Result<Vec<String>, String> {
    if hosts.is_empty() {
        return Err("MITM requires at least one explicit --host".to_string());
    }
    if hosts.len() > MAX_ALLOWED_HOSTS {
        return Err(format!("MITM accepts at most {MAX_ALLOWED_HOSTS} hosts"));
    }
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(hosts.len());
    for host in hosts {
        let host = normalize_host(host)?;
        if seen.insert(host.clone()) {
            normalized.push(host);
        }
    }
    Ok(normalized)
}

fn normalize_host(raw: &str) -> Result<String, String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.contains('*') || host.parse::<std::net::IpAddr>().is_ok() {
        return Err("MITM hosts must be exact DNS names".to_string());
    }
    if host.contains('/') || host.contains(':') || host.contains('@') {
        return Err("MITM hosts must not contain a scheme, path, credentials, or port".to_string());
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if !valid || !host.contains('.') {
        return Err("MITM hosts must be valid fully-qualified DNS names".to_string());
    }
    Ok(host)
}

/// Generates a local CA without trusting or installing it. The operation is
/// `create_new`: it never overwrites previous material.
pub fn generate_local_ca(paths: &CaPaths) -> Result<(), String> {
    if paths.cert.exists() || paths.key.exists() {
        return Err("refusing to overwrite existing CA material".to_string());
    }
    let cert_parent = paths.cert.parent().ok_or("CA certificate path has no parent")?;
    let key_parent = paths.key.parent().ok_or("CA key path has no parent")?;
    create_secure_dir(cert_parent)?;
    create_secure_dir(key_parent)?;

    let key = KeyPair::generate().map_err(|e| format!("cannot generate CA key: {e}"))?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Cerberus Local CA");
    dn.push(DnType::OrganizationName, "Cerberus");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("cannot self-sign CA certificate: {e}"))?;

    let mut key_file = create_new_file(&paths.key, true).map_err(|e| format!("cannot create CA key: {e}"))?;
    if let Err(error) = write_and_sync(&mut key_file, key.serialize_pem().as_bytes()) {
        let _ = fs::remove_file(&paths.key);
        return Err(format!("cannot persist CA key: {error}"));
    }
    drop(key_file);

    let mut cert_file = match create_new_file(&paths.cert, false) {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&paths.key);
            return Err(format!("cannot create CA certificate: {error}"));
        }
    };
    if let Err(error) = write_and_sync(&mut cert_file, cert.pem().as_bytes()) {
        let _ = fs::remove_file(&paths.cert);
        let _ = fs::remove_file(&paths.key);
        return Err(format!("cannot persist CA certificate: {error}"));
    }
    validate_ca_files(paths)
}

/// Validate existence, type, size and permissions of the CA. On Unix a key
/// readable by group/others makes startup fail (fail closed).
pub fn validate_ca_files(paths: &CaPaths) -> Result<(), String> {
    LocalCa::load(paths).map(|_| ())
}

fn create_secure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("cannot create CA directory: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot secure CA directory: {e}"))?;
    }
    Ok(())
}

fn create_new_file(path: &Path, private: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let _ = private;
    options.open(path)
}

fn write_and_sync(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn read_ca_file(path: &Path, private: bool) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("CA file unavailable: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("CA paths must be regular files, not symlinks".to_string());
    }
    if metadata.len() > MAX_CA_FILE_BYTES {
        return Err("CA file exceeds 1 MiB limit".to_string());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("CA private key permissions must be 0600 or stricter".to_string());
        }
    }
    let file = File::open(path).map_err(|e| format!("cannot open CA file: {e}"))?;
    let mut output = String::new();
    file.take(MAX_CA_FILE_BYTES + 1)
        .read_to_string(&mut output)
        .map_err(|e| format!("cannot read CA PEM: {e}"))?;
    if output.len() as u64 > MAX_CA_FILE_BYTES {
        return Err("CA file exceeds 1 MiB limit".to_string());
    }
    Ok(output)
}

fn strict_single_pem_block<'a>(contents: &'a str, label: &str, material: &str) -> Result<&'a str, String> {
    let trimmed = contents.trim();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    if !trimmed.starts_with(&begin) {
        return Err(format!("{material} must contain exactly one {label} PEM block"));
    }
    let body = &trimmed[begin.len()..];
    let Some(relative_end) = body.find(&end) else {
        return Err(format!("{material} has no matching {label} PEM end marker"));
    };
    let end_offset = begin.len() + relative_end;
    let block_end = end_offset + end.len();
    let encoded_body = &trimmed[begin.len()..end_offset];
    if encoded_body.contains("-----BEGIN ") || encoded_body.contains("-----END ") {
        return Err(format!("{material} contains multiple or nested PEM blocks"));
    }
    if !trimmed[block_end..].trim().is_empty() {
        return Err(format!("{material} contains trailing data or multiple PEM blocks"));
    }
    Ok(&trimmed[..block_end])
}

struct LocalCa {
    issuer: Issuer<'static, KeyPair>,
}

impl LocalCa {
    fn load(paths: &CaPaths) -> Result<Self, String> {
        let cert_contents = read_ca_file(&paths.cert, false)?;
        let key_contents = read_ca_file(&paths.key, true)?;
        let cert_pem = strict_single_pem_block(&cert_contents, "CERTIFICATE", "CA certificate")?;
        let key_pem = strict_single_pem_block(&key_contents, "PRIVATE KEY", "CA private key")?;
        let (remainder, persisted_cert_pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| format!("invalid CA certificate PEM: {e}"))?;
        if !remainder.is_empty() {
            return Err("CA certificate contains unconsumed PEM data".to_string());
        }
        let persisted_cert = persisted_cert_pem
            .parse_x509()
            .map_err(|e| format!("invalid CA certificate: {e}"))?;
        let is_ca = persisted_cert
            .basic_constraints()
            .map_err(|e| format!("invalid CA basic constraints: {e}"))?
            .is_some_and(|constraints| constraints.value.ca);
        if !is_ca {
            return Err("configured certificate is not a CA".to_string());
        }
        let key = KeyPair::from_pem(key_pem).map_err(|e| format!("invalid CA private key: {e}"))?;
        if persisted_cert.public_key().raw != key.subject_public_key_info() {
            return Err("CA certificate does not match private key".to_string());
        }
        let certificate_der = CertificateDer::from(persisted_cert_pem.contents.as_slice());
        let issuer = Issuer::from_ca_cert_der(&certificate_der, key)
            .map_err(|e| format!("invalid imported CA certificate: {e}"))?;
        Ok(Self { issuer })
    }

    fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let leaf_key = KeyPair::generate().map_err(|e| format!("cannot generate leaf key: {e}"))?;
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|e| format!("invalid certificate host: {e}"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| format!("cannot sign leaf certificate: {e}"))?;

        let certificate = CertificateDer::from(leaf.der().to_vec());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .map_err(|e| format!("invalid generated TLS identity: {e}"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

struct ForwardState {
    tls_configs: Arc<HashMap<String, Arc<ServerConfig>>>,
    targets: Arc<HashMap<String, String>>,
    ctx: Arc<ProxyContext>,
    client: UpstreamClient,
    shutdown: watch::Receiver<bool>,
    tunnel_jobs: mpsc::UnboundedSender<TunnelJob>,
    active_tunnels: Arc<AtomicUsize>,
    #[cfg(test)]
    active_tunnel_count: watch::Sender<usize>,
    #[cfg(test)]
    test_state: Arc<ForwardTestState>,
}

impl Clone for ForwardState {
    fn clone(&self) -> Self {
        Self {
            tls_configs: self.tls_configs.clone(),
            targets: self.targets.clone(),
            ctx: self.ctx.clone(),
            client: self.client.clone(),
            shutdown: self.shutdown.clone(),
            tunnel_jobs: self.tunnel_jobs.clone(),
            active_tunnels: self.active_tunnels.clone(),
            #[cfg(test)]
            active_tunnel_count: self.active_tunnel_count.clone(),
            #[cfg(test)]
            test_state: self.test_state.clone(),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct ForwardTestState {
    accepted: AtomicUsize,
    permits_acquired: AtomicUsize,
    jobs_enqueued: AtomicUsize,
    jobs_started: AtomicUsize,
    jobs_completed: AtomicUsize,
    pause_job_starts: std::sync::atomic::AtomicBool,
    job_enqueued: Notify,
    job_started_notify: Notify,
}

#[cfg(test)]
#[derive(Debug)]
struct ForwardTestSnapshot {
    accepted: usize,
    permits_acquired: usize,
    permits_available: usize,
    jobs_enqueued: usize,
    jobs_started: usize,
    jobs_completed: usize,
    active_tunnels: usize,
}

#[cfg(test)]
struct ForwardTestJobGuard {
    state: Arc<ForwardTestState>,
}

#[cfg(test)]
impl Drop for ForwardTestJobGuard {
    fn drop(&mut self) {
        self.state.jobs_completed.fetch_add(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
impl ForwardTestState {
    fn job_started(self: &Arc<Self>) -> ForwardTestJobGuard {
        self.jobs_started.fetch_add(1, Ordering::AcqRel);
        self.job_started_notify.notify_waiters();
        ForwardTestJobGuard { state: self.clone() }
    }

    async fn wait_until_jobs_enqueued(&self, expected: usize) {
        loop {
            let notified = self.job_enqueued.notified();
            if self.jobs_enqueued.load(Ordering::Acquire) >= expected {
                return;
            }
            notified.await;
        }
    }

    async fn wait_until_jobs_started(&self, expected: usize) {
        loop {
            let notified = self.job_started_notify.notified();
            if self.jobs_started.load(Ordering::Acquire) >= expected {
                return;
            }
            notified.await;
        }
    }
}

/// Managed handle of the forward listener.
pub struct ManagedForwardProxyHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    #[cfg(test)]
    active_tunnels: watch::Receiver<usize>,
    #[cfg(test)]
    permits: Arc<Semaphore>,
    #[cfg(test)]
    test_state: Arc<ForwardTestState>,
}

impl ManagedForwardProxyHandle {
    #[cfg(test)]
    async fn wait_until_active_tunnels(&mut self, expected: usize) {
        while *self.active_tunnels.borrow() != expected {
            self.active_tunnels
                .changed()
                .await
                .expect("forward listener stopped before reaching the expected tunnel count");
        }
    }

    #[cfg(test)]
    fn test_snapshot(&self) -> ForwardTestSnapshot {
        ForwardTestSnapshot {
            accepted: self.test_state.accepted.load(Ordering::Acquire),
            permits_acquired: self.test_state.permits_acquired.load(Ordering::Acquire),
            permits_available: self.permits.available_permits(),
            jobs_enqueued: self.test_state.jobs_enqueued.load(Ordering::Acquire),
            jobs_started: self.test_state.jobs_started.load(Ordering::Acquire),
            jobs_completed: self.test_state.jobs_completed.load(Ordering::Acquire),
            active_tunnels: *self.active_tunnels.borrow(),
        }
    }

    /// Closes admission and active tunnels, waiting at most `grace`.
    pub async fn shutdown(mut self, grace: Duration) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        match tokio::time::timeout(grace, &mut self.task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("forward proxy task failed during shutdown: {error}")),
            Err(_) => {
                self.task.abort();
                let _ = self.task.await;
                Err(format!("forward proxy drain exceeded {} ms", grace.as_millis()))
            }
        }
    }
}

/// Starts the forward listener. CA loading/validation and the bounded
/// certificate generation happen before the bind.
#[allow(clippy::unused_async)] // Preserve the public async startup API after switching to TcpSocket.
pub async fn spawn_forward_proxy(
    config: ForwardProxyConfig,
    ctx: Arc<ProxyContext>,
) -> Result<(SocketAddr, ManagedForwardProxyHandle), Box<dyn std::error::Error + Send + Sync>> {
    let ca = LocalCa::load(&config.ca)?;
    let mut tls_configs = HashMap::with_capacity(config.allowed_hosts.len());
    let mut targets = HashMap::with_capacity(config.allowed_hosts.len());
    for host in &config.allowed_hosts {
        tls_configs.insert(host.clone(), ca.server_config_for(host)?);
        #[cfg(test)]
        let target = config
            .upstream_overrides
            .get(host)
            .cloned()
            .unwrap_or_else(|| format!("https://{host}:443"));
        #[cfg(not(test))]
        let target = format!("https://{host}:443");
        targets.insert(host.clone(), target);
    }

    let socket = if config.listen.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.bind(config.listen)?;
    let listener = socket.listen(LISTEN_BACKLOG)?;
    let actual = listener.local_addr()?;
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (tunnel_shutdown_tx, tunnel_shutdown_rx) = watch::channel(false);
    let (tunnel_jobs_tx, tunnel_jobs_rx) = mpsc::unbounded_channel();
    #[cfg(test)]
    let (active_tunnel_count_tx, active_tunnel_count_rx) = watch::channel(0);
    #[cfg(test)]
    let test_state = Arc::new(ForwardTestState::default());
    let state = ForwardState {
        tls_configs: Arc::new(tls_configs),
        targets: Arc::new(targets),
        ctx,
        client,
        shutdown: tunnel_shutdown_rx,
        tunnel_jobs: tunnel_jobs_tx,
        active_tunnels: Arc::new(AtomicUsize::new(0)),
        #[cfg(test)]
        active_tunnel_count: active_tunnel_count_tx,
        #[cfg(test)]
        test_state: test_state.clone(),
    };
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    #[cfg(test)]
    let task_permits = permits.clone();
    #[cfg(not(test))]
    let task_permits = permits;
    let task = tokio::spawn(serve_forward(
        listener,
        state,
        task_permits,
        shutdown_rx,
        tunnel_shutdown_tx,
        tunnel_jobs_rx,
    ));
    Ok((
        actual,
        ManagedForwardProxyHandle {
            shutdown: Some(shutdown_tx),
            task,
            #[cfg(test)]
            active_tunnels: active_tunnel_count_rx,
            #[cfg(test)]
            permits,
            #[cfg(test)]
            test_state,
        },
    ))
}

async fn serve_forward(
    listener: TcpListener,
    state: ForwardState,
    permits: Arc<Semaphore>,
    mut shutdown: oneshot::Receiver<()>,
    tunnel_shutdown: watch::Sender<bool>,
    mut tunnel_jobs: mpsc::UnboundedReceiver<TunnelJob>,
) {
    let mut connections = JoinSet::new();
    let mut tunnels = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else {
                    tracing::warn!("forward proxy accept failed");
                    continue;
                };
                #[cfg(test)]
                state.test_state.accepted.fetch_add(1, Ordering::AcqRel);
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!("forward proxy connection limit reached");
                    drop(stream);
                    continue;
                };
                #[cfg(test)]
                state.test_state.permits_acquired.fetch_add(1, Ordering::AcqRel);
                let connection_state = state.clone();
                let permit = Arc::new(Mutex::new(Some(permit)));
                connections.spawn(async move {
                    serve_forward_connection(stream, connection_state, permit).await;
                });
            }
            Some(job) = tunnel_jobs.recv(), if {
                #[cfg(test)]
                {
                    !state.test_state.pause_job_starts.load(Ordering::Acquire)
                }
                #[cfg(not(test))]
                {
                    true
                }
            } => {
                tunnels.spawn(job);
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    tracing::warn!("forward proxy connection task failed");
                }
            }
            completed = tunnels.join_next(), if !tunnels.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    tracing::warn!("forward proxy tunnel task failed");
                }
            }
        }
    }

    tunnel_jobs.close();
    let _ = tunnel_shutdown.send(true);
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            tracing::warn!("forward proxy connection task failed while draining");
        }
    }
    while let Some(job) = tunnel_jobs.recv().await {
        tunnels.spawn(job);
    }
    while let Some(result) = tunnels.join_next().await {
        if result.is_err() {
            tracing::warn!("forward proxy tunnel task failed while draining");
        }
    }
}

async fn serve_forward_connection(stream: TcpStream, state: ForwardState, permit: ConnectionPermit) {
    let service_state = state.clone();
    let service_permit = permit;
    let service = service_fn(move |request| {
        std::future::ready(Ok::<_, Infallible>(forward_connect(
            request,
            service_state.clone(),
            &service_permit,
        )))
    });
    let connection = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    let mut shutdown = state.shutdown.clone();
    if *shutdown.borrow() {
        return;
    }
    tokio::select! {
        result = connection => {
            if result.is_err() {
                tracing::debug!("forward proxy client connection closed with protocol error");
            }
        }
        _ = shutdown.changed() => {}
    }
}

fn forward_connect(
    mut request: Request<Incoming>,
    state: ForwardState,
    connection_permit: &ConnectionPermit,
) -> Response<Full<Bytes>> {
    if request.method() != Method::CONNECT {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let Ok(target) = parse_connect_target(&request) else {
        return empty_response(StatusCode::BAD_REQUEST);
    };
    let Some(tls_config) = state.tls_configs.get(&target).cloned() else {
        return empty_response(StatusCode::FORBIDDEN);
    };
    let Some(target_base) = state.targets.get(&target).cloned() else {
        return empty_response(StatusCode::FORBIDDEN);
    };
    let Some(permit) = connection_permit
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    else {
        return empty_response(StatusCode::SERVICE_UNAVAILABLE);
    };

    let upgrade = hyper::upgrade::on(&mut request);
    let tunnel_state = state;
    tunnel_state.active_tunnels.fetch_add(1, Ordering::AcqRel);
    #[cfg(test)]
    tunnel_state
        .active_tunnel_count
        .send_replace(tunnel_state.active_tunnels.load(Ordering::Acquire));
    let tunnel_jobs = tunnel_state.tunnel_jobs.clone();
    let guard = TunnelGuard {
        _permit: permit,
        active: tunnel_state.active_tunnels.clone(),
        #[cfg(test)]
        active_tunnel_count: tunnel_state.active_tunnel_count.clone(),
    };
    #[cfg(test)]
    let test_state = tunnel_state.test_state.clone();
    let job: TunnelJob = Box::pin(async move {
        let _guard = guard;
        #[cfg(test)]
        let _test_job = tunnel_state.test_state.job_started();
        let mut shutdown = tunnel_state.shutdown.clone();
        if *shutdown.borrow() {
            return;
        }
        let upgraded = tokio::select! {
            result = upgrade => {
                let Ok(upgraded) = result else {
                    tracing::debug!("CONNECT upgrade failed");
                    return;
                };
                upgraded
            }
            _ = shutdown.changed() => return,
        };
        serve_intercepted(upgraded, tls_config, target, target_base, tunnel_state).await;
    });
    if tunnel_jobs.send(job).is_err() {
        return empty_response(StatusCode::SERVICE_UNAVAILABLE);
    }
    #[cfg(test)]
    {
        test_state.jobs_enqueued.fetch_add(1, Ordering::AcqRel);
        test_state.job_enqueued.notify_waiters();
    }
    empty_response(StatusCode::OK)
}

fn parse_connect_target(request: &Request<Incoming>) -> Result<String, ()> {
    let authority = request.uri().authority().ok_or(())?;
    if authority.port_u16() != Some(443) {
        return Err(());
    }
    normalize_host(authority.host()).map_err(|_| ())
}

async fn serve_intercepted(
    upgraded: hyper::upgrade::Upgraded,
    tls_config: Arc<ServerConfig>,
    host: String,
    target_base: String,
    state: ForwardState,
) {
    let acceptor = TlsAcceptor::from(tls_config);
    let mut shutdown = state.shutdown.clone();
    if *shutdown.borrow() {
        return;
    }
    let tls = tokio::select! {
        result = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(TokioIo::new(upgraded))) => {
            match result {
                Ok(Ok(tls)) => tls,
                Ok(Err(_)) => {
                    tracing::debug!(host = %host, "intercepted TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(host = %host, "intercepted TLS handshake timed out");
                    return;
                }
            }
        }
        _ = shutdown.changed() => return,
    };
    let provider = host.clone();
    let request_state = state.clone();
    let service = service_fn(move |mut request: Request<Incoming>| {
        let state = request_state.clone();
        let direct = DirectUpstream {
            base: target_base.clone(),
            provider: provider.clone(),
        };
        request.extensions_mut().insert(direct);
        async move {
            let response = proxy_handler(request, &state.ctx, &state.client)
                .await
                .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY));
            Ok::<_, Infallible>(response)
        }
    });
    let connection = http1::Builder::new().serve_connection(TokioIo::new(tls), service);
    if *shutdown.borrow() {
        return;
    }
    tokio::select! {
        result = connection => {
            if result.is_err() {
                tracing::debug!(host = %host, "intercepted HTTP connection closed with protocol error");
            }
        }
        _ = shutdown.changed() => {}
    }
}

fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

struct TunnelGuard {
    _permit: OwnedSemaphorePermit,
    active: Arc<AtomicUsize>,
    #[cfg(test)]
    active_tunnel_count: watch::Sender<usize>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        #[cfg(test)]
        self.active_tunnel_count
            .send_replace(self.active.load(Ordering::Acquire));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    use crate::config::{FailPolicy, OperationMode};
    use crate::test_utils::{build_test_context, make_test_rule};

    fn ca_paths(dir: &Path) -> CaPaths {
        CaPaths {
            cert: dir.join("cerberus-ca.pem"),
            key: dir.join("cerberus-ca.key"),
        }
    }

    #[test]
    fn allowlist_is_exact_normalized_and_rejects_unsafe_inputs() {
        let hosts = normalize_allowed_hosts(&["API.Example.COM.".to_string(), "api.example.com".to_string()]).unwrap();
        assert_eq!(hosts, vec!["api.example.com"]);
        for invalid in [
            "*.example.com",
            "https://api.example.com",
            "127.0.0.1",
            "localhost",
            "api.example.com:443",
        ] {
            assert!(
                normalize_allowed_hosts(&[invalid.to_string()]).is_err(),
                "accepted {invalid}"
            );
        }
        let too_many = (0..=MAX_ALLOWED_HOSTS)
            .map(|index| format!("host-{index}.example.com"))
            .collect::<Vec<_>>();
        assert!(normalize_allowed_hosts(&too_many).is_err());
    }

    #[test]
    fn config_rejects_public_listener_and_empty_allowlist() {
        let ca = CaPaths {
            cert: PathBuf::from("unused.cert"),
            key: PathBuf::from("unused.key"),
        };
        assert!(
            ForwardProxyConfig::new("0.0.0.0:8788".parse().unwrap(), &["api.example.com".into()], ca.clone()).is_err()
        );
        assert!(ForwardProxyConfig::new("127.0.0.1:8788".parse().unwrap(), &[], ca).is_err());
    }

    #[test]
    fn ca_generation_is_create_new_and_key_is_private() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        validate_ca_files(&paths).unwrap();
        assert!(generate_local_ca(&paths).is_err(), "must never overwrite CA material");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&paths.key).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    fn replace_ca_material(paths: &CaPaths, cert: &[u8], key: &[u8]) {
        fs::write(&paths.cert, cert).unwrap();
        fs::write(&paths.key, key).unwrap();
    }

    #[test]
    fn ca_loader_consumes_exactly_one_pem_block_and_rejects_garbage() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let cert = fs::read(&paths.cert).unwrap();
        let key = fs::read(&paths.key).unwrap();
        let cert_text = String::from_utf8(cert.clone()).unwrap();
        let key_text = String::from_utf8(key.clone()).unwrap();
        let rsa_cert_text = include_str!("../tests/fixtures/f4-rsa-ca.pem");

        replace_ca_material(
            &paths,
            format!("\n\t{cert_text}\r\n ").as_bytes(),
            format!(" \n{key_text}\t\n").as_bytes(),
        );
        validate_ca_files(&paths).expect("whitespace outside the sole PEM block is allowed");

        let cases = [
            (
                "duplicate certificate",
                format!("{cert_text}\n{cert_text}"),
                key_text.clone(),
            ),
            (
                "certificate chain",
                format!("{cert_text}\n{rsa_cert_text}"),
                key_text.clone(),
            ),
            (
                "leading certificate garbage",
                format!("not-pem\n{cert_text}"),
                key_text.clone(),
            ),
            (
                "trailing certificate garbage",
                format!("{cert_text}\nnot-pem"),
                key_text.clone(),
            ),
            (
                "wrong certificate tag",
                cert_text.replace("CERTIFICATE", "CERTIFICATE REQUEST"),
                key_text.clone(),
            ),
            (
                "duplicate private key",
                cert_text.clone(),
                format!("{key_text}\n{key_text}"),
            ),
            (
                "leading private-key garbage",
                cert_text.clone(),
                format!("not-pem\n{key_text}"),
            ),
            (
                "trailing private-key garbage",
                cert_text.clone(),
                format!("{key_text}\nnot-pem"),
            ),
            (
                "wrong private-key tag",
                cert_text.clone(),
                key_text.replace("PRIVATE KEY", "RSA PRIVATE KEY"),
            ),
        ];
        for (case, candidate_cert, candidate_key) in cases {
            replace_ca_material(&paths, candidate_cert.as_bytes(), candidate_key.as_bytes());
            assert!(validate_ca_files(&paths).is_err(), "accepted {case}");
        }

        replace_ca_material(&paths, b"random certificate bytes", &key);
        assert!(validate_ca_files(&paths).is_err(), "accepted random certificate bytes");
        let (_, parsed_cert) = x509_parser::pem::parse_x509_pem(&cert).unwrap();
        replace_ca_material(&paths, &parsed_cert.contents, &key);
        assert!(validate_ca_files(&paths).is_err(), "accepted raw certificate DER");
    }

    #[test]
    fn ca_loader_rejects_non_ca_and_cross_algorithm_mismatches() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let ec_cert = fs::read(&paths.cert).unwrap();
        let ec_key = fs::read(&paths.key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["not-a-ca.test".to_string()])
            .unwrap()
            .self_signed(&leaf_key)
            .unwrap();
        replace_ca_material(&paths, leaf.pem().as_bytes(), leaf_key.serialize_pem().as_bytes());
        assert!(
            validate_ca_files(&paths).unwrap_err().contains("not a CA"),
            "leaf certificate must be rejected"
        );

        let rsa_cert = include_bytes!("../tests/fixtures/f4-rsa-ca.pem");
        let rsa_key = include_bytes!("../tests/fixtures/f4-rsa-ca-key.pem");
        replace_ca_material(&paths, rsa_cert, rsa_key);
        validate_ca_files(&paths).expect("the RSA fixture must be a supported CA identity");

        replace_ca_material(&paths, &ec_cert, rsa_key);
        assert!(validate_ca_files(&paths).unwrap_err().contains("does not match"));
        replace_ca_material(&paths, rsa_cert, &ec_key);
        assert!(validate_ca_files(&paths).unwrap_err().contains("does not match"));
    }

    #[tokio::test]
    async fn mismatched_ca_pair_fails_closed_before_listener_bind() {
        let temp = tempfile::tempdir().unwrap();
        let paths_a = ca_paths(&temp.path().join("ca-a"));
        let paths_b = ca_paths(&temp.path().join("ca-b"));
        generate_local_ca(&paths_a).unwrap();
        generate_local_ca(&paths_b).unwrap();
        let mismatched = CaPaths {
            cert: paths_a.cert,
            key: paths_b.key,
        };

        let validation_error = validate_ca_files(&mismatched).unwrap_err();
        assert!(validation_error.contains("does not match"), "{validation_error}");

        let occupied_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_addr = occupied_listener.local_addr().unwrap();
        let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
        let cfg = ForwardProxyConfig::for_test(occupied_addr, &["api.allowed.test".to_string()], mismatched).unwrap();
        let Err(listener_error) = spawn_forward_proxy(cfg, ctx).await else {
            panic!("mismatched CA must fail before listener bind");
        };
        let listener_error = listener_error.to_string();
        assert!(listener_error.contains("does not match"), "{listener_error}");
        drop(occupied_listener);
    }

    #[cfg(unix)]
    #[test]
    fn insecure_ca_key_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        fs::set_permissions(&paths.key, fs::Permissions::from_mode(0o644)).unwrap();
        let error = validate_ca_files(&paths).unwrap_err();
        assert!(error.contains("0600"), "{error}");
    }

    #[test]
    fn oversized_ca_file_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        fs::write(&paths.cert, vec![b'x'; MAX_CA_FILE_BYTES as usize + 1]).unwrap();
        assert!(validate_ca_files(&paths).unwrap_err().contains("1 MiB"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ca_file_fails_closed() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        fs::remove_file(&paths.cert).unwrap();
        symlink(&paths.key, &paths.cert).unwrap();
        assert!(validate_ca_files(&paths).unwrap_err().contains("symlinks"));
    }

    async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
        let mut output = Vec::new();
        let mut byte = [0_u8; 1];
        while !output.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            output.push(byte[0]);
            assert!(output.len() < 8192);
        }
        output
    }

    async fn open_intercepted_tls(
        addr: SocketAddr,
        host: &str,
        paths: &CaPaths,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_head(&mut tcp).await;
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        let cert_pem = fs::read(&paths.cert).unwrap();
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut Cursor::new(cert_pem)) {
            roots.add(cert.unwrap()).unwrap();
        }
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from(host.to_string()).unwrap(), tcp)
            .await
            .unwrap()
    }

    async fn spawn_capturing_upstream() -> (SocketAddr, oneshot::Receiver<Vec<u8>>, JoinHandle<()>) {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            let (body_start, content_length) = loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read != 0, "upstream request ended before headers");
                bytes.extend_from_slice(&chunk[..read]);
                if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    let start = end + 4;
                    let headers = String::from_utf8_lossy(&bytes[..start]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap();
                    break (start, length);
                }
            };
            while bytes.len() < body_start + content_length {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read != 0, "upstream request body truncated");
                bytes.extend_from_slice(&chunk[..read]);
            }
            captured_tx.send(bytes[..body_start + content_length].to_vec()).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        (upstream_addr, captured_rx, task)
    }

    async fn send_intercepted_request(
        addr: SocketAddr,
        host: &str,
        paths: &CaPaths,
        path: &str,
        body: &str,
    ) -> Vec<u8> {
        let mut tls = open_intercepted_tls(addr, host, paths).await;
        tls.write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }

    #[tokio::test]
    async fn connect_tls_uses_host_certificate_and_blocks_without_leaking_secret() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let host = "api.hardcoded.test";
        let rule = make_test_rule("secret.test", &["SUPERSECRET-[0-9]{8}"]);
        let ctx = build_test_context(&[rule], HashMap::new(), OperationMode::Enforce);
        let cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &[host.to_string()], paths.clone()).unwrap();
        let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_head(&mut tcp).await;
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));

        let cert_pem = fs::read(&paths.cert).unwrap();
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut Cursor::new(cert_pem)) {
            roots.add(cert.unwrap()).unwrap();
        }
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client));
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        let secret = "SUPERSECRET-12345678";
        let body = format!(r#"{{"prompt":"{secret}"}}"#);
        tls.write_all(
            format!(
                "POST /v1/chat HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(!response.contains(secret), "raw secret leaked in response: {response}");

        handle.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn connect_tls_redacts_before_forwarding_and_audit_has_no_raw_secret() {
        use cerberus_engine::rule::Action;

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            let (body_start, content_length) = loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read != 0, "upstream request ended before headers");
                bytes.extend_from_slice(&chunk[..read]);
                if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    let start = end + 4;
                    let headers = String::from_utf8_lossy(&bytes[..start]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap();
                    break (start, length);
                }
            };
            while bytes.len() < body_start + content_length {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read != 0, "upstream request body truncated");
                bytes.extend_from_slice(&chunk[..read]);
            }
            captured_tx.send(bytes[..body_start + content_length].to_vec()).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let host = "api.hardcoded.test";
        let mut rule = make_test_rule("secret.test", &["TOKEN-[0-9]{8}"]);
        rule.action = Action::Redact;
        let ctx = build_test_context(&[rule], HashMap::new(), OperationMode::Enforce);
        let audit = ctx.api.events.clone();
        let mut cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &[host.to_string()], paths.clone()).unwrap();
        cfg.upstream_overrides
            .insert(host.to_string(), format!("http://{upstream_addr}"));
        let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();

        let mut tls = open_intercepted_tls(addr, host, &paths).await;
        let secret = "TOKEN-12345678";
        let body = format!(r#"{{"prompt":"{secret}"}}"#);
        tls.write_all(
            format!(
                "POST /api/stats HTTP/1.1\r\nHost: attacker.invalid\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

        let captured = captured_rx.await.unwrap();
        assert!(
            !String::from_utf8_lossy(&captured).contains("attacker.invalid"),
            "inner Host must not override the CONNECT-authorized destination"
        );
        let body_start = captured.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
        let forwarded = &captured[body_start..];
        assert!(!forwarded
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()));
        assert_ne!(forwarded, body.as_bytes(), "redaction must change the upstream body");
        {
            let events = audit.lock().await;
            assert_eq!(events.len(), 1);
            assert!(events[0].no_raw_values(&[secret]));
            drop(events);
        }

        upstream_task.await.unwrap();
        handle.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn connect_tls_shadow_forwards_original_and_records_redacted_audit_event() {
        use cerberus_engine::rule::Action;

        let (upstream_addr, captured_rx, upstream_task) = spawn_capturing_upstream().await;
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let host = "api.shadow.test";
        let secret = "SHADOW-TOKEN-12345678";
        let mut rule = make_test_rule("secret.shadow", &["SHADOW-TOKEN-[0-9]{8}"]);
        rule.action = Action::Redact;
        let ctx = build_test_context(&[rule], HashMap::new(), OperationMode::Shadow);
        let audit = ctx.api.events.clone();
        let mut cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &[host.to_string()], paths.clone()).unwrap();
        cfg.upstream_overrides
            .insert(host.to_string(), format!("http://{upstream_addr}"));
        let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();

        let body = format!(r#"{{"prompt":"{secret}"}}"#);
        let response = send_intercepted_request(addr, host, &paths, "/v1/chat", &body).await;
        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.starts_with("HTTP/1.1 200"), "{response_text}");
        assert!(
            !response_text.contains(secret),
            "shadow response leaked the raw finding"
        );

        let captured = captured_rx.await.unwrap();
        let body_start = captured.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(
            &captured[body_start..],
            body.as_bytes(),
            "shadow must pass the body through intact"
        );
        let events = audit.lock().await;
        assert_eq!(events.len(), 1, "shadow finding must be audited");
        assert!(events[0].no_raw_values(&[secret]));
        drop(events);

        upstream_task.await.unwrap();
        handle.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn connect_tls_invalid_json_obeys_closed_and_open_fail_policy_without_audit_leak() {
        let temp = tempfile::tempdir().unwrap();
        let host = "api.fail-policy.test";
        let secret = "INVALID-JSON-SECRET-12345678";
        let invalid_body = format!(r#"{{"prompt":"{secret}""#);

        for fail_policy in [FailPolicy::Closed, FailPolicy::Open] {
            let case_name = match fail_policy {
                FailPolicy::Closed => "closed",
                FailPolicy::Open => "open",
            };
            let paths = ca_paths(&temp.path().join(case_name));
            generate_local_ca(&paths).unwrap();
            let (upstream_addr, mut captured_rx, upstream_task) = spawn_capturing_upstream().await;
            let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
            ctx.config.write().unwrap().fail_policy = fail_policy;
            let audit = ctx.api.events.clone();
            let mut cfg =
                ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &[host.to_string()], paths.clone())
                    .unwrap();
            cfg.upstream_overrides
                .insert(host.to_string(), format!("http://{upstream_addr}"));
            let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();

            let response = send_intercepted_request(addr, host, &paths, "/v1/chat", &invalid_body).await;
            let response_text = String::from_utf8_lossy(&response);
            assert!(
                !response_text.contains(secret),
                "proxy response leaked invalid input: {response_text}"
            );
            match fail_policy {
                FailPolicy::Closed => {
                    assert!(response_text.starts_with("HTTP/1.1 502"), "{response_text}");
                    assert!(captured_rx.try_recv().is_err(), "closed policy forwarded invalid JSON");
                    upstream_task.abort();
                    let _ = upstream_task.await;
                }
                FailPolicy::Open => {
                    assert!(response_text.starts_with("HTTP/1.1 200"), "{response_text}");
                    let captured = captured_rx.await.unwrap();
                    let body_start = captured.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
                    assert_eq!(
                        &captured[body_start..],
                        invalid_body.as_bytes(),
                        "open policy must forward the original undecodable body"
                    );
                    upstream_task.await.unwrap();
                }
            }
            let events = audit.lock().await;
            assert!(events.iter().all(|event| event.no_raw_values(&[secret])));
            drop(events);
            handle.shutdown(Duration::from_secs(2)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn connect_tls_redaction_failure_obeys_closed_and_open_fail_policy_without_leak() {
        use cerberus_engine::rule::Action;

        let temp = tempfile::tempdir().unwrap();
        let host = "api.redact-failure.test";
        let block_secret = "BLOCK-SECRET-12345678";
        let redact_secret = "REDACT-SECRET-12345678";
        let body = format!(r#"{{"prompt":"{block_secret} {redact_secret}"}}"#);

        for fail_policy in [FailPolicy::Closed, FailPolicy::Open] {
            let case_name = match fail_policy {
                FailPolicy::Closed => "redact-closed",
                FailPolicy::Open => "redact-open",
            };
            let paths = ca_paths(&temp.path().join(case_name));
            generate_local_ca(&paths).unwrap();
            let (upstream_addr, mut captured_rx, upstream_task) = spawn_capturing_upstream().await;
            let block_rule = make_test_rule("secret.block", &["BLOCK-SECRET-[0-9]{8}"]);
            let mut redact_rule = make_test_rule("secret.redact", &["REDACT-SECRET-[0-9]{8}"]);
            redact_rule.action = Action::Redact;
            let ctx = build_test_context(&[block_rule, redact_rule], HashMap::new(), OperationMode::Enforce);
            {
                let mut config = ctx.config.write().unwrap();
                config.fail_policy = fail_policy;
                config.policy.allowlist = vec![block_secret.to_string()];
            }
            let audit = ctx.api.events.clone();
            let mut cfg =
                ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &[host.to_string()], paths.clone())
                    .unwrap();
            cfg.upstream_overrides
                .insert(host.to_string(), format!("http://{upstream_addr}"));
            let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();

            let response = send_intercepted_request(addr, host, &paths, "/v1/chat", &body).await;
            let response_text = String::from_utf8_lossy(&response);
            assert!(!response_text.contains(block_secret));
            assert!(!response_text.contains(redact_secret));
            match fail_policy {
                FailPolicy::Closed => {
                    assert!(response_text.starts_with("HTTP/1.1 502"), "{response_text}");
                    assert!(
                        captured_rx.try_recv().is_err(),
                        "closed policy forwarded after redaction failure"
                    );
                    upstream_task.abort();
                    let _ = upstream_task.await;
                }
                FailPolicy::Open => {
                    assert!(response_text.starts_with("HTTP/1.1 200"), "{response_text}");
                    let captured = captured_rx.await.unwrap();
                    let body_start = captured.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
                    assert_eq!(
                        &captured[body_start..],
                        body.as_bytes(),
                        "open policy must forward the original body after redaction failure"
                    );
                    upstream_task.await.unwrap();
                }
            }
            let events = audit.lock().await;
            assert!(events
                .iter()
                .all(|event| event.no_raw_values(&[block_secret, redact_secret])));
            drop(events);
            handle.shutdown(Duration::from_secs(2)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn connect_rejects_unlisted_host_wrong_port_and_plain_http() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
        let cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &["api.allowed.test".to_string()], paths)
                .unwrap();
        let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();

        for (request, status) in [
            (
                "CONNECT sub.api.allowed.test:443 HTTP/1.1\r\nHost: sub.api.allowed.test\r\n\r\n",
                "403",
            ),
            (
                "CONNECT api.allowed.test:8443 HTTP/1.1\r\nHost: api.allowed.test\r\n\r\n",
                "400",
            ),
            (
                "GET http://api.allowed.test/ HTTP/1.1\r\nHost: api.allowed.test\r\n\r\n",
                "405",
            ),
        ] {
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            tcp.write_all(request.as_bytes()).await.unwrap();
            let head = read_head(&mut tcp).await;
            assert!(String::from_utf8_lossy(&head).starts_with(&format!("HTTP/1.1 {status}")));
        }

        handle.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn connection_limit_covers_active_connect_tunnels_and_recovers_capacity() {
        const NETWORK_TUNNELS: usize = 16;

        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
        let cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &["api.allowed.test".to_string()], paths)
                .unwrap();
        let (addr, mut handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();
        // Reserve most slots directly so this lifecycle test remains safe to
        // repeat aggressively on kernels that throttle loopback churn. The
        // separate concurrent stress test admits all 128 real TCP tunnels.
        let reserved = handle
            .permits
            .clone()
            .acquire_many_owned((MAX_CONNECTIONS - NETWORK_TUNNELS) as u32)
            .await
            .unwrap();
        let mut held = Vec::with_capacity(NETWORK_TUNNELS);
        for index in 0..NETWORK_TUNNELS {
            let mut tunnel = TcpStream::connect(addr).await.unwrap_or_else(|error| {
                panic!(
                    "active CONNECT {index}/{NETWORK_TUNNELS} failed before admission: {error}; {:?}",
                    handle.test_snapshot()
                )
            });
            tunnel
                .write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\nHost: api.allowed.test:443\r\n\r\n")
                .await
                .unwrap();
            let head = read_head(&mut tunnel).await;
            assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
            held.push(tunnel);
        }
        handle.wait_until_active_tunnels(NETWORK_TUNNELS).await;
        let full = handle.test_snapshot();
        assert_eq!(full.accepted, NETWORK_TUNNELS, "{full:?}");
        assert_eq!(full.permits_acquired, NETWORK_TUNNELS, "{full:?}");
        assert_eq!(full.permits_available, 0, "{full:?}");
        assert_eq!(full.jobs_enqueued, NETWORK_TUNNELS, "{full:?}");
        assert_eq!(full.jobs_started, NETWORK_TUNNELS, "{full:?}");
        assert_eq!(full.active_tunnels, NETWORK_TUNNELS, "{full:?}");

        let mut excess = TcpStream::connect(addr).await.unwrap();
        let _ = excess
            .write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\nHost: api.allowed.test:443\r\n\r\n")
            .await;
        let mut response = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(1), excess.read_to_end(&mut response))
            .await
            .unwrap();
        assert!(
            read.is_err() || !String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "the 129th active CONNECT must be reset or rejected before service"
        );

        drop(held.pop());
        handle.wait_until_active_tunnels(NETWORK_TUNNELS - 1).await;
        let mut replacement = TcpStream::connect(addr).await.unwrap();
        replacement
            .write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\nHost: api.allowed.test:443\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut replacement).await;
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        held.push(replacement);
        handle.wait_until_active_tunnels(NETWORK_TUNNELS).await;

        drop(held);
        handle.wait_until_active_tunnels(0).await;
        assert_eq!(handle.permits.available_permits(), NETWORK_TUNNELS);
        drop(reserved);
        assert_eq!(handle.permits.available_permits(), MAX_CONNECTIONS);
        handle.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn nominal_connect_capacity_is_admitted_under_concurrent_stress() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
        let cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &["api.allowed.test".to_string()], paths)
                .unwrap();
        let (addr, mut handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();
        let start = Arc::new(tokio::sync::Barrier::new(MAX_CONNECTIONS + 1));
        let mut clients = JoinSet::new();
        for index in 0..MAX_CONNECTIONS {
            let start = start.clone();
            clients.spawn(async move {
                start.wait().await;
                let mut tunnel = TcpStream::connect(addr)
                    .await
                    .unwrap_or_else(|error| panic!("concurrent nominal CONNECT {index} failed: {error}"));
                tunnel
                    .write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\nHost: api.allowed.test:443\r\n\r\n")
                    .await
                    .unwrap();
                let head = read_head(&mut tunnel).await;
                assert!(
                    String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
                    "concurrent nominal CONNECT {index} was not admitted"
                );
                tunnel
            });
        }
        start.wait().await;

        let mut held = Vec::with_capacity(MAX_CONNECTIONS);
        while let Some(result) = clients.join_next().await {
            held.push(result.unwrap());
        }
        handle.wait_until_active_tunnels(MAX_CONNECTIONS).await;
        handle.test_state.wait_until_jobs_started(MAX_CONNECTIONS).await;
        let full = handle.test_snapshot();
        assert_eq!(full.accepted, MAX_CONNECTIONS, "{full:?}");
        assert_eq!(full.permits_acquired, MAX_CONNECTIONS, "{full:?}");
        assert_eq!(full.permits_available, 0, "{full:?}");
        assert_eq!(full.jobs_enqueued, MAX_CONNECTIONS, "{full:?}");
        assert_eq!(full.jobs_started, MAX_CONNECTIONS, "{full:?}");
        assert_eq!(full.active_tunnels, MAX_CONNECTIONS, "{full:?}");

        let permits = handle.permits.clone();
        drop(held);
        handle.wait_until_active_tunnels(0).await;
        assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
        handle.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_drains_a_tunnel_job_enqueued_before_it_can_start() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
        let cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &["api.allowed.test".to_string()], paths)
                .unwrap();
        let (addr, handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();
        handle.test_state.pause_job_starts.store(true, Ordering::Release);
        let permits = handle.permits.clone();
        let active_tunnels = handle.active_tunnels.clone();
        let test_state = handle.test_state.clone();

        let mut tunnel = TcpStream::connect(addr).await.unwrap();
        tunnel
            .write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\nHost: api.allowed.test:443\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut tunnel).await;
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        test_state.wait_until_jobs_enqueued(1).await;

        let queued = handle.test_snapshot();
        assert_eq!(queued.accepted, 1, "{queued:?}");
        assert_eq!(queued.permits_acquired, 1, "{queued:?}");
        assert_eq!(queued.permits_available, MAX_CONNECTIONS - 1, "{queued:?}");
        assert_eq!(queued.jobs_enqueued, 1, "{queued:?}");
        assert_eq!(
            queued.jobs_started, 0,
            "job escaped the deterministic queue barrier: {queued:?}"
        );
        assert_eq!(queued.jobs_completed, 0, "{queued:?}");
        assert_eq!(queued.active_tunnels, 1, "{queued:?}");

        handle.shutdown(Duration::from_secs(2)).await.unwrap();
        assert_eq!(test_state.jobs_started.load(Ordering::Acquire), 1);
        assert_eq!(test_state.jobs_completed.load(Ordering::Acquire), 1);
        assert_eq!(*active_tunnels.borrow(), 0);
        assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
        let mut byte = [0_u8; 1];
        assert_eq!(tunnel.read(&mut byte).await.unwrap_or(0), 0);
    }

    #[tokio::test]
    async fn shutdown_cancels_connect_stalled_before_client_hello() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        generate_local_ca(&paths).unwrap();
        let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
        let cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &["api.allowed.test".to_string()], paths)
                .unwrap();
        let (addr, mut handle) = spawn_forward_proxy(cfg, ctx).await.unwrap();
        let mut tunnel = TcpStream::connect(addr).await.unwrap();
        tunnel
            .write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\nHost: api.allowed.test:443\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut tunnel).await;
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        handle.wait_until_active_tunnels(1).await;

        handle.shutdown(Duration::from_millis(500)).await.unwrap();
        let mut byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_millis(500), tunnel.read(&mut byte))
            .await
            .expect("shutdown must close the stalled tunnel within its grace")
            .unwrap_or(0);
        assert_eq!(closed, 0, "stalled tunnel remained open after shutdown");
    }

    #[tokio::test]
    async fn missing_ca_prevents_listener_from_binding() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ca_paths(temp.path());
        let ctx = build_test_context(&[], HashMap::new(), OperationMode::Enforce);
        let cfg =
            ForwardProxyConfig::for_test("127.0.0.1:0".parse().unwrap(), &["api.allowed.test".to_string()], paths)
                .unwrap();
        assert!(spawn_forward_proxy(cfg, ctx).await.is_err());
    }
}
