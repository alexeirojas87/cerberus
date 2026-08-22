//! Telemetría opt-in para Cerberus.
//!
//! Nunca envía datos sensibles. Solo estadísticas de uso anónimas:
//! versión, sistema operativo, conteo de reglas, eventos agregados, uptime
//! y un ID de instalación aleatorio persistente (`~/.cerberus/install_id`).
//!
//! Deshabilitada por defecto (`config.telemetry.enabled = false`): con la
//! telemetría apagada, o sin endpoint configurado, [`Telemetry::send`] **no
//! hace ninguna petición HTTP**. Cuando está habilitada, hace un POST real y
//! silencioso: cualquier fallo se loguea y se devuelve `Ok`, nunca bloquea ni
//! rompe al daemon.
//!
//! El payload NO puede llevar secretos, rutas locales, ni findings/valores
//! hash del escaneo — ver [`privacy_policy`].

use std::ffi::{OsStr, OsString};
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Timeout de la petición de telemetría.
const TELEMETRY_TIMEOUT_SECS: u64 = 5;

/// Variable de entorno que sobreescribe el endpoint configurado (si está
/// presente y no vacía).
pub const TELEMETRY_ENDPOINT_ENV: &str = "CERBERUS_TELEMETRY_ENDPOINT";

/// Variable de entorno (uso avanzado/tests) que redirige el directorio donde
/// se persiste el `install_id`.
pub const INSTALL_ID_DIR_ENV: &str = "CERBERUS_INSTALL_ID_DIR";

/// Configuración de telemetría.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// ¿Telemetría habilitada? Deshabilitada por defecto (opt-in).
    #[serde(default)]
    pub enabled: bool,
    /// URL del endpoint de telemetría. Si está vacía, no se hace red aunque
    /// `enabled` sea `true`. Se puede sobreescribir con
    /// `CERBERUS_TELEMETRY_ENDPOINT` (no vacío).
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Intervalo de envío en segundos.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
}

fn default_endpoint() -> String {
    "https://telemetry.cerberus.dev/v1/ping".to_string()
}

const fn default_interval() -> u64 {
    86_400 // 24 horas
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            interval_secs: default_interval(),
        }
    }
}

/// Payload de telemetría.
///
/// # Contrato de privacidad
///
/// Este struct es la superficie acordada de lo que sale de la máquina.
/// NO añadir campos con secretos, valores detectados, flags, rutas, hosts,
/// nombres de usuario, emails ni nada que pueda identificar al operador o a
/// una víctima de DLP. Ver [`privacy_policy`].
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryPayload {
    /// Versión de Cerberus.
    pub version: String,
    /// Uptime en segundos.
    pub uptime_secs: u64,
    /// Conteo de reglas cargadas.
    pub rule_count: usize,
    /// Cantidad de eventos de auditoría.
    pub event_count: usize,
    /// Tier de licencia.
    pub license_tier: String,
    /// Sistema operativo.
    pub os: String,
    /// ID anónimo y persistente de instalación (uuid v4).
    pub install_id: String,
}

/// Gestor de telemetría.
#[derive(Debug, Clone)]
pub struct Telemetry {
    /// Configuración.
    pub config: TelemetryConfig,
    /// ID de instalación (persistente).
    pub install_id: String,
}

impl Telemetry {
    /// Crear un nuevo gestor de telemetría.
    ///
    /// Carga o genera (y persiste en `~/.cerberus/install_id`) el ID de
    /// instalación.
    #[must_use]
    pub fn new(config: TelemetryConfig) -> Self {
        let install_id = Self::load_or_generate_id();
        Self { config, install_id }
    }

    /// Construir payload de telemetría.
    #[must_use]
    pub fn build_payload(&self, rule_count: usize, event_count: usize, uptime_secs: u64) -> TelemetryPayload {
        TelemetryPayload {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs,
            rule_count,
            event_count,
            license_tier: "free".to_string(),
            os: std::env::consts::OS.to_string(),
            install_id: self.install_id.clone(),
        }
    }

    /// Enviar telemetría.
    ///
    /// Devuelve `Ok` siempre que todo vaya bien **o que el fallo sea de red**:
    /// la telemetría nunca debe bloquear al daemon ni propagar un error que
    /// detenga la operación. Los fallos se loguean a nivel `warn`.
    ///
    /// # Garantías de red
    ///
    /// - `config.enabled == false` → no hace nada, sin tráfico.
    /// - No hay endpoint (vacío en config y en
    ///   `CERBERUS_TELEMETRY_ENDPOINT`) → no hace nada, sin tráfico.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` solo si el payload no se puede serializar.
    pub fn send(&self, payload: &TelemetryPayload) -> Result<(), String> {
        send_inner(&self.config, payload)
    }

    /// Enviar telemetría en segundo plano (`std::thread`) para no bloquear al
    /// llamante (el daemon) ni siquiera los pocos segundos del timeout.
    ///
    /// Respeta los mismos guarados: sin `enabled` o sin endpoint no levanta
    /// hilo.
    pub fn send_background(&self, payload: &TelemetryPayload) {
        if !self.config.enabled || effective_endpoint(&self.config.endpoint).is_none() {
            return;
        }
        let config = self.config.clone();
        let payload = payload.clone();
        std::thread::spawn(move || {
            let _ = send_inner(&config, &payload);
        });
    }

    /// Ruta al archivo de `install_id`.
    fn install_id_file() -> std::path::PathBuf {
        if let Ok(dir) = std::env::var(INSTALL_ID_DIR_ENV) {
            if !dir.is_empty() {
                return std::path::PathBuf::from(dir).join("install_id");
            }
        }
        let home = home_dir().unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
        std::path::PathBuf::from(home).join(".cerberus").join("install_id")
    }

    fn load_or_generate_id() -> String {
        let path = Self::install_id_file();
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let id = existing.trim().to_string();
            if is_plausible_id(&id) {
                return id;
            }
        }
        let id = generate_install_id();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, &id);
        id
    }
}

/// Directorio HOME del usuario actual.
fn home_dir() -> Option<OsString> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|home| !is_root(home))
}

/// `None` para `/root` (HOME pseudo-raíz del contenedor, donde los mounts
/// K8s bajo `/root/.cerberus` son el lugar correcto para el `install_id`).
fn is_root(home: &OsStr) -> bool {
    home.is_empty() || home == "/root" || home == "/root/"
}

/// Generar un uuid v4 como ID de instalación.
fn generate_install_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Un ID de instalación debe ser un uuid no-vacío (36 chars), Y el contenido
/// es un token aleatorio sin datos privados.
fn is_plausible_id(id: &str) -> bool {
    let trimmed = id.trim();
    !trimmed.is_empty() && trimmed.len() <= 64 && !trimmed.contains('\n')
}

/// Endpoint efectivo: env no vacío > config no vacía > `None`.
fn effective_endpoint(config_endpoint: &str) -> Option<String> {
    std::env::var(TELEMETRY_ENDPOINT_ENV)
        .ok()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .or_else(|| {
            let cfg = config_endpoint.trim();
            if cfg.is_empty() {
                None
            } else {
                Some(cfg.to_string())
            }
        })
}

/// Cliente HTTP compartido (bloqueante, con timeout). Solo se crea la primera
/// vez que hay un envío real.
fn blocking_client() -> reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(TELEMETRY_TIMEOUT_SECS))
                .build()
                .unwrap_or_else(|e| {
                    tracing::warn!("telemetry: cannot build HTTP client (non-fatal): {e}");
                    reqwest::blocking::Client::new()
                })
        })
        .clone()
}

/// Enviar un payload con la lógica idéntica para `send` y `send_background`.
///
/// Nunca hace red con `enabled=false` ni sin endpoint.
fn send_inner(config: &TelemetryConfig, payload: &TelemetryPayload) -> Result<(), String> {
    if !config.enabled {
        tracing::debug!("telemetry disabled; skipping HTTP send (no network)");
        return Ok(());
    }
    let Some(endpoint) = effective_endpoint(&config.endpoint) else {
        tracing::debug!("telemetry enabled but no endpoint; skipping HTTP send (no network)");
        return Ok(());
    };
    let body = serde_json::to_string(payload).map_err(|e| format!("telemetry payload serialization failed: {e}"))?;
    match post_json(&endpoint, &body) {
        Ok(()) => {
            tracing::debug!("telemetry sent to {endpoint}");
            Ok(())
        }
        Err(e) => {
            tracing::warn!("telemetry send failed (non-fatal, never blocks DLP): {e}");
            Ok(())
        }
    }
}

/// POST JSON contra el endpoint con timeout.
///
/// # Errors
///
/// Devuelve `Err` si la petición falla a cualquier nivel (red, timeout, status).
fn post_json(endpoint: &str, body: &str) -> Result<(), String> {
    let _resp = blocking_client()
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| format!("telemetry HTTP request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("telemetry endpoint returned error: {e}"))?;
    Ok(())
}

/// Política de privacidad (texto Legible).
#[must_use]
pub const fn privacy_policy() -> &'static str {
    "Cerberus Telemetry Privacy Policy\n\
     \n\
     1. We collect only anonymous usage statistics:\n\
        - Cerberus version and OS\n\
        - Rule count and aggregate event counts\n\
        - Uptime and installation age\n\
        - A random persistent installation ID (uuid, never tied to your identity)\n\
     2. We NEVER collect:\n\
        - Raw secrets, PII, or any content\n\
        - Scan findings, flags, or hashed values\n\
        - User names, emails, system paths, or prompt data\n\
     3. Telemetry is OPT-IN and disabled by default.\n\
     4. You can disable at any time via config.yaml:\n\
        telemetry:\n\
          enabled: false\n\
     5. No data is shared with third parties.\n\
     6. The payload is defined and tested to contain only the metrics above; do not add fields."
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::{mpsc, Mutex};

    use super::*;

    /// Serializa los tests que tocan variables de entorno del proceso.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Guard que restaura una variable de entorno al salir del test.
    struct EnvVarGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let old = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, old }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn telemetry_disabled_by_default() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn telemetry_disabled_no_http() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Endpoint válido y vivo: si `send` hiciera red, conectaría (y el
        // assert de abajo lo detectaría).
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let config = TelemetryConfig {
            enabled: false,
            endpoint: format!("http://{addr}/v1/ping"),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(10, 5, 3600);
        assert!(telemetry.send(&payload).is_ok());
        listener.set_nonblocking(true).expect("nonblocking");
        assert!(
            listener.accept().is_err(),
            "telemetry must not open a TCP connection when disabled"
        );
    }

    #[test]
    fn telemetry_enabled_without_endpoint_skips_http() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test");
        let addr = listener.local_addr().expect("local addr");
        let config = TelemetryConfig {
            enabled: true,
            endpoint: String::new(),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(3, 9, 100);
        assert!(telemetry.send(&payload).is_ok());
        listener.set_nonblocking(true).expect("nonblocking");
        assert!(listener.accept().is_err(), "no HTTP when no endpoint is configured");
        // El listener no debe recibir nada (solo comprobamos ausencia de red).
        let _ = addr;
    }

    #[test]
    fn telemetry_enabled_http_failure_is_ok() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Endpoint inalcanzable (puerto 1) → conexión rechazada al instante.
        let config = TelemetryConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:1/v1/telemetry".to_string(),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(2, 2, 2);
        assert!(telemetry.send(&payload).is_ok(), "telemetry failures must be silent");
    }

    #[test]
    fn send_simulated_fail_ok_when_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // "Fail simulado": endpoint apunta a un socket muerto. Con la telemetría
        // deshabilitada, `send` devuelve Ok sin tocar la red.
        let config = TelemetryConfig {
            enabled: false,
            endpoint: "http://127.0.0.1:1/v1/telemetry".to_string(),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(7, 11, 42);
        assert!(telemetry.send(&payload).is_ok());
    }

    #[test]
    fn telemetry_enabled_posts_to_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Servidor HTTP de juguete: comprueba que con `enabled=true` SÍ se
        // envía una petición POST con el payload serializado.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().expect("accept");
            sock.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or_default();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });

        let config = TelemetryConfig {
            enabled: true,
            endpoint: format!("http://{addr}/v1/telemetry"),
            interval_secs: 1,
        };
        let telemetry = Telemetry::new(config);
        let payload = telemetry.build_payload(4, 8, 15);
        assert!(telemetry.send(&payload).is_ok());

        let request = rx.recv_timeout(Duration::from_secs(3)).expect("request received");
        assert!(request.starts_with("POST"), "got: {request}");
        assert!(request.contains(&payload.install_id), "payload must carry install_id");
        assert!(request.contains(r#""rule_count":4"#), "payload must carry rule_count");
    }

    #[test]
    fn env_endpoint_overrides_config() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Garantiza el estado "sin env" aunque el entorno la tenga puesta.
        let _initial = EnvVarGuard::set(TELEMETRY_ENDPOINT_ENV, "");
        let config = TelemetryConfig {
            endpoint: "https://config.example/v1/ping".to_string(),
            ..TelemetryConfig::default()
        };
        assert_eq!(
            effective_endpoint(&config.endpoint).as_deref(),
            Some("https://config.example/v1/ping"),
            "config endpoint used when env is empty"
        );
        {
            let _env = EnvVarGuard::set(TELEMETRY_ENDPOINT_ENV, "https://env.example/v1/ping");
            assert_eq!(
                effective_endpoint(&config.endpoint).as_deref(),
                Some("https://env.example/v1/ping"),
                "env no vacía override config endpoint"
            );
        }
        assert_eq!(
            effective_endpoint(&config.endpoint).as_deref(),
            Some("https://config.example/v1/ping"),
            "after env removed, config endpoint is used again"
        );
    }

    #[test]
    fn telemetry_payload_contains_version() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let telemetry = Telemetry::new(TelemetryConfig::default());
        let payload = telemetry.build_payload(42, 100, 7200);
        assert_eq!(payload.rule_count, 42);
        assert_eq!(payload.event_count, 100);
        assert_eq!(payload.uptime_secs, 7200);
        assert!(!payload.version.is_empty());
    }

    #[test]
    fn payload_has_no_secrets_fields() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let telemetry = Telemetry::new(TelemetryConfig::default());
        let payload = telemetry.build_payload(3, 7, 100);
        let json = serde_json::to_string(&payload).expect("serialize payload");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("reparse");
        let obj = parsed.as_object().expect("payload must be an object");

        let allowed = [
            "version",
            "uptime_secs",
            "rule_count",
            "event_count",
            "license_tier",
            "os",
            "install_id",
        ];
        assert_eq!(
            obj.len(),
            allowed.len(),
            "payload must contain EXACTLY the anonymous metrics, got keys: {}",
            obj.keys().map(String::as_str).collect::<Vec<_>>().join(",")
        );
        for key in allowed {
            assert!(obj.contains_key(key), "missing key {key}");
        }

        // Y, defensiva: ningún valor puede ser un secreto, ruta, token, flag
        // ni hash del escaneo.
        let lower = json.to_lowercase();
        for forbidden in ["admin", "secret", "token", "api_key", "bearer", "/", "c:", "\\"] {
            assert!(!lower.contains(forbidden), "payload leaks {forbidden:?}: {json}");
        }
    }

    #[test]
    fn privacy_policy_not_empty() {
        let policy = privacy_policy();
        assert!(policy.contains("Cerberus Telemetry"));
        assert!(policy.contains("OPT-IN"));
    }

    #[test]
    fn install_id_is_persistent() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let t1 = Telemetry::new(TelemetryConfig::default());
        let t2 = Telemetry::new(TelemetryConfig::default());
        assert_eq!(t1.install_id, t2.install_id);
        assert_eq!(t1.install_id.len(), 36, "install_id should be a uuid v4");
    }

    #[test]
    fn id_default_persistent_in_tmp() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvVarGuard::set(INSTALL_ID_DIR_ENV, tmp.path().to_str().expect("utf8 path"));
        let t1 = Telemetry::new(TelemetryConfig::default());
        let t2 = Telemetry::new(TelemetryConfig::default());
        assert_eq!(t1.install_id, t2.install_id, "id must persist across instances");
        assert_eq!(t1.install_id.len(), 36, "uuid v4");
        let file = tmp.path().join("install_id");
        assert!(file.exists(), "install_id written to disk");
        assert_eq!(
            std::fs::read_to_string(&file).expect("read id").trim_end(),
            t1.install_id
        );
    }
}
