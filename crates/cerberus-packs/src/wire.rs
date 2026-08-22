//! Contrato de cable (`wire`) del control plane de rule packs — v6.1.
//!
//! Este módulo es el ÚNICO lugar donde vive la forma de los mensajes que el
//! CLI (`cerberus pack …`) envía al control plane del daemon y de los datos
//! auxiliares que ambos comparten:
//!
//! * [`PackInstallRequest`]: install **por bytes del pack firmado**, nunca por
//!   path. El diseño anterior mandaba `{"path": "..."}`: el daemon abría ese
//!   path con SU cwd y SU usuario, lo que (a) rompía en cuanto CLI y daemon no
//!   compartían filesystem/cwd (Docker, remoto, `sudo`), y (b) convertía al
//!   control plane en un lector de archivos arbitrarios del host. El pack va
//!   ahora dentro del body y el daemon NUNCA interpreta rutas del cliente.
//! * [`ControlPlaneEndpoint`]: descriptor del endpoint efectivo que el daemon
//!   publica (`endpoint.json`) para que el CLI lo descubra sin adivinar el
//!   puerto. El CLI siempre habla contra loopback.
//!
//! Todos los parsers son *fail-safe*: un body vacío, demasiado grande, no
//! UTF-8, con versión de wire desconocida o con la forma legada `{"path":…}`
//! se rechaza con un [`PackWireError`] explícito, jamás con un default
//! silencioso.

use serde::{Deserialize, Serialize};

use crate::pack::SignedRulePack;

/// Ruta del control plane que lista packs (GET).
pub const PACK_LIST_PATH: &str = "/api/packs";
/// Ruta del control plane que instala un pack (POST, body [`PackInstallRequest`]).
pub const PACK_INSTALL_PATH: &str = "/api/packs/install";
/// Ruta del control plane que revierte la última activación (POST, sin body).
pub const PACK_ROLLBACK_PATH: &str = "/api/packs/rollback";

/// Versión del contrato de install. `1` era el legado por path (retirado); `2`
/// transporta los bytes del pack firmado.
pub const PACK_WIRE_VERSION: u32 = 2;

/// Tamaño máximo del body HTTP wire v2 (1 MiB), compartido con el control
/// plane para que ambos lados apliquen exactamente la misma cota.
pub const MAX_PACK_BODY_BYTES: usize = 1 << 20;

/// Tamaño máximo aceptado para el JSON del pack firmado (511.5 KiB).
///
/// Se reserva 1 KiB para los campos del envelope y se presupuestan hasta dos
/// bytes de envelope por byte del JSON firmado. La relación se vigila en los
/// tests del control plane: incluso el envelope máximo cabe en
/// [`MAX_PACK_BODY_BYTES`].
pub const MAX_PACK_BYTES: usize = (MAX_PACK_BODY_BYTES - 1024) / 2;

/// Longitud máxima del nombre de origen informativo.
pub const MAX_ORIGIN_NAME_LEN: usize = 128;

/// Nombre del archivo donde el daemon publica su endpoint efectivo, dentro del
/// directorio de configuración (`~/.cerberus/endpoint.json`).
pub const ENDPOINT_FILE: &str = "endpoint.json";

/// Fallo al construir o parsear un mensaje del contrato de packs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackWireError {
    /// El body o el pack venía vacío.
    Empty,
    /// Excede el máximo permitido.
    TooLarge {
        /// Bytes recibidos.
        got: usize,
        /// Máximo admitido.
        max: usize,
    },
    /// Los bytes no son UTF-8 válido (un pack firmado siempre es JSON UTF-8).
    NotUtf8,
    /// JSON inválido o campos inesperados (detalle adjunto).
    Malformed(String),
    /// Request legada `{"path": …}`: el control plane ya no resuelve rutas del
    /// cliente. El CLI debe enviar los bytes del pack.
    LegacyPathRequest,
    /// Versión de wire no soportada por este binario.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for PackWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "pack payload vacío"),
            Self::TooLarge { got, max } => {
                write!(f, "pack payload demasiado grande: {got} bytes (máximo {max})")
            }
            Self::NotUtf8 => write!(f, "pack payload no es UTF-8 válido"),
            Self::Malformed(detail) => write!(f, "pack payload inválido: {detail}"),
            Self::LegacyPathRequest => write!(
                f,
                "install por path retirado (wire v1): el control plane no abre rutas del cliente; \
                 envía los bytes del pack firmado en el campo 'pack' (wire v{PACK_WIRE_VERSION})"
            ),
            Self::UnsupportedVersion(v) => write!(
                f,
                "versión de wire no soportada: {v} (este binario habla v{PACK_WIRE_VERSION})"
            ),
        }
    }
}

impl std::error::Error for PackWireError {}

/// Versión por defecto cuando el campo falta (clientes v6.1 tempranos).
const fn default_wire_version() -> u32 {
    PACK_WIRE_VERSION
}

/// Request de `POST /api/packs/install`: los **bytes** del `SignedRulePack`.
///
/// `pack` es el JSON completo del pack firmado (el mismo contenido que el
/// archivo `.json` que el usuario pasó por CLI). `origin_name` es SOLO
/// informativo (logs/telemetría): es un basename saneado, sin separadores de
/// ruta, y el daemon NUNCA lo usa para abrir nada.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackInstallRequest {
    /// Versión del contrato (véase [`PACK_WIRE_VERSION`]).
    #[serde(default = "default_wire_version")]
    pub wire_version: u32,
    /// JSON del `SignedRulePack` a instalar.
    pub pack: String,
    /// Basename informativo del archivo de origen (nunca una ruta).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_name: Option<String>,
}

impl PackInstallRequest {
    /// Construir la request desde los bytes leídos por el CLI.
    ///
    /// Valida tamaño, UTF-8 y que el contenido sea un `SignedRulePack`
    /// estructuralmente válido (la firma la verifica el daemon contra SU trust
    /// root: el cliente no es autoridad de confianza).
    ///
    /// # Errors
    ///
    /// [`PackWireError`] si está vacío, excede [`MAX_PACK_BYTES`], no es UTF-8
    /// o no parsea como pack firmado.
    pub fn from_pack_bytes(bytes: &[u8], origin_name: Option<&str>) -> Result<Self, PackWireError> {
        if bytes.is_empty() {
            return Err(PackWireError::Empty);
        }
        if bytes.len() > MAX_PACK_BYTES {
            return Err(PackWireError::TooLarge {
                got: bytes.len(),
                max: MAX_PACK_BYTES,
            });
        }
        let pack = std::str::from_utf8(bytes).map_err(|_| PackWireError::NotUtf8)?;
        validate_signed_pack(pack)?;
        Ok(Self {
            wire_version: PACK_WIRE_VERSION,
            pack: pack.to_string(),
            origin_name: origin_name.and_then(sanitize_origin_name),
        })
    }

    /// Serializar la request al body HTTP.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] si la serialización falla.
    pub fn to_body(&self) -> Result<String, PackWireError> {
        serde_json::to_string(self).map_err(|e| PackWireError::Malformed(e.to_string()))
    }

    /// Parsear el body recibido por el control plane (lado servidor).
    ///
    /// Fail-safe: rechaza vacío, oversize, no-UTF-8, la forma legada
    /// `{"path": …}` y versiones de wire desconocidas.
    ///
    /// # Errors
    ///
    /// [`PackWireError`] con la causa exacta del rechazo.
    pub fn parse_body(body: &[u8]) -> Result<Self, PackWireError> {
        if body.is_empty() {
            return Err(PackWireError::Empty);
        }
        // El envelope JSON escapa el pack; la cota compartida también es la
        // que aplica el colector HTTP antes de llegar a este parser.
        if body.len() > MAX_PACK_BODY_BYTES {
            return Err(PackWireError::TooLarge {
                got: body.len(),
                max: MAX_PACK_BODY_BYTES,
            });
        }
        let text = std::str::from_utf8(body).map_err(|_| PackWireError::NotUtf8)?;
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| PackWireError::Malformed(e.to_string()))?;
        let obj = value
            .as_object()
            .ok_or_else(|| PackWireError::Malformed("se esperaba un objeto JSON".to_string()))?;
        if !obj.contains_key("pack") {
            if obj.contains_key("path") {
                return Err(PackWireError::LegacyPathRequest);
            }
            return Err(PackWireError::Malformed("falta el campo 'pack'".to_string()));
        }
        let req: Self = serde_json::from_value(value).map_err(|e| PackWireError::Malformed(e.to_string()))?;
        if req.wire_version != PACK_WIRE_VERSION {
            return Err(PackWireError::UnsupportedVersion(req.wire_version));
        }
        if req.pack.is_empty() {
            return Err(PackWireError::Empty);
        }
        if req.pack.len() > MAX_PACK_BYTES {
            return Err(PackWireError::TooLarge {
                got: req.pack.len(),
                max: MAX_PACK_BYTES,
            });
        }
        if let Some(origin) = req.origin_name.as_deref() {
            if sanitize_origin_name(origin).as_deref() != Some(origin) {
                return Err(PackWireError::Malformed(
                    "origin_name debe ser un basename sin separadores de ruta".to_string(),
                ));
            }
        }
        validate_signed_pack(&req.pack)?;
        Ok(req)
    }

    /// Deserializar el pack firmado transportado.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] si el JSON no es un `SignedRulePack`.
    pub fn signed_pack(&self) -> Result<SignedRulePack, PackWireError> {
        serde_json::from_str::<SignedRulePack>(&self.pack).map_err(|e| PackWireError::Malformed(e.to_string()))
    }

    /// Etiqueta para logs: el origen saneado o `<inline>`.
    #[must_use]
    pub fn origin_label(&self) -> &str {
        self.origin_name.as_deref().unwrap_or("<inline>")
    }
}

/// Validar que `json` es un `SignedRulePack` estructuralmente correcto.
fn validate_signed_pack(json: &str) -> Result<(), PackWireError> {
    let signed = serde_json::from_str::<SignedRulePack>(json).map_err(|e| PackWireError::Malformed(e.to_string()))?;
    if signed.pack_json.is_empty() || signed.signature_hex.is_empty() || signed.signer_public_key_hex.is_empty() {
        return Err(PackWireError::Malformed(
            "pack firmado incompleto (pack_json/signature_hex/signer_public_key_hex)".to_string(),
        ));
    }
    Ok(())
}

/// Reducir un nombre de archivo (posiblemente una ruta completa del cliente) a
/// un basename informativo seguro, o `None` si no queda nada usable.
///
/// Elimina toda semántica de ruta: separadores unix y windows, `.`/`..`, bytes
/// de control y nombres excesivamente largos.
#[must_use]
pub fn sanitize_origin_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
    if base.is_empty() || base == "." || base == ".." || base.len() > MAX_ORIGIN_NAME_LEN {
        return None;
    }
    if base
        .chars()
        .any(|c| c.is_control() || c == '/' || c == '\\' || c == '\0')
    {
        return None;
    }
    Some(base.to_string())
}

/// Puerto de un `listen` con forma `host:port` (soporta `[::1]:8787`).
#[must_use]
pub fn port_from_listen(listen: &str) -> Option<u16> {
    listen.trim().rsplit(':').next()?.trim().parse::<u16>().ok()
}

/// Endpoint efectivo del control plane, publicado por el daemon.
///
/// El daemon puede ligar en `0.0.0.0` (Docker) o en un puerto efímero; el CLI
/// necesita el puerto REAL, no el configurado. Este descriptor se escribe
/// atómicamente junto al pid file y el CLI lo lee; el `host` publicado es
/// informativo, la URL que usa el CLI es SIEMPRE loopback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneEndpoint {
    /// `listen` tal como el daemon lo ligó (informativo).
    pub listen: String,
    /// Puerto efectivo del control plane.
    pub port: u16,
    /// PID del daemon dueño de este endpoint (para detectar descriptores rancios).
    pub pid: u32,
}

impl ControlPlaneEndpoint {
    /// Construir el descriptor a partir del `listen` real y el pid del daemon.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] si `listen` no contiene un puerto válido.
    pub fn new(listen: &str, pid: u32) -> Result<Self, PackWireError> {
        let port = port_from_listen(listen)
            .ok_or_else(|| PackWireError::Malformed(format!("listen sin puerto válido: {listen}")))?;
        Ok(Self {
            listen: listen.trim().to_string(),
            port,
            pid,
        })
    }

    /// Serializar a JSON para `endpoint.json`.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] si la serialización falla.
    pub fn to_json(&self) -> Result<String, PackWireError> {
        serde_json::to_string(self).map_err(|e| PackWireError::Malformed(e.to_string()))
    }

    /// Parsear `endpoint.json` (fail-safe: puerto 0 se rechaza).
    ///
    /// # Errors
    ///
    /// [`PackWireError`] si el JSON es inválido o el puerto es 0.
    pub fn from_json(json: &str) -> Result<Self, PackWireError> {
        if json.trim().is_empty() {
            return Err(PackWireError::Empty);
        }
        let ep: Self = serde_json::from_str(json).map_err(|e| PackWireError::Malformed(e.to_string()))?;
        if ep.port == 0 {
            return Err(PackWireError::Malformed("puerto 0 en endpoint.json".to_string()));
        }
        Ok(ep)
    }

    /// URL base para el CLI: siempre loopback, nunca el host publicado.
    #[must_use]
    pub fn loopback_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SignedRulePack` mínimo válido estructuralmente (firma ficticia: la
    /// verificación criptográfica es del daemon, no del cliente).
    fn sample_signed_pack() -> String {
        serde_json::json!({
            "pack_json": r#"{"metadata":{"name":"demo","version":"1.0.0","description":"d","author":"a","published":"2026-01-01","min_engine_version":"0.1.0"},"rules":[]}"#,
            "signature_hex": "aa".repeat(64),
            "signer_public_key_hex": "bb".repeat(32),
        })
        .to_string()
    }

    #[test]
    fn install_request_roundtrips_bytes() {
        let pack = sample_signed_pack();
        let req = PackInstallRequest::from_pack_bytes(pack.as_bytes(), Some("/home/u/packs/demo.json"))
            .expect("request se construye");
        assert_eq!(req.wire_version, PACK_WIRE_VERSION);
        assert_eq!(req.origin_name.as_deref(), Some("demo.json"), "solo basename");

        let body = req.to_body().expect("serializa");
        let parsed = PackInstallRequest::parse_body(body.as_bytes()).expect("parsea");
        assert_eq!(parsed, req);
        let signed = parsed.signed_pack().expect("pack firmado");
        assert!(signed.pack_json.contains("demo"));
    }

    #[test]
    fn origin_name_absent_when_path_is_not_usable() {
        let pack = sample_signed_pack();
        for raw in ["..", ".", "/", "   ", "a/../"] {
            let req = PackInstallRequest::from_pack_bytes(pack.as_bytes(), Some(raw)).expect("request");
            assert!(req.origin_name.is_none(), "origen inseguro no debe viajar: {raw:?}");
        }
        let traversal =
            PackInstallRequest::from_pack_bytes(pack.as_bytes(), Some("../../../etc/shadow.json")).expect("request");
        assert_eq!(traversal.origin_name.as_deref(), Some("shadow.json"));
    }

    #[test]
    fn legacy_path_request_is_rejected_explicitly() {
        let body = serde_json::json!({ "path": "/tmp/pack.json" }).to_string();
        assert_eq!(
            PackInstallRequest::parse_body(body.as_bytes()),
            Err(PackWireError::LegacyPathRequest)
        );
        // Mensaje accionable para el operador.
        assert!(PackWireError::LegacyPathRequest.to_string().contains("bytes del pack"));
    }

    #[test]
    fn parse_body_fails_safe() {
        assert_eq!(PackInstallRequest::parse_body(b""), Err(PackWireError::Empty));
        assert_eq!(
            PackInstallRequest::parse_body(&[0xff, 0xfe, 0xfd]),
            Err(PackWireError::NotUtf8)
        );
        assert!(matches!(
            PackInstallRequest::parse_body(b"[1,2,3]"),
            Err(PackWireError::Malformed(_))
        ));
        assert!(matches!(
            PackInstallRequest::parse_body(br#"{"pack":"not-json"}"#),
            Err(PackWireError::Malformed(_))
        ));
        assert_eq!(
            PackInstallRequest::parse_body(br#"{"pack":"","wire_version":2}"#),
            Err(PackWireError::Empty)
        );
        let bad_version = serde_json::json!({ "wire_version": 99, "pack": sample_signed_pack() }).to_string();
        assert_eq!(
            PackInstallRequest::parse_body(bad_version.as_bytes()),
            Err(PackWireError::UnsupportedVersion(99))
        );
        let bad_origin = serde_json::json!({ "pack": sample_signed_pack(), "origin_name": "../../etc/x" }).to_string();
        assert!(matches!(
            PackInstallRequest::parse_body(bad_origin.as_bytes()),
            Err(PackWireError::Malformed(_))
        ));
    }

    #[test]
    fn oversize_pack_is_rejected_on_both_sides() {
        let big = vec![b'x'; MAX_PACK_BYTES + 1];
        assert!(matches!(
            PackInstallRequest::from_pack_bytes(&big, None),
            Err(PackWireError::TooLarge { .. })
        ));
        let body = serde_json::json!({ "pack": "x".repeat(MAX_PACK_BYTES + 1) }).to_string();
        assert!(matches!(
            PackInstallRequest::parse_body(body.as_bytes()),
            Err(PackWireError::TooLarge { .. })
        ));
    }

    #[test]
    fn incomplete_signed_pack_is_rejected() {
        let incomplete = serde_json::json!({
            "pack_json": "{}",
            "signature_hex": "",
            "signer_public_key_hex": "bb",
        })
        .to_string();
        assert!(matches!(
            PackInstallRequest::from_pack_bytes(incomplete.as_bytes(), None),
            Err(PackWireError::Malformed(_))
        ));
    }

    #[test]
    fn endpoint_descriptor_roundtrip_and_loopback() {
        let ep = ControlPlaneEndpoint::new("0.0.0.0:9931", 4242).expect("endpoint");
        assert_eq!(ep.port, 9931);
        assert_eq!(ep.loopback_base_url(), "http://127.0.0.1:9931");
        let json = ep.to_json().expect("json");
        assert_eq!(ControlPlaneEndpoint::from_json(&json).expect("parse"), ep);

        assert!(ControlPlaneEndpoint::new("sin-puerto", 1).is_err());
        assert_eq!(ControlPlaneEndpoint::from_json("   "), Err(PackWireError::Empty));
        assert!(matches!(
            ControlPlaneEndpoint::from_json(r#"{"listen":"x:0","port":0,"pid":1}"#),
            Err(PackWireError::Malformed(_))
        ));
        assert!(matches!(
            ControlPlaneEndpoint::from_json("{"),
            Err(PackWireError::Malformed(_))
        ));
    }

    #[test]
    fn port_from_listen_handles_ipv6_and_garbage() {
        assert_eq!(port_from_listen("127.0.0.1:8787"), Some(8787));
        assert_eq!(port_from_listen("[::1]:8080"), Some(8080));
        assert_eq!(port_from_listen(" 0.0.0.0:1 "), Some(1));
        assert_eq!(port_from_listen("8787"), Some(8787));
        assert_eq!(port_from_listen("host:notaport"), None);
        assert_eq!(port_from_listen(""), None);
    }
}
