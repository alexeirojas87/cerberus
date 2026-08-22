//! Wire contract for the rule pack control plane — v6.1.
//!
//! This module is the ONLY place where the shape of the messages the CLI
//! (`cerberus pack …`) sends to the daemon's control plane lives, and of the
//! auxiliary data both share:
//!
//! * [`PackInstallRequest`]: install **by signed pack bytes**, never by path.
//!   The previous design sent `{"path": "..."}`: the daemon opened that path
//!   with ITS cwd and ITS user, which (a) broke as soon as CLI and daemon did
//!   not share filesystem/cwd (Docker, remote, `sudo`), and (b) turned the
//!   control plane into an arbitrary file reader on the host. The pack now
//!   travels inside the body and the daemon NEVER interprets client paths.
//! * [`ControlPlaneEndpoint`]: descriptor of the effective endpoint the daemon
//!   publishes (`endpoint.json`) so the CLI can discover it without guessing
//!   the port. The CLI always talks to loopback.
//!
//! All parsers are *fail-safe*: an empty, too-large, non-UTF-8 body, with an
//! unknown wire version or with the legacy `{"path":…}` shape is rejected
//! with an explicit [`PackWireError`], never with a silent default.

use serde::{Deserialize, Serialize};

use crate::pack::SignedRulePack;

/// Control plane route that lists packs (GET).
pub const PACK_LIST_PATH: &str = "/api/packs";
/// Control plane route that installs a pack (POST, body [`PackInstallRequest`]).
pub const PACK_INSTALL_PATH: &str = "/api/packs/install";
/// Control plane route that reverts the last activation (POST, no body).
pub const PACK_ROLLBACK_PATH: &str = "/api/packs/rollback";

/// Install contract version. `1` was the legacy by-path one (retired); `2`
/// carries the signed pack bytes.
pub const PACK_WIRE_VERSION: u32 = 2;

/// Maximum HTTP wire v2 body size (1 MiB), shared with the control plane so
/// both sides apply exactly the same bound.
pub const MAX_PACK_BODY_BYTES: usize = 1 << 20;

/// Maximum accepted size for the signed pack JSON (511.5 KiB).
///
/// 1 KiB is reserved for envelope fields and up to two envelope bytes per
/// byte of signed JSON are budgeted. The ratio is monitored in the control
/// plane tests: even the maximum envelope fits in [`MAX_PACK_BODY_BYTES`].
pub const MAX_PACK_BYTES: usize = (MAX_PACK_BODY_BYTES - 1024) / 2;

/// Maximum length of the informative origin name.
pub const MAX_ORIGIN_NAME_LEN: usize = 128;

/// Name of the file where the daemon publishes its effective endpoint, inside
/// the config directory (`~/.cerberus/endpoint.json`).
pub const ENDPOINT_FILE: &str = "endpoint.json";

/// Failure to build or parse a pack contract message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackWireError {
    /// The body or pack was empty.
    Empty,
    /// Exceeds the allowed maximum.
    TooLarge {
        /// Bytes received.
        got: usize,
        /// Maximum accepted.
        max: usize,
    },
    /// The bytes are not valid UTF-8 (a signed pack is always UTF-8 JSON).
    NotUtf8,
    /// Invalid JSON or unexpected fields (detail attached).
    Malformed(String),
    /// Legacy `{"path": …}` request: the control plane no longer resolves
    /// client paths. The CLI must send the pack bytes.
    LegacyPathRequest,
    /// Wire version not supported by this binary.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for PackWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "pack payload empty"),
            Self::TooLarge { got, max } => {
                write!(f, "pack payload too large: {got} bytes (maximum {max})")
            }
            Self::NotUtf8 => write!(f, "pack payload is not valid UTF-8"),
            Self::Malformed(detail) => write!(f, "pack payload invalid: {detail}"),
            Self::LegacyPathRequest => write!(
                f,
                "install by path retired (wire v1): the control plane does not open client paths; \
                 send the signed pack bytes in the 'pack' field (wire v{PACK_WIRE_VERSION})"
            ),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported wire version: {v} (this binary speaks v{PACK_WIRE_VERSION})"
            ),
        }
    }
}

impl std::error::Error for PackWireError {}

/// Default version when the field is missing (early v6.1 clients).
const fn default_wire_version() -> u32 {
    PACK_WIRE_VERSION
}

/// `POST /api/packs/install` request: the **bytes** of the `SignedRulePack`.
///
/// `pack` is the full JSON of the signed pack (the same content as the `.json`
/// file the user passed on the CLI). `origin_name` is ONLY informative
/// (logs/telemetry): it is a sanitized basename, without path separators, and
/// the daemon NEVER uses it to open anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackInstallRequest {
    /// Contract version (see [`PACK_WIRE_VERSION`]).
    #[serde(default = "default_wire_version")]
    pub wire_version: u32,
    /// JSON of the `SignedRulePack` to install.
    pub pack: String,
    /// Informative basename of the source file (never a path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_name: Option<String>,
}

impl PackInstallRequest {
    /// Build the request from the bytes read by the CLI.
    ///
    /// Validates size, UTF-8 and that the content is a structurally valid
    /// `SignedRulePack` (the signature is verified by the daemon against ITS
    /// trust root: the client is not a trust authority).
    ///
    /// # Errors
    ///
    /// [`PackWireError`] if it is empty, exceeds [`MAX_PACK_BYTES`], is not
    /// UTF-8 or does not parse as a signed pack.
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

    /// Serialize the request to the HTTP body.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] if serialization fails.
    pub fn to_body(&self) -> Result<String, PackWireError> {
        serde_json::to_string(self).map_err(|e| PackWireError::Malformed(e.to_string()))
    }

    /// Parse the body received by the control plane (server side).
    ///
    /// Fail-safe: rejects empty, oversize, non-UTF-8, the legacy
    /// `{"path": …}` shape and unknown wire versions.
    ///
    /// # Errors
    ///
    /// [`PackWireError`] with the exact rejection reason.
    pub fn parse_body(body: &[u8]) -> Result<Self, PackWireError> {
        if body.is_empty() {
            return Err(PackWireError::Empty);
        }
        // The JSON envelope escapes the pack; the shared bound is also the
        // one applied by the HTTP collector before reaching this parser.
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
            .ok_or_else(|| PackWireError::Malformed("expected a JSON object".to_string()))?;
        if !obj.contains_key("pack") {
            if obj.contains_key("path") {
                return Err(PackWireError::LegacyPathRequest);
            }
            return Err(PackWireError::Malformed("missing 'pack' field".to_string()));
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
                    "origin_name must be a basename without path separators".to_string(),
                ));
            }
        }
        validate_signed_pack(&req.pack)?;
        Ok(req)
    }

    /// Deserialize the transported signed pack.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] if the JSON is not a `SignedRulePack`.
    pub fn signed_pack(&self) -> Result<SignedRulePack, PackWireError> {
        serde_json::from_str::<SignedRulePack>(&self.pack).map_err(|e| PackWireError::Malformed(e.to_string()))
    }

    /// Label for logs: the sanitized origin or `<inline>`.
    #[must_use]
    pub fn origin_label(&self) -> &str {
        self.origin_name.as_deref().unwrap_or("<inline>")
    }
}

/// Validate that `json` is a structurally correct `SignedRulePack`.
fn validate_signed_pack(json: &str) -> Result<(), PackWireError> {
    let signed = serde_json::from_str::<SignedRulePack>(json).map_err(|e| PackWireError::Malformed(e.to_string()))?;
    if signed.pack_json.is_empty() || signed.signature_hex.is_empty() || signed.signer_public_key_hex.is_empty() {
        return Err(PackWireError::Malformed(
            "incomplete signed pack (pack_json/signature_hex/signer_public_key_hex)".to_string(),
        ));
    }
    Ok(())
}

/// Reduce a file name (possibly a full client path) to a safe informative
/// basename, or `None` if nothing usable remains.
///
/// Strips all path semantics: unix and windows separators, `.`/`..`, control
/// bytes and overly long names.
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

/// Port of a `listen` with the form `host:port` (supports `[::1]:8787`).
#[must_use]
pub fn port_from_listen(listen: &str) -> Option<u16> {
    listen.trim().rsplit(':').next()?.trim().parse::<u16>().ok()
}

/// Effective control plane endpoint, published by the daemon.
///
/// The daemon may bind on `0.0.0.0` (Docker) or on an ephemeral port; the CLI
/// needs the REAL port, not the configured one. This descriptor is written
/// atomically alongside the pid file and the CLI reads it; the published
/// `host` is informative, the URL the CLI uses is ALWAYS loopback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneEndpoint {
    /// `listen` as the daemon bound it (informative).
    pub listen: String,
    /// Effective control plane port.
    pub port: u16,
    /// PID of the daemon owning this endpoint (to detect stale descriptors).
    pub pid: u32,
}

impl ControlPlaneEndpoint {
    /// Build the descriptor from the real `listen` and the daemon pid.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] if `listen` does not contain a valid port.
    pub fn new(listen: &str, pid: u32) -> Result<Self, PackWireError> {
        let port = port_from_listen(listen)
            .ok_or_else(|| PackWireError::Malformed(format!("listen without valid port: {listen}")))?;
        Ok(Self {
            listen: listen.trim().to_string(),
            port,
            pid,
        })
    }

    /// Serialize to JSON for `endpoint.json`.
    ///
    /// # Errors
    ///
    /// [`PackWireError::Malformed`] if serialization fails.
    pub fn to_json(&self) -> Result<String, PackWireError> {
        serde_json::to_string(self).map_err(|e| PackWireError::Malformed(e.to_string()))
    }

    /// Parse `endpoint.json` (fail-safe: port 0 is rejected).
    ///
    /// # Errors
    ///
    /// [`PackWireError`] if the JSON is invalid or the port is 0.
    pub fn from_json(json: &str) -> Result<Self, PackWireError> {
        if json.trim().is_empty() {
            return Err(PackWireError::Empty);
        }
        let ep: Self = serde_json::from_str(json).map_err(|e| PackWireError::Malformed(e.to_string()))?;
        if ep.port == 0 {
            return Err(PackWireError::Malformed("port 0 in endpoint.json".to_string()));
        }
        Ok(ep)
    }

    /// Base URL for the CLI: always loopback, never the published host.
    #[must_use]
    pub fn loopback_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal structurally valid `SignedRulePack` (dummy signature: the
    /// cryptographic verification is the daemon's, not the client's).
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
            .expect("request builds");
        assert_eq!(req.wire_version, PACK_WIRE_VERSION);
        assert_eq!(req.origin_name.as_deref(), Some("demo.json"), "basename only");

        let body = req.to_body().expect("serializes");
        let parsed = PackInstallRequest::parse_body(body.as_bytes()).expect("parses");
        assert_eq!(parsed, req);
        let signed = parsed.signed_pack().expect("signed pack");
        assert!(signed.pack_json.contains("demo"));
    }

    #[test]
    fn origin_name_absent_when_path_is_not_usable() {
        let pack = sample_signed_pack();
        for raw in ["..", ".", "/", "   ", "a/../"] {
            let req = PackInstallRequest::from_pack_bytes(pack.as_bytes(), Some(raw)).expect("request");
            assert!(req.origin_name.is_none(), "unsafe origin must not travel: {raw:?}");
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
        // Actionable message for the operator.
        assert!(PackWireError::LegacyPathRequest.to_string().contains("pack bytes"));
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

        assert!(ControlPlaneEndpoint::new("no-port", 1).is_err());
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
