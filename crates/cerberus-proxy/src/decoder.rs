//! Provider-agnostic body decoder (§4.2 del build plan).
//!
//! Decodifica el body del request (JSON/text) y extrae todo
//! el contenido textual para escanear. Es agnóstico por construcción:
//! funciona con cualquier proveedor LLM.

use bytes::Bytes;

/// Resultado de decodificar un body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody {
    /// Todo el contenido textual extraído para escaneo.
    pub text: String,
    /// Tipo de contenido detectado.
    pub content_type: ContentType,
}

/// Tipo de contenido del body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// JSON body (más común en APIs LLM).
    Json,
    /// Plain text.
    Text,
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Text => f.write_str("text"),
        }
    }
}

/// Decodificar un body en `DecodedBody`.
///
/// Estrategia (§4.2):
/// 1. Si es JSON, serializar todo el JSON a string (esto extrae todos los
///    campos de texto, independientemente del esquema del proveedor).
/// 2. Si no es JSON, tratarlo como texto plano.
/// 3. El texto extraído se pasa al motor de detección.
#[must_use]
pub fn decode(body: &Bytes, _content_type_hint: Option<&str>) -> DecodedBody {
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
        let text = json_to_string(&json);
        return DecodedBody {
            text,
            content_type: ContentType::Json,
        };
    }

    let text = String::from_utf8_lossy(body).to_string();
    DecodedBody {
        text,
        content_type: ContentType::Text,
    }
}

/// Extraer todo el texto de un JSON Value de forma recursiva.
fn json_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => {
            let mut parts: Vec<String> = arr.iter().map(json_to_string).collect();
            parts.retain(|p| !p.is_empty());
            parts.join(" ")
        }
        serde_json::Value::Object(obj) => {
            let mut parts: Vec<String> = obj.values().map(json_to_string).collect();
            parts.retain(|p| !p.is_empty());
            parts.join(" ")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_json_object() {
        let body = Bytes::from(r#"{"prompt":"my api key is sk-abc123","user":"alice"}"#);
        let decoded = decode(&body, None);
        assert_eq!(decoded.content_type, ContentType::Json);
        assert!(decoded.text.contains("sk-abc123"));
        assert!(decoded.text.contains("alice"));
    }

    #[test]
    fn decode_json_array() {
        let body = Bytes::from(r#"[{"role":"user","content":"hello"},{"role":"assistant","content":"hi"}]"#);
        let decoded = decode(&body, None);
        assert_eq!(decoded.content_type, ContentType::Json);
        assert!(decoded.text.contains("hello"));
        assert!(decoded.text.contains("hi"));
    }

    #[test]
    fn decode_json_nested() {
        let body = Bytes::from(r#"{"messages":[{"role":"user","content":"my token is sk-secret"}]}"#);
        let decoded = decode(&body, None);
        assert!(decoded.text.contains("sk-secret"));
    }

    #[test]
    fn decode_plain_text() {
        let body = Bytes::from("this is plain text with a secret api_key=abc123");
        let decoded = decode(&body, None);
        assert_eq!(decoded.content_type, ContentType::Text);
        assert!(decoded.text.contains("api_key=abc123"));
    }

    #[test]
    fn decode_empty_body() {
        let body = Bytes::from("");
        let decoded = decode(&body, None);
        assert!(decoded.text.is_empty());
    }

    #[test]
    fn decode_json_ignores_numbers_and_bools() {
        let body = Bytes::from(r#"{"count":42,"active":true,"name":"secret"}"#);
        let decoded = decode(&body, None);
        assert!(!decoded.text.contains("42"));
        assert!(!decoded.text.contains("true"));
        assert!(decoded.text.contains("secret"));
    }

    #[test]
    fn decode_invalid_utf8_fallback() {
        let body = Bytes::copy_from_slice(&[0xff, 0xfe, 0x00]);
        let decoded = decode(&body, None);
        assert!(!decoded.text.is_empty());
    }

    #[test]
    fn content_type_display() {
        assert_eq!(ContentType::Json.to_string(), "json");
        assert_eq!(ContentType::Text.to_string(), "text");
    }
}
