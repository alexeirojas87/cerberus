//! Schema adapters opcionales (§4.2 del build plan).
//!
//! Para proveedores conocidos (`OpenAI`, `Anthropic`), estos adaptadores
//! acotan el escaneo a los campos de mensajes relevantes, reduciendo
//! falsos positivos.

use serde_json::Value;

/// Resultado de aplicar un adaptador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptedBody {
    /// Texto extraído de los campos relevantes.
    pub text: String,
    /// Nombre del adaptador usado.
    pub adapter_name: String,
}

/// Adaptador de esquema: extrae solo los campos relevantes para escaneo.
pub trait SchemaAdapter: std::fmt::Debug {
    /// Nombre del adaptador.
    fn name(&self) -> &'static str;
    /// Extraer texto relevante del JSON, o `None` si no aplica.
    fn extract(&self, json: &Value) -> Option<AdaptedBody>;
}

/// Adaptador para APIs estilo `OpenAI` (chat completions, messages array).
///
/// Extrae `messages[].content` y `prompt` para escaneo acotado.
#[derive(Debug)]
pub struct OpenAIAdapter;

impl SchemaAdapter for OpenAIAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn extract(&self, json: &Value) -> Option<AdaptedBody> {
        let mut texts: Vec<String> = Vec::new();

        // messages[].content
        if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
            for msg in messages {
                if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                    texts.push(content.to_string());
                }
            }
        }

        // prompt field (for completions API)
        if let Some(prompt) = json.get("prompt").and_then(|v| v.as_str()) {
            texts.push(prompt.to_string());
        }

        if texts.is_empty() {
            return None;
        }

        Some(AdaptedBody {
            text: texts.join(" "),
            adapter_name: self.name().to_string(),
        })
    }
}

/// Adaptador para Anthropic (Claude) API.
///
/// Extrae `messages[].content` (estilo Anthropic).
#[derive(Debug)]
pub struct AnthropicAdapter;

impl SchemaAdapter for AnthropicAdapter {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn extract(&self, json: &Value) -> Option<AdaptedBody> {
        let mut texts: Vec<String> = Vec::new();

        if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
            for msg in messages {
                if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                    texts.push(content.to_string());
                }
            }
        }

        if texts.is_empty() {
            return None;
        }

        Some(AdaptedBody {
            text: texts.join(" "),
            adapter_name: self.name().to_string(),
        })
    }
}

/// Aplicar adaptadores conocidos al JSON.
///
/// Devuelve el primer adaptador que matchea, o `None` si ninguno aplica.
#[must_use]
pub fn try_adapt(json: &Value) -> Option<AdaptedBody> {
    let adapters: [&dyn SchemaAdapter; 2] = [&OpenAIAdapter, &AnthropicAdapter];
    for adapter in &adapters {
        if let Some(result) = adapter.extract(json) {
            return Some(result);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_extracts_messages_content() {
        let json: Value =
            serde_json::from_str(r#"{"messages":[{"role":"user","content":"my key is sk-abc123"}]}"#).unwrap();
        let result = OpenAIAdapter.extract(&json).unwrap();
        assert_eq!(result.adapter_name, "openai");
        assert!(result.text.contains("sk-abc123"));
    }

    #[test]
    fn openai_extracts_prompt() {
        let json: Value = serde_json::from_str(r#"{"prompt":"my token is secret","max_tokens":100}"#).unwrap();
        let result = OpenAIAdapter.extract(&json).unwrap();
        assert!(result.text.contains("secret"));
    }

    #[test]
    fn openai_no_match_returns_none() {
        let json: Value = serde_json::from_str(r#"{"model":"gpt-4","temperature":0}"#).unwrap();
        assert!(OpenAIAdapter.extract(&json).is_none());
    }

    #[test]
    fn anthropic_extracts_messages() {
        let json: Value =
            serde_json::from_str(r#"{"messages":[{"role":"user","content":"my secret is sk-xyz"}]}"#).unwrap();
        let result = AnthropicAdapter.extract(&json).unwrap();
        assert_eq!(result.adapter_name, "anthropic");
        assert!(result.text.contains("sk-xyz"));
    }

    #[test]
    fn anthropic_no_match() {
        let json: Value = serde_json::from_str(r#"{"model":"claude-3"}"#).unwrap();
        assert!(AnthropicAdapter.extract(&json).is_none());
    }

    #[test]
    fn try_adapt_prefers_openai() {
        let json: Value =
            serde_json::from_str(r#"{"messages":[{"role":"user","content":"secret-1"}],"prompt":"secret-2"}"#).unwrap();
        let result = try_adapt(&json).unwrap();
        assert_eq!(result.adapter_name, "openai");
    }

    #[test]
    fn try_adapt_fallback_to_agnostic() {
        let json: Value = serde_json::from_str(r#"{"unrelated":42}"#).unwrap();
        assert!(try_adapt(&json).is_none());
    }

    #[test]
    fn openai_multiple_messages() {
        let json: Value = serde_json::from_str(
            r#"{"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"world"}]}"#,
        )
        .unwrap();
        let result = OpenAIAdapter.extract(&json).unwrap();
        assert!(result.text.contains("hello"));
        assert!(result.text.contains("world"));
    }
}
