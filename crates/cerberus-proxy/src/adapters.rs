//! Optional schema adapters (§4.2 of the build plan).
//!
//! For known providers (`OpenAI`, `Anthropic`), these adapters narrow the
//! scan to the relevant message fields, reducing false positives.

use serde_json::Value;

/// Result of applying an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptedBody {
    /// Text extracted from the relevant fields.
    pub text: String,
    /// Name of the adapter used.
    pub adapter_name: String,
}

/// Schema adapter: extracts only the fields relevant for scanning.
pub trait SchemaAdapter: std::fmt::Debug {
    /// Name of the adapter.
    fn name(&self) -> &'static str;
    /// Extract relevant text from the JSON, or `None` if it does not apply.
    fn extract(&self, json: &Value) -> Option<AdaptedBody>;
}

/// Adapter for `OpenAI`-style APIs (chat completions, messages array).
///
/// Extracts `messages[].content` and `prompt` for narrowed scanning.
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

/// Adapter for the Anthropic (Claude) API.
///
/// Extracts `messages[].content` (Anthropic style).
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

/// Apply known adapters to the JSON.
///
/// Returns the first adapter that matches, or `None` if none applies.
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
