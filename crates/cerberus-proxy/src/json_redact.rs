//! JSON-preserving redaction (F2 fix, review P0-2).
//!
//! The old path concatenated every string value of the body, redacted that
//! concatenation, and forwarded plain text — corrupting JSON. This module
//! walks the parsed `serde_json::Value` tree and redacts **only** matching
//! string leaves, re-serializing the original structure afterwards.
//!
//! Non-JSON bodies fall back to whole-text redaction.

use bytes::Bytes;
use cerberus_engine::engine::{CompiledEngine, Finding};
use cerberus_engine::redact::{apply_redaction, RedactOptions};

use crate::decoder::{ContentType, DecodedBody};

/// Redact the body preserving structure.
///
/// Returns the transformed bytes. For JSON bodies the structure is preserved
/// (only matching string leaves are replaced); for text bodies the whole text
/// is redacted in place using the already-produced findings.
///
/// # Errors
///
/// Returns an error if the redaction itself fails internally (fail-policy
/// decides at the caller: Open → forward original, Closed → reject).
pub fn redact_body(
    engine: &CompiledEngine,
    body: &Bytes,
    decoded: &DecodedBody,
    opts: &RedactOptions,
    findings: &[Finding],
) -> Result<Vec<u8>, String> {
    // JSON path first; si el body no es JSON válido cae al fallback de texto.
    if decoded.content_type == ContentType::Json {
        if let Some(redacted) = redact_json(engine, body, opts)? {
            return Ok(redacted);
        }
    }
    fallback_text(decoded, findings, opts)
}

/// Fallback: redacción en texto plano del texto decodificado.
fn fallback_text(decoded: &DecodedBody, findings: &[Finding], opts: &RedactOptions) -> Result<Vec<u8>, String> {
    apply_redaction(&decoded.text, findings, opts)
        .map(String::into_bytes)
        .map_err(|e| format!("redaction failed: {e}"))
}

/// Redact every string leaf of a JSON body that triggers a finding.
/// Returns `Ok(None)` if the body isn't valid JSON (caller falls back to
/// whole-text redaction). Propagates redaction errors (review v4 #5): antes
/// se tragaba el error de `apply_redaction` y se reenviaba el secreto crudo.
fn redact_json(engine: &CompiledEngine, body: &Bytes, opts: &RedactOptions) -> Result<Option<Vec<u8>>, String> {
    let mut value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // El body completo como contexto para constraints de keywords.
    let body_text = String::from_utf8_lossy(body).to_string();
    redact_value(engine, &mut value, opts, &body_text)?;
    serde_json::to_vec(&value)
        .map(Some)
        .map_err(|e| format!("json reserialize failed: {e}"))
}

fn redact_value(
    engine: &CompiledEngine,
    value: &mut serde_json::Value,
    opts: &RedactOptions,
    body_text: &str,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(s) => {
            // scan_with_context: los contextKeywords pueden vivir en otros
            // campos del JSON (regresión revisión 2, P0). El leaf se escanea
            // con el body completo como contexto.
            let found = engine.scan_with_context(s, body_text);
            if !found.findings.is_empty() {
                let redacted =
                    apply_redaction(s, &found.findings, opts).map_err(|e| format!("leaf redaction failed: {e}"))?;
                *s = redacted;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                redact_value(engine, item, opts, body_text)?;
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map {
                redact_value(engine, v, opts, body_text)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::decode;
    use cerberus_engine::engine::EngineBuilder;
    use cerberus_engine::loader::load_rules_from_str;
    use cerberus_engine::rule::Rule;

    const RULES: &str = r#"[
        {"flag":"secret.oauth_bearer","category":"secrets","severity":"high","action":"redact",
         "contextKeywords":[],"minLength":8,"maxLength":256,
         "patterns":["\\bBearer\\s+[A-Za-z0-9._~+/-]+=*\\b"]},
        {"flag":"secret.google_api_key","category":"secrets","severity":"high","action":"redact",
         "contextKeywords":["google","api_key"],"minLength":30,"maxLength":100,
         "patterns":["AIza[A-Za-z0-9_-]{35}"]}
    ]"#;

    fn engine() -> CompiledEngine {
        let rules: Vec<Rule> = load_rules_from_str(RULES).expect("rules");
        EngineBuilder::new(&rules).build().expect("engine")
    }

    #[test]
    fn json_structure_preserved_after_redaction() {
        let engine = engine();
        let raw = r#"{"messages":[{"role":"user","content":"Authorization: Bearer abcdefghijklmnopqrstuvwxyzA123456 fin"}],"model":"gpt-4","temperature":0.0,"n":1}"#;
        let body = Bytes::from(raw);
        let decoded = decode(&body, Some("application/json"));
        let findings: Vec<Finding> = Vec::new(); // unused in JSON path
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &findings).expect("redact");
        let text = String::from_utf8(out).expect("utf8");
        // JSON removido? debe seguir siendo JSON válido y con la estructura.
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON after redaction");
        assert_eq!(parsed["model"], "gpt-4");
        assert_eq!(parsed["temperature"], 0.0);
        assert_eq!(parsed["n"], 1);
        let content = parsed["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[REDACTED"));
        assert!(!content.contains("Bearer abcdefghijklmnopqrstuvwxyzA123456"));
    }

    #[test]
    fn redaction_reaches_nested_string_leaves() {
        let engine = engine();
        let payload =
            r#"{"data":{"items":[{"tag":"secret","note":"auth: Bearer xyzwvutsrqponmlkjihgfedcbaA987654"}]}}"#;
        let body = Bytes::from(payload);
        let decoded = decode(&body, Some("application/json"));
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[]).expect("redact");
        let parsed: serde_json::Value = serde_json::from_slice(&out[..]).expect("valid JSON");
        let inner = parsed["data"]["items"][0]["note"].as_str().unwrap();
        assert!(inner.contains("[REDACTED"));
        assert!(!inner.contains("xyzwvutsrqponmlkjihgfedcbaA987654"));
    }

    #[test]
    fn context_keyword_in_other_field_redacts() {
        // Regresión revisión 2 (P0): el keyword de contexto vive en OTRO campo
        // del JSON. El scan por leaf sin contexto no lo vería, permitiendo
        // fugas; scan_with_context debe redactarlo.
        let key = format!("AIza{}", "A".repeat(35));
        let payload = format!(r#"{{"context":"google api_key","secret":"{key}"}}"#);
        let body = Bytes::from(payload);
        let decoded = decode(&body, Some("application/json"));
        let out = redact_body(&engine(), &body, &decoded, &RedactOptions::default(), &[]).expect("redact");
        let text = String::from_utf8(out).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let redacted = parsed["secret"].as_str().expect("secret field");
        assert!(
            !redacted.contains(key.as_str()),
            "secret must not reach upstream raw; got {redacted:?}"
        );
        assert!(redacted.contains("[REDACTED"), "got {redacted:?}");
        assert_eq!(parsed["context"], "google api_key");
    }

    #[test]
    fn redaction_failure_propagates_not_swallowed() {
        // Review v4 #5: una regla `block` en un leaf hace que `apply_redaction`
        // devuelva Err. Antes se tragaba (`if let Ok`) y se reenviaba el secreto
        // crudo; ahora `redact_body` debe propagar el error para que la
        // fail_policy decida (Closed → 502 / Open → forward original).
        let rules: Vec<Rule> = load_rules_from_str(
            r#"[{"flag":"secret.block","category":"secrets","severity":"critical","action":"block",
                "contextKeywords":[],"minLength":8,"maxLength":256,
                "patterns":["\\bBlockMe[A-Za-z0-9]{20,}\\b"]}]"#,
        )
        .expect("rules");
        let engine = EngineBuilder::new(&rules).build().expect("engine");
        let raw = r#"{"prompt":"BlockMeSuperSecretDoNotLeak1234567890 fin"}"#;
        let body = Bytes::from(raw);
        let decoded = decode(&body, Some("application/json"));
        let err = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[])
            .expect_err("redaction must fail (block finding) and NOT return the raw JSON");
        assert!(
            err.contains("redaction") || err.contains("Blocked"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn text_fallback_propagates_invalid_span_error() {
        // Review v4 #5, span inválido (end > len): `apply_redaction` falla y
        // el error debe llegar al caller, no devolverse el texto crudo.
        let engine = engine();
        let body = Bytes::from("hola");
        let decoded = decode(&body, Some("text/plain"));
        let bad_finding = Finding {
            flag: "broken.span".to_string(),
            category: cerberus_engine::rule::Category::Secrets,
            severity: cerberus_engine::rule::Severity::High,
            action: cerberus_engine::rule::Action::Redact,
            start: 0,
            end: 100,
            hashed_value: "unused".to_string(),
        };
        let err = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[bad_finding]).err();
        assert!(err.is_some(), "invalid span must propagate as Err");
    }
}
