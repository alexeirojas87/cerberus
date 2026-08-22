//! Default rule packs — reglas de detección incluidas por defecto.
//!
//! El contenido del pack por defecto vive en `cerberus_packs::default_pack`
//! (fuente única de verdad). Este módulo lo expone al daemon/CLI y mantiene
//! los tests de coherencia del pack.

/// Obtener el JSON de reglas por defecto (delegado a `cerberus_packs`).
#[must_use]
pub(crate) fn default_rules_json() -> String {
    cerberus_packs::default_pack::DEFAULT_PACK_JSON.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::loader::load_rules_from_str;

    #[test]
    fn default_rules_parse_successfully() {
        let json = default_rules_json();
        let rules = load_rules_from_str(&json).unwrap();
        assert!(rules.len() >= 10, "expected at least 10 rules, got {}", rules.len());
    }

    #[test]
    fn default_rules_have_required_fields() {
        let json = default_rules_json();
        let rules = load_rules_from_str(&json).unwrap();
        for rule in &rules {
            assert!(!rule.flag.is_empty(), "rule missing flag");
            assert!(!rule.patterns.is_empty(), "rule {} has no patterns", rule.flag);
        }
    }

    #[test]
    fn default_rules_compile_successfully() {
        let json = default_rules_json();
        let rules = load_rules_from_str(&json).unwrap();
        let result = cerberus_engine::engine::EngineBuilder::new(&rules).build();
        assert!(result.is_ok(), "engine compile failed: {:?}", result.err());
    }

    // ─── P0-2: Verify high-specificity keywords are normalized ─────────────

    #[test]
    fn keywords_normalized_to_lowercase_at_compile() {
        let json = r#"[{
            "flag": "test.aws",
            "category": "secrets",
            "severity": "critical",
            "action": "block",
            "contextKeywords": ["AWS", "ACCESS", "KEY"],
            "patterns": ["\\bAKIA[0-9A-Z]{16}\\b"]
        }]"#;
        let rules = load_rules_from_str(json).unwrap();
        // Keywords from JSON may be uppercase ("AWS", "ACCESS").
        // After compile, they must be lowercase.
        let engine = cerberus_engine::engine::EngineBuilder::new(&rules).build().unwrap();
        // This should still work — compilation normalized "AWS" → "aws".
        let result = engine.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(
            !result.findings.is_empty(),
            "AKIA key in AWS context should match after keyword normalization"
        );
    }
}
