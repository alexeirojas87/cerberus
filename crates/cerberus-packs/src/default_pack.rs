//! Default rule pack — out-of-the-box detection rules.
//!
//! Single source of truth for the default pack. Consumed by:
//! - The CLI/daemon (`cerberus`) when booting without config.
//! - The F9 hardening tests (redos-fuzz, load-test) to fuzz and benchmark the
//!   **real** pack we ship, not an inline copy.
//!
//! Any change here is reflected in production and in the tests
//! simultaneously (no drift).

/// Version of the exact default pack embedded in this crate.
pub const DEFAULT_PACK_VERSION: &str = "1.2.3";

/// Version and SHA-256 identity of the exact [`DEFAULT_PACK_JSON`] bytes.
/// Product gates fail if either the version or pack bytes drift without an
/// intentional identity update.
pub const DEFAULT_PACK_IDENTITY: &str = "1.2.3@sha256:cc2999f03792194f9aea73763fd8b4831b48d5564400546ba90a465556411379";

/// Virtual detectors that are part of the product engine rather than duplicate
/// entries in [`DEFAULT_PACK_JSON`].
///
/// They are named here so product gates can
/// require explicit coverage and report them alongside declarative rules.
pub const DEFAULT_PACK_VIRTUAL_FLAGS: &[&str] = &["entropy.high_entropy_secret"];

/// Default pack JSON (15 rules: OpenAI, Anthropic, AWS, Bearer,
/// GitHub, Stripe, Google, Slack, email, credit card, two phone policies,
/// PEM, id_rsa, .env).
///
/// Keep in sync with `evidence/f9/redos-fuzz.md` and
/// `evidence/f9/load-test.md`.
#[allow(clippy::doc_markdown)]
pub const DEFAULT_PACK_JSON: &str = r#"[
  {
    "flag": "secret.openai_api_key",
    "category": "secrets",
    "severity": "critical",
    "action": "block",
    "hashNormalization": "trim",
    "contextKeywords": [],
    "minLength": 20,
    "maxLength": 128,
    "allowedExamples": ["sk-EXAMPLE000000000000000000000000"],
    "patterns": ["\\bsk-[A-Za-z0-9]{20,}\\b"],
    "validators": []
  },
  {
    "flag": "secret.anthropic_api_key",
    "category": "secrets",
    "severity": "critical",
    "action": "block",
    "contextKeywords": [],
    "minLength": 20,
    "maxLength": 128,
    "patterns": ["\\bsk-ant-[A-Za-z0-9]{20,}\\b"],
    "validators": []
  },
  {
    "flag": "secret.aws_access_key_id",
    "category": "secrets",
    "severity": "critical",
    "action": "block",
    "contextKeywords": [],
    "minLength": 16,
    "maxLength": 32,
    "allowedExamples": ["AKIAIOSFODNN7EXAMPLE"],
    "patterns": ["\\bAKIA[0-9A-Z]{16}\\b"],
    "validators": []
  },
  {
    "flag": "secret.generic_bearer_token",
    "category": "secrets",
    "severity": "high",
    "action": "redact",
    "contextKeywords": [],
    "minLength": 16,
    "maxLength": 256,
    "allowedExamples": ["Bearer YOUR_TOKEN_HERE"],
    "patterns": ["\\bBearer\\s+[A-Za-z0-9._~+/-]+=*\\b"],
    "validators": []
  },
  {
    "flag": "secret.github_token",
    "category": "secrets",
    "severity": "critical",
    "action": "block",
    "contextKeywords": [],
    "minLength": 20,
    "maxLength": 200,
    "allowedExamples": ["ghp_example_token_do_not_use_in_production"],
    "patterns": ["\\bgh[psou]_[A-Za-z0-9_]{20,}\\b"],
    "validators": []
  },
  {
    "flag": "secret.stripe_key",
    "category": "secrets",
    "severity": "critical",
    "action": "block",
    "contextKeywords": [],
    "minLength": 20,
    "maxLength": 128,
    "patterns": ["\\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]+\\b"],
    "validators": []
  },
  {
    "flag": "secret.google_api_key",
    "category": "secrets",
    "severity": "high",
    "action": "redact",
    "contextKeywords": [],
    "minLength": 30,
    "maxLength": 100,
    "patterns": ["\\bAIza[0-9A-Za-z_-]{35}\\b"],
    "validators": []
  },
  {
    "flag": "secret.slack_token",
    "category": "secrets",
    "severity": "high",
    "action": "redact",
    "contextKeywords": [],
    "minLength": 20,
    "maxLength": 100,
    "allowedExamples": ["xoxb-EXAMPLE0000000000000000000000"],
    "patterns": ["\\bxox[abpors]-[A-Za-z0-9]{20,}\\b"],
    "validators": []
  },
  {
    "flag": "pii.email_address",
    "category": "pii",
    "severity": "medium",
    "action": "warn",
    "contextKeywords": [],
    "minLength": 5,
    "maxLength": 254,
    "allowedExamples": ["user@example.com"],
    "patterns": ["\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"],
    "validators": []
  },
  {
    "flag": "pii.credit_card",
    "category": "pii",
    "severity": "critical",
    "action": "redact",
    "contextKeywords": [],
    "minLength": 13,
    "maxLength": 38,
    "allowedExamples": ["4111 1111 1111 1111"],
    "patterns": ["(?:\\+[0-9](?:(?:[ \u00a0]{1,3}|[./-])?[0-9]){12,18}\\b|\\b[0-9](?:(?:[ \u00a0]{1,3}|[./-])?[0-9]){12,18}\\b)"],
    "validators": ["payment-card"]
  },
  {
    "flag": "pii.phone_number",
    "category": "pii",
    "severity": "medium",
    "action": "warn",
    "contextKeywords": [],
    "minLength": 7,
    "maxLength": 20,
    "patterns": ["(?-u)(?:\\+[1-9][0-9]{6,14}\\b|\\+[0-9]{1,3}[ .-](?:\\([0-9]{1,4}\\)|[0-9]{1,4})(?:[ .-][0-9]{2,4}){1,3}\\b|\\([0-9]{3}\\)[ .-][0-9]{3}[ .-][0-9]{4}\\b|\\b[0-9]{3}[ .-][0-9]{3}[ .-][0-9]{4}\\b|\\b[0-9]{1,3}[ ][0-9]{1,4}(?:[ ][0-9]{2,4}){1,2}\\b)"],
    "validators": ["not-payment-card"]
  },
  {
    "flag": "pii.phone_number",
    "category": "pii",
    "severity": "medium",
    "action": "warn",
    "contextKeywords": ["phone", "phones", "tel", "telephone", "mobile", "contact", "contacts", "hotline", "e.164", "e164"],
    "minLength": 7,
    "maxLength": 20,
    "patterns": ["(?-u)\\b[1-9][0-9]{6,14}\\b"],
    "validators": ["not-payment-card"]
  },
  {
    "flag": "secret.pem_private_key",
    "category": "secrets",
    "severity": "critical",
    "action": "block",
    "contextKeywords": [],
    "patterns": ["-----BEGIN\\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\\n(?:.*\\n)*?-----END\\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"],
    "validators": []
  },
  {
    "flag": "secret.id_rsa_ssh_key",
    "category": "secrets",
    "severity": "critical",
    "action": "block",
    "contextKeywords": [],
    "patterns": ["-----BEGIN\\s+OPENSSH PRIVATE KEY-----\\n(?:.*\\n)*?-----END\\s+OPENSSH PRIVATE KEY-----"],
    "validators": []
  },
  {
    "flag": "secret.env_block",
    "category": "secrets",
    "severity": "high",
    "action": "warn",
    "contextKeywords": [],
    "patterns": ["(?m)^(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_TENANT_ID|AZURE_CLIENT_SECRET|DATABASE_URL|REDIS_URL|SECRET_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)=.{10,}\\n?"],
    "validators": []
  }
]"#;

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::engine::EngineBuilder;
    use cerberus_engine::loader::load_rules_from_str;

    #[test]
    fn default_pack_parses_successfully() {
        let rules = load_rules_from_str(DEFAULT_PACK_JSON).unwrap();
        assert!(rules.len() >= 10, "expected at least 10 rules, got {}", rules.len());
    }

    #[test]
    fn default_pack_rules_have_required_fields() {
        let rules = load_rules_from_str(DEFAULT_PACK_JSON).unwrap();
        for rule in &rules {
            assert!(!rule.flag.is_empty(), "rule missing flag");
            assert!(!rule.patterns.is_empty(), "rule {} has no patterns", rule.flag);
        }
    }

    #[test]
    fn default_pack_compiles_successfully() {
        let rules = load_rules_from_str(DEFAULT_PACK_JSON).unwrap();
        let result = EngineBuilder::new(&rules).build();
        assert!(result.is_ok(), "engine compile failed: {:?}", result.err());
    }
}
