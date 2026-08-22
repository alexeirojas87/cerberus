//! Rule pack format — versioned, signed rule packs (§7 of the build plan).
//!
//! A rule pack is a set of detection rules packaged with metadata
//! (name, version, description) and signed with Ed25519 to guarantee
//! integrity and authenticity.

use cerberus_engine::rule::Rule;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

/// Metadata for a rule pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackMetadata {
    /// Pack name, e.g. "secrets-core".
    pub name: String,
    /// Semantic version, e.g. "1.2.0".
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// Pack author/publisher.
    pub author: String,
    /// Publication date `ISO 8601`.
    pub published: String,
    /// Minimum required engine version for the pack.
    pub min_engine_version: String,
}

/// A complete (unsigned) rule pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    /// Pack metadata.
    pub metadata: PackMetadata,
    /// Pack rules.
    pub rules: Vec<Rule>,
}

/// A rule pack signed with Ed25519.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRulePack {
    /// Pack content as JSON (serialized for signing).
    pub pack_json: String,
    /// Ed25519 signature in hex.
    pub signature_hex: String,
    /// Signer public key in hex.
    pub signer_public_key_hex: String,
}

impl RulePack {
    /// Serialize the pack to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("serialize pack: {e}"))
    }

    /// Deserialize a pack from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is invalid.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("deserialize pack: {e}"))
    }

    /// Compile all the pack's rules into the engine.
    ///
    /// # Errors
    ///
    /// Returns an error if any rule fails to compile.
    pub fn compile(&self) -> Result<(), String> {
        let _engine = cerberus_engine::engine::EngineBuilder::new(&self.rules)
            .build()
            .map_err(|e| format!("compile error: {e}"))?;
        Ok(())
    }

    /// Get the rule count.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl SignedRulePack {
    /// Create a `SignedRulePack` by signing a `RulePack`.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or signing fails.
    pub fn sign(pack: &RulePack, keypair: &ed25519_dalek::SigningKey) -> Result<Self, String> {
        let pack_json = pack.to_json()?;
        let signature = keypair.sign(pack_json.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes().as_slice());
        let public_key_hex = hex::encode(keypair.verifying_key().as_bytes());

        Ok(Self {
            pack_json,
            signature_hex,
            signer_public_key_hex: public_key_hex,
        })
    }

    /// Verify the pack signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self) -> Result<(), String> {
        let signature_bytes = hex::decode(&self.signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?;
        let signature =
            ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|e| format!("invalid signature: {e}"))?;

        let public_key_bytes =
            hex::decode(&self.signer_public_key_hex).map_err(|e| format!("invalid public key hex: {e}"))?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(
            &public_key_bytes
                .try_into()
                .map_err(|_| "invalid public key length".to_string())?,
        )
        .map_err(|e| format!("invalid public key: {e}"))?;

        public_key
            .verify_strict(self.pack_json.as_bytes(), &signature)
            .map_err(|e| format!("signature verification failed: {e}"))?;

        Ok(())
    }

    /// Verify the pack signature against a trusted public key (trust root).
    /// Any pack signed by another key is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or the key does not match.
    pub fn verify_with_trusted_root(&self, expected_public_key_hex: &str) -> Result<(), String> {
        if !self.signer_public_key_hex.eq_ignore_ascii_case(expected_public_key_hex) {
            return Err(format!(
                "pack signer key mismatch: expected {expected_public_key_hex:?}, got {}",
                self.signer_public_key_hex
            ));
        }
        self.verify()
    }

    /// Deserialize the inner `RulePack`.
    ///
    /// The signature is ALWAYS verified against a trust root: the
    /// `CERBERUS_PACK_TRUST_ROOT` environment variable. Without a trust root
    /// it is NOT accepted: fail-closed (review 2 regression, P1 #4). The
    /// `signer_public_key_hex` of the pack itself can never serve as root
    /// (self-signed pack by the attacker). For an explicit root use
    /// [`Self::extract_with_root`].
    ///
    /// # Errors
    ///
    /// Returns an error if there is no trust root, the signature is invalid,
    /// or the JSON cannot be parsed.
    pub fn extract(&self) -> Result<RulePack, String> {
        let root = std::env::var("CERBERUS_PACK_TRUST_ROOT").ok().filter(|r| !r.is_empty());
        let Some(root) = root else {
            return Err(
                "pack verification impossible: no trust root configured (set CERBERUS_PACK_TRUST_ROOT or use extract_with_root)"
                    .to_string(),
            );
        };
        self.extract_with_root(&root)
    }

    /// Deserialize the inner `RulePack` verifying against an EXPLICIT trust
    /// root key. This is the path to use for callers that already resolve the
    /// root from their own trusted config, without depending on the environment.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, does not match
    /// `root_hex`, or the JSON cannot be parsed.
    pub fn extract_with_root(&self, root_key: &str) -> Result<RulePack, String> {
        self.verify_with_trusted_root(root_key)?;
        RulePack::from_json(&self.pack_json).map_err(|e| format!("deserialize pack: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::rule::{Action, Category, Severity};
    use ed25519_dalek::SigningKey;
    use std::sync::Mutex;

    /// Guard to serialize the (few) tests that touch `std::env`
    /// (see race with `--test-threads=N`).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn sample_pack() -> RulePack {
        let rule = Rule {
            flag: "secret.test".to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Block,
            hash_normalization: None,
            context_keywords: vec!["test".to_string()],
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec!["test-pattern".to_string()],
            validators: Vec::new(),
        };

        RulePack {
            metadata: PackMetadata {
                name: "test-pack".to_string(),
                version: "1.0.0".to_string(),
                description: "Test pack".to_string(),
                author: "Cerberus".to_string(),
                published: "2026-08-17T00:00:00Z".to_string(),
                min_engine_version: "0.1.0".to_string(),
            },
            rules: vec![rule],
        }
    }

    #[test]
    fn pack_roundtrip_json() {
        let pack = sample_pack();
        let json = pack.to_json().unwrap();
        let restored = RulePack::from_json(&json).unwrap();
        assert_eq!(pack.metadata.name, restored.metadata.name);
        assert_eq!(pack.rules.len(), restored.rules.len());
    }

    #[test]
    fn pack_compile_succeeds() {
        let pack = sample_pack();
        assert!(pack.compile().is_ok());
    }

    fn test_keypair() -> SigningKey {
        let seed = [42u8; 32];
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn pack_sign_and_verify() {
        let pack = sample_pack();
        let keypair = test_keypair();

        let signed = SignedRulePack::sign(&pack, &keypair).unwrap();
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn pack_tampered_signature_fails() {
        let pack = sample_pack();
        let keypair = test_keypair();

        let mut signed = SignedRulePack::sign(&pack, &keypair).unwrap();
        signed.pack_json.push(' ');
        assert!(signed.verify().is_err());
    }

    #[test]
    fn pack_extract_requires_trust_root() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let pack = sample_pack();
        let keypair = test_keypair();
        let signed = SignedRulePack::sign(&pack, &keypair).unwrap();

        // Without CERBERUS_PACK_TRUST_ROOT → fail-closed (review 2 regression,
        // P1 #4). The pack's own signer is never a root.
        std::env::remove_var("CERBERUS_PACK_TRUST_ROOT");
        assert!(signed.extract().is_err(), "without a trust root it must not pass");
    }

    #[test]
    fn pack_extract_verifies_and_deserializes() {
        let pack = sample_pack();
        let keypair = test_keypair();

        let signed = SignedRulePack::sign(&pack, &keypair).unwrap();
        // Explicit root as a parameter (without touching the process env).
        let root = hex::encode(keypair.verifying_key().as_bytes());
        let extracted = signed.extract_with_root(&root).unwrap();
        assert_eq!(extracted.metadata.name, "test-pack");
        assert_eq!(extracted.rules.len(), 1);
    }

    #[test]
    fn pack_mismatched_root_rejected() {
        let pack = sample_pack();
        let keypair = test_keypair();
        let attacker = SigningKey::from_bytes(&[99u8; 32]);

        let signed = SignedRulePack::sign(&pack, &keypair).unwrap();
        let attacker_root = hex::encode(attacker.verifying_key().as_bytes());
        assert!(
            signed.extract_with_root(&attacker_root).is_err(),
            "a root from another signer must not pass"
        );
    }

    #[test]
    fn different_key_fails_verification() {
        let pack = sample_pack();
        let keypair1 = test_keypair();
        let seed2 = [99u8; 32];
        let keypair2 = SigningKey::from_bytes(&seed2);

        let mut signed = SignedRulePack::sign(&pack, &keypair1).unwrap();
        signed.signer_public_key_hex = hex::encode(keypair2.verifying_key().as_bytes());
        assert!(signed.verify().is_err());
    }

    #[test]
    fn pack_metadata_version() {
        let pack = sample_pack();
        assert_eq!(pack.metadata.version, "1.0.0");
    }

    #[test]
    fn pack_rule_count() {
        let pack = sample_pack();
        assert_eq!(pack.rule_count(), 1);
    }
}
