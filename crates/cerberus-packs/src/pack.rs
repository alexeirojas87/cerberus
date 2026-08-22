//! Rule pack format — versioned, signed rule packs (§7 del build plan).
//!
//! Un rule pack es un conjunto de reglas de detección empaquetado con
//! metadatos (nombre, versión, descripción) y firmado con Ed25519 para
//! garantizar integridad y autenticidad.

use cerberus_engine::rule::Rule;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

/// Metadatos de un rule pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackMetadata {
    /// Nombre del pack, ej. "secrets-core".
    pub name: String,
    /// Versión semántica, ej. "1.2.0".
    pub version: String,
    /// Descripción legible.
    pub description: String,
    /// Autor/editor del pack.
    pub author: String,
    /// Fecha de publicación `ISO 8601`.
    pub published: String,
    /// Pack requerido mínima versión del engine.
    pub min_engine_version: String,
}

/// Un rule pack completo (sin firmar).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    /// Metadatos del pack.
    pub metadata: PackMetadata,
    /// Reglas del pack.
    pub rules: Vec<Rule>,
}

/// Un rule pack firmado con Ed25519.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRulePack {
    /// Contenido del pack en JSON (serializado para firma).
    pub pack_json: String,
    /// Firma Ed25519 en hex.
    pub signature_hex: String,
    /// Clave pública del firmante en hex.
    pub signer_public_key_hex: String,
}

impl RulePack {
    /// Serializar el pack a JSON.
    ///
    /// # Errors
    ///
    /// Devuelve error si la serialización falla.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("serialize pack: {e}"))
    }

    /// Deserializar un pack desde JSON.
    ///
    /// # Errors
    ///
    /// Devuelve error si el JSON no es válido.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("deserialize pack: {e}"))
    }

    /// Compilar todas las reglas del pack en el engine.
    ///
    /// # Errors
    ///
    /// Devuelve error si alguna regla no compila.
    pub fn compile(&self) -> Result<(), String> {
        let _engine = cerberus_engine::engine::EngineBuilder::new(&self.rules)
            .build()
            .map_err(|e| format!("compile error: {e}"))?;
        Ok(())
    }

    /// Obtener el conteo de reglas.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl SignedRulePack {
    /// Crear un `SignedRulePack` firmando un `RulePack`.
    ///
    /// # Errors
    ///
    /// Devuelve error si la serialización o firma fallan.
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

    /// Verificar la firma del pack.
    ///
    /// # Errors
    ///
    /// Devuelve error si la firma no es válida.
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

    /// Verificar la firma del pack contra una clave pública de confianza
    /// (trust root). Cualquier pack firmado por otra clave es rechazado.
    ///
    /// # Errors
    ///
    /// Devuelve error si la firma no es válida o la clave no coincide.
    pub fn verify_with_trusted_root(&self, expected_public_key_hex: &str) -> Result<(), String> {
        if !self.signer_public_key_hex.eq_ignore_ascii_case(expected_public_key_hex) {
            return Err(format!(
                "pack signer key mismatch: expected {expected_public_key_hex:?}, got {}",
                self.signer_public_key_hex
            ));
        }
        self.verify()
    }

    /// Deserializar el `RulePack` interno.
    ///
    /// La firma SIEMPRE se verifica contra un trust root: la variable de
    /// entorno `CERBERUS_PACK_TRUST_ROOT`. Sin trust root NO se acepta:
    /// falla-closed (regresión revisión 2, P1 #4). El `signer_public_key_hex`
    /// del propio pack jamás puede servir de root (pack autofirmado por el
    /// atacante). Para un root explícito usar [`Self::extract_with_root`].
    ///
    /// # Errors
    ///
    /// Devuelve error si no hay trust root, la firma no es válida o el JSON
    /// no se puede parsear.
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

    /// Deserializar el `RulePack` interno verificando contra una clave raíz de
    /// confianza EXPLÍCITA. Esta es la vía a usar por callers que ya resuelven
    /// el root desde su propia config confiable, sin depender del entorno.
    ///
    /// # Errors
    ///
    /// Devuelve error si la firma no es válida, no coincide con `root_hex`, o
    /// el JSON no se puede parsear.
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

    /// Guard para serializar los (pocos) tests que tocan `std::env`
    /// (ver carrera con `--test-threads=N`).
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

        // Sin CERBERUS_PACK_TRUST_ROOT → fail-closed (regresión revisión 2,
        // P1 #4). El signer del propio pack jamás es root.
        std::env::remove_var("CERBERUS_PACK_TRUST_ROOT");
        assert!(signed.extract().is_err(), "sin trust root no debe pasar");
    }

    #[test]
    fn pack_extract_verifies_and_deserializes() {
        let pack = sample_pack();
        let keypair = test_keypair();

        let signed = SignedRulePack::sign(&pack, &keypair).unwrap();
        // Root explícito como parámetro (sin tocar el entorno del proceso).
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
            "root de otro firmante no debe pasar"
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
