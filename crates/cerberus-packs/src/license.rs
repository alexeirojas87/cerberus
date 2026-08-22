//! Free/Pro entitlement system for Cerberus (§7 del build plan).
//!
//! El motor y el modo local básico quedan libres (Free). Features Pro
//! (dashboard avanzado, reglas premium, alertas, etc.) se activan via
//! archivo de licencia.

use serde::{Deserialize, Serialize};

/// Tier de licencia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Free (open-core): motor básico, proxy local, rule packs básicos.
    #[default]
    Free,
    /// Pro: packs premium, dashboard, alertas, políticas por equipo.
    Pro,
}

/// Información de una licencia.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// Tier de la licencia.
    pub tier: LicenseTier,
    /// Email del titular.
    pub email: String,
    /// Identificador de licencia.
    pub license_id: String,
    /// Fecha de expiración `ISO 8601` (None = perpetua).
    pub expires_at: Option<String>,
    /// Features habilitadas adicionales.
    pub features: Vec<String>,
}

/// Licencia firmada (firma Ed25519 del emisor sobre el JSON de la licencia).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    /// JSON serializado de la licencia (lo que se firma).
    pub license_json: String,
    /// Firma Ed25519 en hex.
    pub signature_hex: String,
    /// Clave pública del firmante en hex.
    pub signer_public_key_hex: String,
    /// Clave del titular, SOLO como metadata (P0: no es trust root).
    ///
    /// Lo que pone el atacante aquí SIEMPRE debe ignorarse a la hora de
    /// verificar: el trust root solo puede venir de `CERBERUS_LICENSE_PUBLIC_KEY`,
    /// de `CERBERUS_EMBEDDED_LICENSE_KEY` (build time) o de
    /// [`LicenseManager::from_file_with_root`].
    #[serde(default)]
    pub owner_public_key_hex: Option<String>,
}

/// Clave pública raíz embebida en build time (opcional).
///
/// Se fija compilando con `CERBERUS_EMBEDDED_LICENSE_KEY=<hex>`. Mientras no
/// se defina en build time, esta constante es `None` y `from_file` solo
/// confiará en `CERBERUS_LICENSE_PUBLIC_KEY`.
pub const EMBEDDED_LICENSE_PUBLIC_KEY: Option<&'static str> = option_env!("CERBERUS_EMBEDDED_LICENSE_KEY");

impl SignedLicense {
    /// Verificar la firma de la licencia contra la clave pública indicada.
    ///
    /// La clave indicada debe provenir de una fuente de confianza EXTERNA:
    /// env de despliegue, clave embebida en build time o un parámetro
    /// explícito de [`LicenseManager::from_file_with_root`].
    /// NUNCA se debe usar `owner_public_key_hex` del propio archivo como root
    /// (P0: licencia autofirmada por el atacante).
    ///
    /// # Errors
    ///
    /// Devuelve error si la firma no es válida o la clave no coincide.
    pub fn verify(&self, expected_public_key_hex: &str) -> Result<(), String> {
        if !self.signer_public_key_hex.eq_ignore_ascii_case(expected_public_key_hex) {
            return Err("license signer key mismatch".to_string());
        }
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
            .verify_strict(self.license_json.as_bytes(), &signature)
            .map_err(|e| format!("license signature verification failed: {e}"))?;
        Ok(())
    }

    /// Parsear la licencia firmada de vuelta a [`License`].
    ///
    /// # Errors
    ///
    /// Devuelve error si el JSON no es válido.
    pub fn license(&self) -> Result<License, String> {
        serde_json::from_str(&self.license_json).map_err(|e| format!("invalid license json: {e}"))
    }
}

/// Features disponibles en cada tier.
#[derive(Debug, Clone)]
pub enum Feature {
    /// Dashboard con históricos y estadísticas.
    Dashboard,
    /// Alertas Slack/Teams/webhook.
    Alerts,
    /// Rule packs premium auto-actualizados.
    PremiumPacks,
    /// Editor visual de reglas.
    RuleEditor,
    /// Políticas por equipo y SSO.
    TeamPolicies,
    /// Alertas multi-canal.
    MultiChannelAlerts,
}

impl Feature {
    /// Verificar si un feature está disponible en el tier dado.
    #[must_use]
    pub fn available_in(&self, tier: LicenseTier) -> bool {
        tier == LicenseTier::Pro
    }

    /// Obtener el nombre del feature.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Dashboard => "dashboard",
            Self::Alerts => "alerts",
            Self::PremiumPacks => "premium_packs",
            Self::RuleEditor => "rule_editor",
            Self::TeamPolicies => "team_policies",
            Self::MultiChannelAlerts => "multi_channel_alerts",
        }
    }
}

/// Gestor de licencias.
#[derive(Debug, Clone)]
pub struct LicenseManager {
    /// Licencia activa.
    license: License,
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::free()
    }
}

impl LicenseManager {
    /// Crear un `LicenseManager` con tier Free.
    #[must_use]
    pub fn free() -> Self {
        Self {
            license: License {
                tier: LicenseTier::Free,
                email: String::new(),
                license_id: "free".to_string(),
                expires_at: None,
                features: Vec::new(),
            },
        }
    }

    /// Crear un `LicenseManager` desde un archivo de licencia firmada.
    ///
    /// La firma SIEMPRE se verifica contra un trust root externo:
    /// `CERBERUS_LICENSE_PUBLIC_KEY` (env, recomendado) o, si no está
    /// definida, la clave embebida en build time via
    /// `CERBERUS_EMBEDDED_LICENSE_KEY` (ver [`EMBEDDED_LICENSE_PUBLIC_KEY`]).
    /// El campo `owner_public_key_hex` del propio archivo NUNCA se usa como
    /// trust root (P0: licencia autofirmada por el atacante). Sin ningún
    /// root configurado la licencia se rechaza (fail-closed). Un JSON plano
    /// también se rechaza. (Regresión revisión 2, P1 #3.)
    ///
    /// Para un root explícito, usar [`Self::from_file_with_root`].
    ///
    /// # Errors
    ///
    /// Devuelve error si el archivo no existe, no hay trust root configurado,
    /// o la firma no es válida.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let root = std::env::var("CERBERUS_LICENSE_PUBLIC_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .or_else(|| {
                EMBEDDED_LICENSE_PUBLIC_KEY
                    .filter(|k| !k.is_empty())
                    .map(str::to_string)
            });
        let Some(root) = root else {
            return Err(
                "license verification impossible: no trust root configured (set CERBERUS_LICENSE_PUBLIC_KEY or build with CERBERUS_EMBEDDED_LICENSE_KEY)"
                    .to_string(),
            );
        };
        Self::from_file_with_root(path, &root)
    }

    /// Crear un `LicenseManager` desde un archivo de licencia firmada usando
    /// una clave raíz de confianza EXPLÍCITA. Esta es la vía a usar por
    /// callers que ya tienen el root resuelto desde su propia config confiable
    /// (sin depender del entorno del proceso).
    ///
    /// # Errors
    ///
    /// Devuelve error si el archivo no existe, la firma no es válida o no
    /// coincide con `root_hex`.
    pub fn from_file_with_root(path: impl AsRef<std::path::Path>, root_hex: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| format!("cannot read license: {e}"))?;
        let signed: SignedLicense =
            serde_json::from_str(&content).map_err(|e| format!("invalid license (must be signed): {e}"))?;

        signed.verify(root_hex)?;

        let license = signed.license()?;
        Ok(Self { license })
    }

    /// Obtener el tier actual.
    #[must_use]
    pub const fn tier(&self) -> LicenseTier {
        self.license.tier
    }

    /// Verificar si un feature está disponible.
    ///
    /// Una licencia expirada NO habilita ningún feature (P1-9).
    #[must_use]
    pub fn has_feature(&self, feature: &Feature) -> bool {
        if self.is_expired() {
            return false;
        }
        // Verificar feature por tier
        if feature.available_in(self.license.tier) {
            return true;
        }
        // Verificar feature en lista de features adicionales
        self.license.features.iter().any(|f| f == feature.name())
    }

    /// Verificar si la licencia es Pro (y no está expirada).
    #[must_use]
    pub fn is_pro(&self) -> bool {
        !self.is_expired() && matches!(self.license.tier, LicenseTier::Pro)
    }

    /// Verificar si la licencia ha expirado.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(ref expires) = self.license.expires_at {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires) {
                return chrono::Utc::now() > expiry;
            }
        }
        false
    }

    /// Generar un reporte de estado de licencia.
    #[must_use]
    pub fn report(&self) -> String {
        let tier_str = match self.license.tier {
            LicenseTier::Free => "Free (open-core)",
            LicenseTier::Pro => "Pro",
        };
        let expiry = self.license.expires_at.as_deref().unwrap_or("perpetua");
        let features: Vec<&str> = [
            Feature::Dashboard,
            Feature::Alerts,
            Feature::PremiumPacks,
            Feature::RuleEditor,
            Feature::TeamPolicies,
            Feature::MultiChannelAlerts,
        ]
        .iter()
        .filter(|f| self.has_feature(f))
        .map(Feature::name)
        .collect();

        format!(
            "Licencia: {tier_str}\nEmail: {}\nID: {}\nExpira: {expiry}\nFeatures: {}",
            self.license.email,
            self.license.license_id,
            features.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    /// Guard para serializar los tests que mutan el entorno del proceso.
    /// `std::env` es global: con `--test-threads=N` hay carrera entre tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn free_tier_by_default() {
        let mgr = LicenseManager::free();
        assert_eq!(mgr.tier(), LicenseTier::Free);
        assert!(!mgr.is_pro());
    }

    #[test]
    fn free_tier_has_no_pro_features() {
        let mgr = LicenseManager::free();
        assert!(!mgr.has_feature(&Feature::Dashboard));
        assert!(!mgr.has_feature(&Feature::Alerts));
        assert!(!mgr.has_feature(&Feature::PremiumPacks));
    }

    #[test]
    fn pro_tier_has_all_features() {
        let license = License {
            tier: LicenseTier::Pro,
            email: "test@example.com".to_string(),
            license_id: "pro-123".to_string(),
            expires_at: None,
            features: Vec::new(),
        };
        let mgr = LicenseManager { license };
        assert!(mgr.is_pro());
        assert!(mgr.has_feature(&Feature::Dashboard));
        assert!(mgr.has_feature(&Feature::Alerts));
    }

    fn test_keypair() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    fn signed_license_json(license: &License) -> String {
        use ed25519_dalek::Signer;
        let keypair = test_keypair();
        let license_json = serde_json::to_string(license).expect("serialize license");
        let signature = keypair.sign(license_json.as_bytes());
        let signed = SignedLicense {
            license_json,
            signature_hex: hex::encode(signature.to_bytes().as_slice()),
            signer_public_key_hex: hex::encode(keypair.verifying_key().as_bytes()),
            owner_public_key_hex: None,
        };
        serde_json::to_string(&signed).expect("serialize signed license")
    }

    #[test]
    fn unsigned_license_rejected() {
        let license = License {
            tier: LicenseTier::Pro,
            email: "dev@cerberus.dev".to_string(),
            license_id: "pro-abc".to_string(),
            expires_at: None,
            features: vec!["custom_feature".to_string()],
        };
        let tmp = NamedTempFile::new().unwrap();
        // JSON plano (sin firma) → rechazado (P1-9).
        std::fs::write(tmp.path(), serde_json::to_string(&license).unwrap()).unwrap();
        assert!(LicenseManager::from_file(tmp.path()).is_err());
    }

    #[test]
    fn license_without_trust_root_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Regresión revisión 2 (P1 #3): sin ningún trust root externo, la
        // licencia "firmada" NO debe pasar.
        let license = License {
            tier: LicenseTier::Pro,
            email: "dev@cerberus.dev".to_string(),
            license_id: "pro-abc".to_string(),
            expires_at: None,
            features: Vec::new(),
        };
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), signed_license_json(&license)).unwrap();
        // Sin env ni clave embebida en build time → error.
        std::env::remove_var("CERBERUS_LICENSE_PUBLIC_KEY");
        assert!(
            LicenseManager::from_file(tmp.path()).is_err(),
            "sin trust root no debe pasar"
        );
    }

    #[test]
    fn license_from_file_signed_with_env_root() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let license = License {
            tier: LicenseTier::Pro,
            email: "dev@cerberus.dev".to_string(),
            license_id: "pro-abc".to_string(),
            expires_at: None,
            features: vec!["custom_feature".to_string()],
        };
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), signed_license_json(&license)).unwrap();

        let root_hex = hex::encode(test_keypair().verifying_key().as_bytes());
        std::env::set_var("CERBERUS_LICENSE_PUBLIC_KEY", &root_hex);
        // Sanidad: la root explícita coincide con la del env.
        assert!(LicenseManager::from_file_with_root(tmp.path(), &root_hex).is_ok());
        let mgr = LicenseManager::from_file(tmp.path()).unwrap();
        assert!(mgr.is_pro());
        assert!(mgr.has_feature(&Feature::Dashboard));
    }

    #[test]
    fn license_rejects_owner_key_as_untrusted_root() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // P0: ataque de licencia autofirmada. El atacante genera su clave,
        // firma una License Pro y pone ESA MISMA clave como signer y como
        // owner_public_key_hex. Nada de eso puede servir de trust root.
        let license = License {
            tier: LicenseTier::Pro,
            email: "attacker@evil.dev".to_string(),
            license_id: "pro-forged".to_string(),
            expires_at: None,
            features: Vec::new(),
        };
        let keypair = test_keypair();
        let license_json = serde_json::to_string(&license).unwrap();
        let signature = ed25519_dalek::Signer::sign(&keypair, license_json.as_bytes());
        let signed = SignedLicense {
            license_json,
            signature_hex: hex::encode(signature.to_bytes().as_slice()),
            signer_public_key_hex: hex::encode(keypair.verifying_key().as_bytes()),
            owner_public_key_hex: Some(hex::encode(keypair.verifying_key().as_bytes())),
        };
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), serde_json::to_string(&signed).unwrap()).unwrap();
        std::env::remove_var("CERBERUS_LICENSE_PUBLIC_KEY");

        // owner_public_key_hex del archivo NO es trust root → rechazo.
        assert!(
            LicenseManager::from_file(tmp.path()).is_err(),
            "owner key del propio archivo no debe ser trust root"
        );

        // Con el root EXPLÍCITO correcto (la misma clave, vía param) → acepta.
        let mgr =
            LicenseManager::from_file_with_root(tmp.path(), &hex::encode(keypair.verifying_key().as_bytes())).unwrap();
        assert!(mgr.is_pro());
    }

    #[test]
    fn tampered_signed_license_rejected() {
        let license = License {
            tier: LicenseTier::Pro,
            email: "dev@cerberus.dev".to_string(),
            license_id: "pro-abc".to_string(),
            expires_at: None,
            features: Vec::new(),
        };
        let mut signed: SignedLicense = serde_json::from_str(&signed_license_json(&license)).expect("parse signed");
        // Firmado por otra clave (attacker).
        let other = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        signed.signer_public_key_hex = hex::encode(other.verifying_key().as_bytes());
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), serde_json::to_string(&signed).expect("serialize")).unwrap();
        let root_hex = hex::encode(test_keypair().verifying_key().as_bytes());
        assert!(
            LicenseManager::from_file_with_root(tmp.path(), &root_hex).is_err(),
            "clave del atacante no debe pasar"
        );
    }

    #[test]
    fn expired_pro_not_pro() {
        let license = License {
            tier: LicenseTier::Pro,
            email: "x@y.dev".to_string(),
            license_id: "exp".to_string(),
            expires_at: Some("2020-01-01T00:00:00Z".to_string()),
            features: Vec::new(),
        };
        let mgr = LicenseManager { license };
        assert!(
            !mgr.is_pro(),
            "licencia expirada no debe contar como Pro (revisión 2, P1 #3)"
        );
    }

    #[test]
    fn expired_license_has_no_features() {
        let license = License {
            tier: LicenseTier::Pro,
            email: "test@example.com".to_string(),
            license_id: "expired-1".to_string(),
            expires_at: Some("2020-01-01T00:00:00Z".to_string()),
            features: Vec::new(),
        };
        let mgr = LicenseManager { license };
        assert!(mgr.is_expired());
        assert!(
            !mgr.has_feature(&Feature::Dashboard),
            "expired license must not grant features"
        );
    }

    #[test]
    fn expired_license_detected() {
        let license = License {
            tier: LicenseTier::Pro,
            email: "test@example.com".to_string(),
            license_id: "expired-1".to_string(),
            expires_at: Some("2020-01-01T00:00:00Z".to_string()),
            features: Vec::new(),
        };
        let mgr = LicenseManager { license };
        assert!(mgr.is_expired());
    }

    #[test]
    fn license_report_includes_info() {
        let mgr = LicenseManager::free();
        let report = mgr.report();
        assert!(report.contains("Free"));
        assert!(report.contains("perpetua"));
    }

    #[test]
    fn custom_feature_via_list() {
        let license = License {
            tier: LicenseTier::Free,
            email: "test@example.com".to_string(),
            license_id: "custom-1".to_string(),
            expires_at: None,
            features: vec!["dashboard".to_string()],
        };
        let mgr = LicenseManager { license };
        assert!(mgr.has_feature(&Feature::Dashboard));
    }

    #[test]
    fn feature_available_in_returns_false_for_free() {
        assert!(!Feature::Dashboard.available_in(LicenseTier::Free));
        assert!(Feature::Dashboard.available_in(LicenseTier::Pro));
    }
}
