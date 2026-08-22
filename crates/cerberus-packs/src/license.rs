//! Free/Pro entitlement system for Cerberus (§7 of the build plan).
//!
//! The engine and the basic local mode remain free (Free). Pro features
//! (advanced dashboard, premium rules, alerts, etc.) are activated via a
//! license file.

use serde::{Deserialize, Serialize};

/// License tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Free (open-core): basic engine, local proxy, basic rule packs.
    #[default]
    Free,
    /// Pro: premium packs, dashboard, alerts, per-team policies.
    Pro,
}

/// Information about a license.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// License tier.
    pub tier: LicenseTier,
    /// Holder email.
    pub email: String,
    /// License identifier.
    pub license_id: String,
    /// Expiration date `ISO 8601` (None = perpetual).
    pub expires_at: Option<String>,
    /// Additional enabled features.
    pub features: Vec<String>,
}

/// Signed license (Ed25519 signature of the issuer over the license JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    /// Serialized license JSON (what is signed).
    pub license_json: String,
    /// Ed25519 signature in hex.
    pub signature_hex: String,
    /// Signer public key in hex.
    pub signer_public_key_hex: String,
    /// Holder key, ONLY as metadata (P0: it is not a trust root).
    ///
    /// What the attacker puts here MUST always be ignored when verifying:
    /// the trust root can only come from `CERBERUS_LICENSE_PUBLIC_KEY`,
    /// from `CERBERUS_EMBEDDED_LICENSE_KEY` (build time) or from
    /// [`LicenseManager::from_file_with_root`].
    #[serde(default)]
    pub owner_public_key_hex: Option<String>,
}

/// Root public key embedded at build time (optional).
///
/// It is set by compiling with `CERBERUS_EMBEDDED_LICENSE_KEY=<hex>`. As long
/// as it is not defined at build time, this constant is `None` and
/// `from_file` will only trust `CERBERUS_LICENSE_PUBLIC_KEY`.
pub const EMBEDDED_LICENSE_PUBLIC_KEY: Option<&'static str> = option_env!("CERBERUS_EMBEDDED_LICENSE_KEY");

impl SignedLicense {
    /// Verify the license signature against the given public key.
    ///
    /// The given key must come from an EXTERNAL trust source:
    /// deployment env, a build-time embedded key, or an explicit parameter
    /// of [`LicenseManager::from_file_with_root`].
    /// `owner_public_key_hex` from the file itself MUST NEVER be used as root
    /// (P0: self-signed license by the attacker).
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or the key does not match.
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

    /// Parse the signed license back into a [`License`].
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is invalid.
    pub fn license(&self) -> Result<License, String> {
        serde_json::from_str(&self.license_json).map_err(|e| format!("invalid license json: {e}"))
    }
}

/// Features available in each tier.
#[derive(Debug, Clone)]
pub enum Feature {
    /// Dashboard with history and statistics.
    Dashboard,
    /// Slack/Teams/webhook alerts.
    Alerts,
    /// Auto-updated premium rule packs.
    PremiumPacks,
    /// Visual rule editor.
    RuleEditor,
    /// Per-team policies and SSO.
    TeamPolicies,
    /// Multi-channel alerts.
    MultiChannelAlerts,
}

impl Feature {
    /// Check whether a feature is available in the given tier.
    #[must_use]
    pub fn available_in(&self, tier: LicenseTier) -> bool {
        tier == LicenseTier::Pro
    }

    /// Get the feature name.
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

/// License manager.
#[derive(Debug, Clone)]
pub struct LicenseManager {
    /// Active license.
    license: License,
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::free()
    }
}

impl LicenseManager {
    /// Create a `LicenseManager` with Free tier.
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

    /// Create a `LicenseManager` from a signed license file.
    ///
    /// The signature is ALWAYS verified against an external trust root:
    /// `CERBERUS_LICENSE_PUBLIC_KEY` (env, recommended) or, if not set, the
    /// build-time embedded key via `CERBERUS_EMBEDDED_LICENSE_KEY` (see
    /// [`EMBEDDED_LICENSE_PUBLIC_KEY`]).
    /// The `owner_public_key_hex` field of the file itself is NEVER used as a
    /// trust root (P0: self-signed license by the attacker). With no root
    /// configured the license is rejected (fail-closed). A plain JSON is
    /// also rejected. (Review 2 regression, P1 #3.)
    ///
    /// For an explicit root, use [`Self::from_file_with_root`].
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, no trust root is
    /// configured, or the signature is invalid.
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

    /// Create a `LicenseManager` from a signed license file using an
    /// EXPLICIT trust root key. This is the path to use for callers that
    /// already have the root resolved from their own trusted config (without
    /// depending on the process environment).
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, the signature is invalid,
    /// or it does not match `root_hex`.
    pub fn from_file_with_root(path: impl AsRef<std::path::Path>, root_hex: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| format!("cannot read license: {e}"))?;
        let signed: SignedLicense =
            serde_json::from_str(&content).map_err(|e| format!("invalid license (must be signed): {e}"))?;

        signed.verify(root_hex)?;

        let license = signed.license()?;
        Ok(Self { license })
    }

    /// Get the current tier.
    #[must_use]
    pub const fn tier(&self) -> LicenseTier {
        self.license.tier
    }

    /// Check whether a feature is available.
    ///
    /// An expired license does NOT enable any feature (P1-9).
    #[must_use]
    pub fn has_feature(&self, feature: &Feature) -> bool {
        if self.is_expired() {
            return false;
        }
        // Check feature by tier
        if feature.available_in(self.license.tier) {
            return true;
        }
        // Check feature in the additional features list
        self.license.features.iter().any(|f| f == feature.name())
    }

    /// Check whether the license is Pro (and not expired).
    #[must_use]
    pub fn is_pro(&self) -> bool {
        !self.is_expired() && matches!(self.license.tier, LicenseTier::Pro)
    }

    /// Check whether the license has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(ref expires) = self.license.expires_at {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires) {
                return chrono::Utc::now() > expiry;
            }
        }
        false
    }

    /// Generate a license status report.
    #[must_use]
    pub fn report(&self) -> String {
        let tier_str = match self.license.tier {
            LicenseTier::Free => "Free (open-core)",
            LicenseTier::Pro => "Pro",
        };
        let expiry = self.license.expires_at.as_deref().unwrap_or("perpetual");
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
            "License: {tier_str}\nEmail: {}\nID: {}\nExpires: {expiry}\nFeatures: {}",
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

    /// Guard to serialize tests that mutate the process environment.
    /// `std::env` is global: with `--test-threads=N` there is a race between tests.
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
        // Plain JSON (no signature) → rejected (P1-9).
        std::fs::write(tmp.path(), serde_json::to_string(&license).unwrap()).unwrap();
        assert!(LicenseManager::from_file(tmp.path()).is_err());
    }

    #[test]
    fn license_without_trust_root_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Review 2 regression (P1 #3): with no external trust root, the
        // "signed" license MUST NOT pass.
        let license = License {
            tier: LicenseTier::Pro,
            email: "dev@cerberus.dev".to_string(),
            license_id: "pro-abc".to_string(),
            expires_at: None,
            features: Vec::new(),
        };
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), signed_license_json(&license)).unwrap();
        // Without env or build-time embedded key → error.
        std::env::remove_var("CERBERUS_LICENSE_PUBLIC_KEY");
        assert!(
            LicenseManager::from_file(tmp.path()).is_err(),
            "without a trust root it must not pass"
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
        // Sanity: the explicit root matches the env one.
        assert!(LicenseManager::from_file_with_root(tmp.path(), &root_hex).is_ok());
        let mgr = LicenseManager::from_file(tmp.path()).unwrap();
        assert!(mgr.is_pro());
        assert!(mgr.has_feature(&Feature::Dashboard));
    }

    #[test]
    fn license_rejects_owner_key_as_untrusted_root() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // P0: self-signed license attack. The attacker generates their key,
        // signs a Pro License and puts THAT SAME key as signer and as
        // owner_public_key_hex. None of that can serve as a trust root.
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

        // owner_public_key_hex from the file is NOT a trust root → rejected.
        assert!(
            LicenseManager::from_file(tmp.path()).is_err(),
            "owner key from the file itself must not be a trust root"
        );

        // With the correct EXPLICIT root (the same key, via param) → accepted.
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
        // Signed by another key (attacker).
        let other = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        signed.signer_public_key_hex = hex::encode(other.verifying_key().as_bytes());
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), serde_json::to_string(&signed).expect("serialize")).unwrap();
        let root_hex = hex::encode(test_keypair().verifying_key().as_bytes());
        assert!(
            LicenseManager::from_file_with_root(tmp.path(), &root_hex).is_err(),
            "attacker key must not pass"
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
            "expired license must not count as Pro (review 2, P1 #3)"
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
        assert!(report.contains("perpetual"));
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
