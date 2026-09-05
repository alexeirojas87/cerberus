//! HMAC-only allowlist fingerprints (R9-7 / F6.3).
//!
//! The false-positive allowlist used to persist the **raw secret value**
//! (`policy.allowlist: ["sk-…"]` in config.yaml, echoed by the API) — R9-7.
//! Since F6.3 every persisted entry is a **fingerprint**:
//!
//! ```text
//! hmac-sha256(installation_key, "cerberus:allowlist:v1" || 0x00 || trimmed_value)
//! ```
//!
//! with the `hmac:` prefix (the [`cerberus_engine::engine::ALLOWLIST_HASH_DOMAIN`]
//! domain, reserved by F5). Consequences:
//!
//! - **Raw values are never persisted** (config.yaml, API responses, logs).
//! - **Matching** computes the HMAC of the candidate on the hot path and
//!   compares fingerprints — the raw value is never stored to compare with.
//! - **Removal** accepts the raw value (computes its fingerprint) or the
//!   fingerprint itself; the raw value is never needed at rest.
//! - **Key rotation invalidates fingerprints** (documented, fail-closed:
//!   previously allowed values start being flagged again and can be
//!   re-added). The installation key is the same one F5 wires for audit
//!   hashes — there is exactly ONE key per installation.
//! - **Store-level write gate**: [`DetectionPolicy::validate`] (the config
//!   store) rejects non-fingerprint entries, and the daemon migrates legacy
//!   raw entries at boot (see `migrate_entries`).

use cerberus_engine::engine::{domain_hash, ALLOWLIST_HASH_DOMAIN};

/// Prefix of a persisted allowlist fingerprint (`hmac:` + 64 lowercase hex).
pub const ALLOWLIST_FINGERPRINT_PREFIX: &str = "hmac:";

/// Normalize + fingerprint an allowlist candidate (R9-7).
///
/// The normalization is `trim()` — exactly what the hot-path matcher compares
/// (the finding raw text is sliced from the scanned body and trimmed), so the
/// value that was allowed by triage is the value that matches at scan time.
/// Values are case-sensitive (secrets are).
#[must_use]
pub fn fingerprint(key: &[u8], value: &str) -> String {
    domain_hash(key, ALLOWLIST_HASH_DOMAIN, value.trim().as_bytes())
}

/// Is `entry` a well-formed allowlist fingerprint (`hmac:` + 64 hex chars)?
///
/// This is the shape check behind the store-level write gate: the config
/// store only ever persists fingerprint-shaped entries; raw values are
/// rejected at validation time (and migrated at daemon boot).
#[must_use]
pub fn is_fingerprint(entry: &str) -> bool {
    entry
        .strip_prefix(ALLOWLIST_FINGERPRINT_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Migrate legacy RAW allowlist entries to fingerprints, in place.
///
/// **Migration decision (R9-7, smallest safe design, documented):** entries
/// that are already fingerprint-shaped are left untouched (idempotent);
/// raw entries are converted with the installation key and their raw form is
/// DESTROYED (never written to a backup file — a raw backup would itself
/// violate the R9-7 invariant "the raw value is never persisted"; the
/// fingerprint cannot recover the value, which is the point). Returns the
/// number of migrated entries so the caller can log the conversion loudly
/// and persist the config atomically.
///
/// Without a key (`None`, test contexts only) nothing is migrated — the
/// entries stay raw and the write gate will reject them at validation; the
/// product daemon always resolves the installation key BEFORE this runs.
pub fn migrate_entries(entries: &mut [String], key: Option<&[u8]>) -> usize {
    let Some(key) = key else { return 0 };
    let mut migrated = 0;
    for entry in entries.iter_mut() {
        if !is_fingerprint(entry) {
            *entry = fingerprint(key, entry);
            migrated += 1;
        }
    }
    migrated
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-installation-key-0123456789ab";

    #[test]
    fn fingerprint_is_deterministic_and_domain_separated() {
        let fp1 = fingerprint(KEY, "sk-EXAMPLE-do-not-flag");
        let fp2 = fingerprint(KEY, "sk-EXAMPLE-do-not-flag");
        assert_eq!(fp1, fp2, "same key + value → same fingerprint");
        assert!(is_fingerprint(&fp1), "shape: {fp1}");
        // Normalization (trim) matches the hot-path matcher: an entry added
        // with surrounding whitespace fingerprints the same as the trimmed
        // value sliced from the scanned body.
        assert_eq!(
            fingerprint(KEY, " sk-EXAMPLE-do-not-flag "),
            fingerprint(KEY, "sk-EXAMPLE-do-not-flag"),
            "trim normalization collapses both sides"
        );
    }

    #[test]
    fn fingerprint_domain_differs_from_other_f5_domains() {
        // Cross-domain confusion must be impossible (F5 AV-8 semantics):
        // the same value under the allowlist domain must differ from the
        // audit-event and break-glass domains.
        let value = b"cross-domain-probe";
        let allow = domain_hash(KEY, ALLOWLIST_HASH_DOMAIN, value);
        let event = domain_hash(KEY, cerberus_engine::engine::AUDIT_EVENT_HASH_DOMAIN, value);
        let glass = domain_hash(KEY, cerberus_engine::engine::BREAK_GLASS_HASH_DOMAIN, value);
        assert_ne!(allow, event);
        assert_ne!(allow, glass);
        // `is_fingerprint` is a SHAPE check (`hmac:` + 64 hex): every F5
        // domain produces the same shape (they are distinguished by the
        // domain string INSIDE the digest, which is what makes the digests
        // above differ — a foreign-domain digest can never equal an
        // allowlist digest for the same value).
        assert!(is_fingerprint(&allow) && is_fingerprint(&event) && is_fingerprint(&glass));
    }

    #[test]
    fn fingerprint_depends_on_the_installation_key() {
        let a = fingerprint(b"key-one---0123456789abcdef", "sk-test");
        let b = fingerprint(b"key-two---0123456789abcdef", "sk-test");
        assert_ne!(a, b, "key rotation invalidates fingerprints (documented)");
        assert!(is_fingerprint(&a) && is_fingerprint(&b));
    }

    #[test]
    fn is_fingerprint_shape_matrix() {
        let good = "hmac:";
        let good = format!("{good}{}", "a".repeat(64));
        assert!(is_fingerprint(&good));
        assert!(!is_fingerprint("hmac:abc"), "too short");
        assert!(!is_fingerprint("hmac:"), "empty");
        assert!(!is_fingerprint(&format!("hmac:{}", "g".repeat(64))), "not hex");
        assert!(!is_fingerprint(&format!("hmac:{}", "a".repeat(63))), "63 hex");
        assert!(
            !is_fingerprint("sha256:0404"),
            "legacy unkeyed scheme is not a fingerprint"
        );
        assert!(
            !is_fingerprint("sk-EXAMPLE-do-not-flag"),
            "raw value is not a fingerprint"
        );
        assert!(!is_fingerprint(""), "empty entry");
    }

    #[test]
    fn migrate_is_idempotent_and_destroys_raw() {
        let raw = "sk-EXAMPLE-do-not-flag";
        let mut entries = vec![raw.to_string(), fingerprint(KEY, "already-keyed")];
        let n = migrate_entries(&mut entries, Some(KEY));
        assert_eq!(n, 1, "only the raw entry migrated");
        assert!(is_fingerprint(&entries[0]));
        assert_eq!(
            entries[1],
            fingerprint(KEY, "already-keyed"),
            "idempotent: fingerprint untouched"
        );
        assert!(!entries.iter().any(|e| e == raw), "raw value destroyed in place");

        // Second run: nothing to do.
        assert_eq!(migrate_entries(&mut entries, Some(KEY)), 0);

        // Without a key: no-op (the write gate will reject raw entries later).
        let mut raw_only = vec![raw.to_string()];
        assert_eq!(migrate_entries(&mut raw_only, None), 0);
        assert_eq!(raw_only[0], raw);
    }
}
