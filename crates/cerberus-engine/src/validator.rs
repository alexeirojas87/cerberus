#![allow(clippy::float_cmp, clippy::unreadable_literal, clippy::unusual_byte_groupings)]
//! Pluggable validators that reduce false positives by confirming a regex
//! match is a real secret or PII value.
//!
//! Validators are named in `Rule.validators` (see §6 of the build plan).
//! The [`ValidatorRegistry`] maps names like `"luhn"`,
//! `"shannon-entropy>4.0"` or `"checksum"` to their implementations.

use std::collections::HashMap;

/// A pluggable validator that confirms a regex match is a real secret/PII.
///
/// Implementations perform checks beyond the regex (checksums, entropy, etc.)
/// to reduce false positives.
pub trait Validator {
    /// Return `true` when `value` passes the validator's check.
    fn validate(&self, value: &str) -> bool;
}

/// Validates credit-card numbers using the Luhn checksum (ISO 7812).
///
/// Strips non-digit characters, doubles every second digit from the right,
/// sums digits, and checks that the total is a multiple of 10.
#[derive(Debug, Clone, Copy, Default)]
pub struct LuhnValidator;

impl Validator for LuhnValidator {
    fn validate(&self, value: &str) -> bool {
        luhn_valid(value)
    }
}

/// Shannon entropy specification parsed from a validator name.
#[derive(Debug, Clone, Copy)]
enum EntropySpec {
    /// Entropy must be strictly greater than the threshold.
    Above(f64),
    /// Entropy must be greater than or equal to the threshold.
    AtLeast(f64),
}

/// Validates that the Shannon entropy of `value` exceeds a threshold.
///
/// Named `"shannon-entropy>N"` (strictly greater) or `"shannon-entropy>=N"`
/// (at least). Without a threshold, defaults to `">3.0"`.
#[derive(Debug, Clone, Copy)]
pub struct ShannonEntropyValidator {
    threshold: f64,
    strict: bool,
}

impl ShannonEntropyValidator {
    /// Create a validator with a strict > threshold.
    #[must_use]
    pub const fn above(threshold: f64) -> Self {
        Self {
            threshold,
            strict: true,
        }
    }

    /// Create a validator with a >= threshold.
    #[must_use]
    pub const fn at_least(threshold: f64) -> Self {
        Self {
            threshold,
            strict: false,
        }
    }

    #[must_use]
    const fn from_spec(spec: EntropySpec) -> Self {
        match spec {
            EntropySpec::Above(t) => Self::above(t),
            EntropySpec::AtLeast(t) => Self::at_least(t),
        }
    }
}

impl Validator for ShannonEntropyValidator {
    fn validate(&self, value: &str) -> bool {
        let h = shannon_entropy(value);
        if self.strict {
            h > self.threshold
        } else {
            h >= self.threshold
        }
    }
}

/// Validates common account-number checksums.
///
/// Currently implements the ISO 7064 mod-97 check used by IBAN.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChecksumValidator;

impl Validator for ChecksumValidator {
    fn validate(&self, value: &str) -> bool {
        iban_valid(value)
    }
}

type ValidatorConstructor = fn() -> Box<dyn Validator>;

fn luhn_ctor() -> Box<dyn Validator> {
    Box::new(LuhnValidator)
}

fn checksum_ctor() -> Box<dyn Validator> {
    Box::new(ChecksumValidator)
}

/// Maps validator names (as they appear in `Rule.validators`) to their
/// implementations.
///
/// Builtin names (`"luhn"`, `"checksum"`) are stored as constructor
/// functions; parametrized names such as `"shannon-entropy>4.0"` are parsed
/// on demand.
#[derive(Debug)]
pub struct ValidatorRegistry {
    builtins: HashMap<String, ValidatorConstructor>,
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorRegistry {
    /// Create a registry with the builtin validators.
    #[must_use]
    pub fn new() -> Self {
        let mut builtins = HashMap::new();
        builtins.insert("luhn".to_string(), luhn_ctor as ValidatorConstructor);
        builtins.insert("checksum".to_string(), checksum_ctor as ValidatorConstructor);
        Self { builtins }
    }

    /// Look up the validator registered under `name`.
    ///
    /// Recognised names:
    /// - `"luhn"` — Luhn checksum for card numbers
    /// - `"checksum"` — IBAN mod-97 checksum
    /// - `"shannon-entropy"` or `"shannon-entropy>N"` / `"shannon-entropy>=N"`
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Box<dyn Validator>> {
        if let Some(ctor) = self.builtins.get(name) {
            return Some(ctor());
        }
        get_validator(name)
    }

    /// Whether `value` passes **all** configured validators.
    ///
    /// An empty `validators` list passes. Unknown validator names **fail
    /// closed** (the value cannot be positively verified, so the finding is
    /// dropped).
    #[must_use]
    pub fn all_pass(&self, validators: &[String], value: &str) -> bool {
        validators
            .iter()
            .all(|name| self.get(name).is_some_and(|v| v.validate(value)))
    }
}

/// Factory: resolve a validator by its rule name.
///
/// This is a convenience function that delegates to the same lookup logic as
/// [`ValidatorRegistry::get`].
#[must_use]
pub fn get_validator(name: &str) -> Option<Box<dyn Validator>> {
    match name {
        "luhn" => Some(luhn_ctor()),
        "checksum" => Some(checksum_ctor()),
        _ => parse_entropy_spec(name)
            .map(|spec| -> Box<dyn Validator> { Box::new(ShannonEntropyValidator::from_spec(spec)) }),
    }
}

/// Compute the Shannon entropy of a string.
///
/// H = -Σ p(c) · log₂ p(c)  where p(c) = count(c) / `total_chars`.
/// Shannon entropy delegated to `entropy::shannon_entropy` (char-level).
pub use crate::entropy::shannon_entropy;

/// Check whether `value` passes the Luhn checksum (ISO 7812).
///
/// Strips non-digit characters, doubles every second digit from the right,
/// sums digits, and checks that the total is a multiple of 10.
#[must_use]
pub fn luhn_valid(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(char::is_ascii_digit)
        .map(|c| u32::from(c as u8 - b'0'))
        .collect();
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits.iter().rev().enumerate().fold(0, |acc, (i, &d)| {
        if i % 2 == 1 {
            let doubled = d * 2;
            if doubled > 9 {
                acc + doubled - 9
            } else {
                acc + doubled
            }
        } else {
            acc + d
        }
    });
    sum.is_multiple_of(10)
}

/// Check whether `value` is a valid IBAN (ISO 13616, mod-97 check).
///
/// Strips whitespace, verifies the country code and check digits, then
/// performs the ISO 7064 mod-97 remainder check.
#[must_use]
pub fn iban_valid(value: &str) -> bool {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = compact.as_bytes();
    if bytes.len() < 15 || bytes.len() > 34 {
        return false;
    }
    if !bytes.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
        return false;
    }
    let mut n: u64 = 0;
    for &b in &bytes[4..] {
        n = apply_iban_char(n, b);
        n %= 97;
    }
    for &b in &bytes[..4] {
        n = apply_iban_char(n, b);
        n %= 97;
    }
    n % 97 == 1
}

/// Accumulate a character into the IBAN mod-97 remainder.
///
/// Digits are appended as one decimal digit; letters A..Z become 10..35
/// (two decimal digits).
#[must_use]
fn apply_iban_char(n: u64, b: u8) -> u64 {
    if b.is_ascii_digit() {
        n * 10 + u64::from(b - b'0')
    } else {
        n * 100 + u64::from(b - b'A' + 10)
    }
}

/// Parse a `"shannon-entropy..."` validator name into an entropy spec.
fn parse_entropy_spec(name: &str) -> Option<EntropySpec> {
    let rest = name.strip_prefix("shannon-entropy")?;
    if rest.is_empty() {
        return Some(EntropySpec::Above(3.0));
    }
    if let Some(threshold_str) = rest.strip_prefix(">=") {
        return threshold_str.trim().parse::<f64>().ok().map(EntropySpec::AtLeast);
    }
    if let Some(threshold_str) = rest.strip_prefix('>') {
        return threshold_str.trim().parse::<f64>().ok().map(EntropySpec::Above);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Luhn
    // -----------------------------------------------------------------------

    #[test]
    fn luhn_valid_card_visa() {
        assert!(luhn_valid("4111111111111111"));
    }

    #[test]
    fn luhn_valid_card_with_spaces() {
        assert!(luhn_valid("4111 1111 1111 1111"));
    }

    #[test]
    fn luhn_invalid_random_number() {
        assert!(!luhn_valid("1234567812345678"));
    }

    #[test]
    fn luhn_too_short() {
        assert!(!luhn_valid("12"));
    }

    #[test]
    fn luhn_empty() {
        assert!(!luhn_valid(""));
    }

    // -----------------------------------------------------------------------
    // Shannon entropy
    // -----------------------------------------------------------------------

    /// Deterministic pseudo-random token generator for tests.
    fn pseudo_random_token(len: usize) -> String {
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut seed: u64 = 0x5EED_C0DE_C0FFEE;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            out.push(ALPHA[(seed >> 33) as usize % ALPHA.len()] as char);
        }
        out
    }

    #[test]
    fn entropy_high_token_passes() {
        let token = pseudo_random_token(40);
        let v = ShannonEntropyValidator::above(4.0);
        assert!(v.validate(&token), "token '{token}' should have entropy > 4.0");
    }

    #[test]
    fn entropy_low_string_fails() {
        let v = ShannonEntropyValidator::above(4.0);
        assert!(!v.validate("aaaa"));
    }

    #[test]
    fn entropy_constant_string() {
        let v = ShannonEntropyValidator::above(0.01);
        // all same char → entropy = 0.0
        assert!(!v.validate("xxxxxxxxxxxxxxxxxx"));
    }

    #[test]
    fn entropy_empty_string() {
        let v = ShannonEntropyValidator::above(0.0);
        assert!(!v.validate(""));
    }

    #[test]
    fn entropy_at_least_threshold() {
        // "ab" has entropy = 1.0
        let v = ShannonEntropyValidator::at_least(1.0);
        assert!(v.validate("ab"));
        let v = ShannonEntropyValidator::above(1.0);
        assert!(!v.validate("ab"));
    }

    // -----------------------------------------------------------------------
    // Shannon entropy function
    // -----------------------------------------------------------------------

    #[test]
    fn shannon_entropy_uniform_two_chars() {
        let h = shannon_entropy("ab");
        assert!((h - 1.0).abs() < 1e-10);
    }

    #[test]
    fn shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    // -----------------------------------------------------------------------
    // IBAN / checksum
    // -----------------------------------------------------------------------

    #[test]
    fn iban_valid_be() {
        assert!(iban_valid("BE68539007547034"));
    }

    #[test]
    fn iban_valid_gb() {
        assert!(iban_valid("GB29NWBK60161331926819"));
    }

    #[test]
    fn iban_valid_with_spaces() {
        assert!(iban_valid("BE68 5390 0754 7034"));
    }

    #[test]
    fn iban_invalid_string() {
        assert!(!iban_valid("INVALID1234"));
    }

    #[test]
    fn iban_too_short() {
        assert!(!iban_valid("DE123"));
    }

    #[test]
    fn iban_lowercase_fails() {
        assert!(!iban_valid("be68539007547034"));
    }

    // -----------------------------------------------------------------------
    // Factory: get_validator
    // -----------------------------------------------------------------------

    #[test]
    fn get_validator_luhn() {
        let v = get_validator("luhn");
        assert!(v.is_some());
        assert!(v.unwrap().validate("4111111111111111"));
    }

    #[test]
    fn get_validator_checksum() {
        let v = get_validator("checksum");
        assert!(v.is_some());
        assert!(v.unwrap().validate("BE68539007547034"));
    }

    #[test]
    fn get_validator_shannon_entropy_bare() {
        let v = get_validator("shannon-entropy");
        assert!(v.is_some());
        // "aaaa" has entropy = 0 < 3.0 default → false
        assert!(!v.unwrap().validate("aaaa"));
    }

    #[test]
    fn get_validator_shannon_entropy_with_threshold() {
        let v = get_validator("shannon-entropy>4.0");
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.validate(&pseudo_random_token(40)));
        assert!(!v.validate("aaaa"));
    }

    #[test]
    fn get_validator_nonexistent() {
        assert!(get_validator("nonexistent").is_none());
    }

    #[test]
    fn get_validator_empty_string() {
        assert!(get_validator("").is_none());
    }

    // -----------------------------------------------------------------------
    // ValidatorRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_get_luhn() {
        let reg = ValidatorRegistry::new();
        let v = reg.get("luhn");
        assert!(v.is_some());
        assert!(v.unwrap().validate("4111111111111111"));
    }

    #[test]
    fn registry_get_nonexistent() {
        let reg = ValidatorRegistry::new();
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn registry_all_pass_empty() {
        let reg = ValidatorRegistry::new();
        assert!(reg.all_pass(&[], "anything"));
    }

    #[test]
    fn registry_all_pass_valid() {
        let reg = ValidatorRegistry::new();
        assert!(reg.all_pass(&["luhn".to_string()], "4111111111111111"));
    }

    #[test]
    fn registry_all_pass_unknown_fails() {
        let reg = ValidatorRegistry::new();
        assert!(!reg.all_pass(&["nonexistent_validator".to_string()], "value"));
    }
}
