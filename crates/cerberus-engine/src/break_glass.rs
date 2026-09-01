//! Break-glass / audited bypass — server-side one-shot primitive (§4.7 of
//! the build plan, R9-8 remediation F2.3).
//!
//! Review 9 (R9-8) found the historical `BreakGlass` struct was **dead code**
//! (no caller outside its own tests) while evidence claimed the feature was
//! BUILT. This module now provides the real primitive:
//!
//! - **Authenticated**: tokens are issued ONLY through the control plane
//!   (`POST /api/break-glass`), which sits behind the existing admin-token
//!   gate (`X-Cerberus-Admin-Token`). No valid admin token → no bypass.
//! - **One-shot**: a nonce is consumed atomically on redemption; a replay is
//!   rejected (`UnknownNonce`) even under concurrency.
//! - **Cryptographic nonce**: 256 bits of CSPRNG output (`getrandom`).
//! - **Short TTL**: every token carries an absolute deadline; expired tokens
//!   are rejected and purged.
//! - **Explicit scope**: a token can be bound to a specific provider; a
//!   redemption from another provider is rejected (`ScopeMismatch`) and the
//!   token stays valid for its intended scope.
//! - **Audited**: the data-plane redemption flows into the existing bypass
//!   audit path (`action_taken = "bypass"`, flags `["bypass", "break-glass"]`,
//!   `bypass-hash:<sha256>`); the header bypass and the (future) CLI share
//!   the same audit trail.
//! - **Never stores the raw reason**: only `sha256` of the truncated reason
//!   is kept (the reason may itself contain secrets).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::engine::hash_value;

/// Maximum TTL accepted for a one-shot token (short-lived by design).
pub const MAX_TTL: Duration = Duration::from_hours(1);

/// Default TTL for a one-shot token.
pub const DEFAULT_TTL: Duration = Duration::from_mins(1);

/// Truncate a bypass reason to at most 200 bytes without cutting a UTF-8
/// char in half (mirrors the proxy-side helper; the result is hashed).
#[must_use]
fn truncate_reason(reason: &str) -> &str {
    const MAX: usize = 200;
    if reason.len() <= MAX {
        return reason;
    }
    let mut end = MAX;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// Explicit scope of a one-shot token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassScope {
    /// When `Some(provider)`, the token is only valid for that provider.
    /// `None` = explicit global scope (any provider).
    pub provider: Option<String>,
}

impl BreakGlassScope {
    /// Scope bound to one provider.
    #[must_use]
    pub fn for_provider(name: impl Into<String>) -> Self {
        Self {
            provider: Some(name.into()),
        }
    }

    /// Explicit global scope.
    #[must_use]
    pub const fn global() -> Self {
        Self { provider: None }
    }

    /// Does this scope cover a redemption for `provider`?
    #[must_use]
    fn covers(&self, provider: Option<&str>) -> bool {
        self.provider
            .as_deref()
            .is_none_or(|p| provider.is_some_and(|req| req == p))
    }
}

impl std::fmt::Display for BreakGlassScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.provider {
            Some(p) => write!(f, "provider:{p}"),
            None => f.write_str("global"),
        }
    }
}

/// A one-shot break-glass token (as returned by `issue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassToken {
    /// 256-bit CSPRNG nonce (hex). The ONLY bearer credential for the bypass.
    pub nonce: String,
    /// Explicit scope.
    pub scope: BreakGlassScope,
    /// SHA-256 of the truncated reason — the raw reason is NEVER stored.
    pub reason_hash: String,
    /// TTL in seconds (informational; redemption uses the absolute deadline).
    pub ttl_secs: u64,
    /// Absolute deadline (Unix epoch nanos, informational for the API).
    pub expires_at_nanos: u64,
}

/// Successful redemption: what the data plane needs to authorize the bypass
/// and write the audit event. Contains no raw secret and no raw reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassGrant {
    /// SHA-256 of the truncated reason (audit trail).
    pub reason_hash: String,
    /// Scope the token was issued for.
    pub scope: BreakGlassScope,
}

/// Why a redemption failed. `Display` never leaks secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakGlassError {
    /// Unknown nonce: never issued, already consumed (replay), or purged.
    UnknownNonce,
    /// The token existed but its TTL elapsed; it was consumed and purged.
    Expired,
    /// The token is scoped to another provider; it was NOT consumed.
    ScopeMismatch {
        /// Provider the token is scoped to.
        scoped_to: String,
    },
}

impl std::fmt::Display for BreakGlassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownNonce => f.write_str("unknown or already-consumed break-glass nonce"),
            Self::Expired => f.write_str("break-glass token expired"),
            Self::ScopeMismatch { scoped_to } => {
                write!(f, "break-glass token is scoped to another provider ({scoped_to})")
            }
        }
    }
}

/// Pending one-shot token held server-side.
struct PendingToken {
    scope: BreakGlassScope,
    reason_hash: String,
    expires_at: Instant,
}

/// Server-side one-shot break-glass ledger.
///
/// Shared between the control plane (issue, authenticated by the admin-token
/// gate) and the data plane (redeem on `X-Cerberus-Bypass: break-glass:<nonce>`).
/// The `Mutex` makes consumption atomic: exactly one concurrent redeemer wins.
pub struct BreakGlassLedger {
    inner: Mutex<HashMap<String, PendingToken>>,
    default_ttl: Duration,
}

impl std::fmt::Debug for BreakGlassLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("break-glass lock poisoned");
        f.debug_struct("BreakGlassLedger")
            .field("pending", &inner.len())
            // The nonce map is intentionally NOT part of Debug output: nonces
            // are bearer credentials (R9-8: nothing secret in Debug/logs).
            .finish_non_exhaustive()
    }
}

impl Default for BreakGlassLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakGlassLedger {
    /// Create a ledger with [`DEFAULT_TTL`] as the default token TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_ttl(DEFAULT_TTL)
    }

    /// Create a ledger with an explicit default TTL (tests / policy).
    #[must_use]
    pub fn new_with_ttl(default_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            default_ttl,
        }
    }

    /// Issue a one-shot token.
    ///
    /// `reason` is truncated to 200 bytes and stored ONLY as its SHA-256.
    /// `ttl` is clamped to `MAX_TTL` at most (short-lived by design); tests
    /// may use sub-second TTLs.
    #[must_use]
    pub fn issue(&self, scope: BreakGlassScope, reason: &str, ttl: Option<Duration>) -> BreakGlassToken {
        let ttl = ttl.unwrap_or(self.default_ttl).min(MAX_TTL);
        let reason_hash = hash_value(truncate_reason(reason));
        let expires_at = Instant::now() + ttl;
        let expires_at_nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos()) + ttl.as_nanos();
        let token = BreakGlassToken {
            nonce: crate::vault::random_nonce_256(),
            scope,
            reason_hash,
            ttl_secs: ttl.as_secs(),
            expires_at_nanos: u64::try_from(expires_at_nanos).unwrap_or(u64::MAX),
        };
        let mut inner = self.inner.lock().expect("break-glass lock poisoned");
        Self::purge_expired_locked(&mut inner);
        inner.insert(
            token.nonce.clone(),
            PendingToken {
                scope: token.scope.clone(),
                reason_hash: token.reason_hash.clone(),
                expires_at,
            },
        );
        token
    }

    /// Redeem a nonce for `provider` (atomic, exactly-once).
    ///
    /// - Unknown / already-consumed → `UnknownNonce` (replay is rejected).
    /// - Expired → `Expired` (the token is consumed and purged).
    /// - Scoped to another provider → `ScopeMismatch`; the token is NOT
    ///   consumed and remains valid for its intended scope.
    ///
    /// # Errors
    ///
    /// See [`BreakGlassError`].
    // The lock guard is intentionally held across remove → expiry check →
    // re-insert: releasing it early would open a window where a concurrent
    // redeemer could consume the token and let the mismatch path re-insert
    // it afterwards (breaking exactly-once). clippy::significant_drop_tightening
    // is therefore deliberately allowed here.
    #[allow(clippy::significant_drop_tightening)]
    pub fn redeem(&self, nonce: &str, provider: Option<&str>) -> Result<BreakGlassGrant, BreakGlassError> {
        let mut inner = self.inner.lock().expect("break-glass lock poisoned");
        // Remove first: concurrent redeemers race on this single removal, so
        // exactly one winner observes the token (one-shot under concurrency).
        // (Expired entries are purged on issue/len — NOT here, so an expired
        // redemption is reported as `Expired`, not `UnknownNonce`.)
        let Some(pending) = inner.remove(nonce) else {
            return Err(BreakGlassError::UnknownNonce);
        };
        if pending.expires_at <= Instant::now() {
            return Err(BreakGlassError::Expired); // consumed + dropped
        }
        if !pending.scope.covers(provider) {
            // Wrong provider: put the token back (not consumed for its scope).
            let scoped_to = pending.scope.provider.clone().unwrap_or_else(|| "global".to_string());
            inner.insert(nonce.to_string(), pending);
            return Err(BreakGlassError::ScopeMismatch { scoped_to });
        }
        Ok(BreakGlassGrant {
            reason_hash: pending.reason_hash,
            scope: pending.scope,
        })
    }

    /// Remove and drop every expired pending token. Returns count purged.
    #[must_use]
    pub fn purge_expired(&self) -> usize {
        let mut inner = self.inner.lock().expect("break-glass lock poisoned");
        Self::purge_expired_locked(&mut inner)
    }

    fn purge_expired_locked(inner: &mut HashMap<String, PendingToken>) -> usize {
        let now = Instant::now();
        let expired: Vec<String> = inner
            .iter()
            .filter(|(_, t)| t.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        let n = expired.len();
        for k in expired {
            inner.remove(&k);
        }
        n
    }

    /// Number of pending (unconsumed, unexpired) tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut inner = self.inner.lock().expect("break-glass lock poisoned");
        Self::purge_expired_locked(&mut inner);
        inner.len()
    }

    /// Is the ledger empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_redemption_returns_grant_with_reason_hash() {
        let ledger = BreakGlassLedger::new();
        let token = ledger.issue(BreakGlassScope::global(), "emergency send", None);
        let grant = ledger.redeem(&token.nonce, Some("openai")).expect("redeem");
        assert_eq!(grant.reason_hash, token.reason_hash);
        assert_eq!(grant.scope, BreakGlassScope::global());
        // Raw reason is never stored anywhere observable.
        assert!(!format!("{token:?}").contains("emergency send"));
        assert!(!format!("{grant:?}").contains("emergency send"));
    }

    #[test]
    fn absent_nonce_rejected() {
        let ledger = BreakGlassLedger::new();
        let err = ledger.redeem(&"a".repeat(64), Some("openai")).unwrap_err();
        assert_eq!(err, BreakGlassError::UnknownNonce);
    }

    #[test]
    fn expired_nonce_rejected() {
        let ledger = BreakGlassLedger::new_with_ttl(Duration::from_millis(10));
        let token = ledger.issue(BreakGlassScope::global(), "late", Some(Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(ledger.redeem(&token.nonce, None).unwrap_err(), BreakGlassError::Expired);
        assert!(ledger.is_empty(), "expired token consumed and purged");
    }

    #[test]
    fn replay_rejected_one_shot() {
        let ledger = BreakGlassLedger::new();
        let token = ledger.issue(BreakGlassScope::global(), "once", None);
        assert!(ledger.redeem(&token.nonce, None).is_ok(), "first use succeeds");
        assert_eq!(
            ledger.redeem(&token.nonce, None).unwrap_err(),
            BreakGlassError::UnknownNonce,
            "second use must fail (one-shot)"
        );
    }

    #[test]
    fn nonce_is_cryptographic_and_unique() {
        let ledger = BreakGlassLedger::new();
        let t1 = ledger.issue(BreakGlassScope::global(), "a", None);
        let t2 = ledger.issue(BreakGlassScope::global(), "b", None);
        assert_ne!(t1.nonce, t2.nonce);
        assert_eq!(t1.nonce.len(), 64, "256-bit hex nonce");
        assert!(t1.nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn two_concurrent_requests_exactly_one_wins() {
        let ledger = std::sync::Arc::new(BreakGlassLedger::new());
        let token = ledger.issue(BreakGlassScope::global(), "race", None);
        let nonce = token.nonce;
        let (tx, rx) = std::sync::mpsc::channel();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        for _ in 0..2 {
            let ledger = std::sync::Arc::clone(&ledger);
            let nonce = nonce.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let tx = tx.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let _ = tx.send(ledger.redeem(&nonce, None).is_ok());
            });
        }
        drop(tx);
        let wins: Vec<bool> = rx.iter().collect();
        assert_eq!(wins.iter().filter(|w| **w).count(), 1, "exactly one redeemer wins");
        assert_eq!(wins.len(), 2);
    }

    #[test]
    fn wrong_provider_rejected_and_token_survives_for_right_scope() {
        let ledger = BreakGlassLedger::new();
        let token = ledger.issue(BreakGlassScope::for_provider("openai"), "scoped", None);
        let err = ledger.redeem(&token.nonce, Some("anthropic")).unwrap_err();
        assert!(
            matches!(err, BreakGlassError::ScopeMismatch { .. }),
            "provider mismatch must be rejected"
        );
        assert_eq!(ledger.len(), 1, "token NOT consumed on scope mismatch");
        // The right provider can still redeem it.
        assert!(ledger.redeem(&token.nonce, Some("openai")).is_ok());
        // Global-scope token covers every provider.
        let global = ledger.issue(BreakGlassScope::global(), "any", None);
        assert!(ledger.redeem(&global.nonce, Some("anthropic")).is_ok());
    }

    #[test]
    fn reason_truncated_and_hashed_never_raw() {
        let ledger = BreakGlassLedger::new();
        let long_reason = format!("reason-with-secret sk-live{} and padding", "x".repeat(500));
        let token = ledger.issue(BreakGlassScope::global(), &long_reason, None);
        // The stored hash is of the TRUNCATED reason; the raw text (and the
        // embedded secret-looking material) is nowhere in the token/ledger.
        assert!(!token.reason_hash.contains("sk-live"));
        assert!(!format!("{token:?}").contains("sk-live"));
        let ledger_dbg = format!("{ledger:?}");
        assert!(!ledger_dbg.contains("sk-live"), "ledger Debug leaks reason");
    }

    #[test]
    fn ttl_clamped_to_max() {
        let ledger = BreakGlassLedger::new();
        let token = ledger.issue(BreakGlassScope::global(), "long", Some(Duration::from_secs(999_999)));
        assert_eq!(token.ttl_secs, MAX_TTL.as_secs(), "TTL clamped (short-lived)");
    }
}
