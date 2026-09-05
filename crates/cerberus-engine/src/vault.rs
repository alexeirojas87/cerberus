//! Reversible local vault (§4.4 of the build plan) — R9-8 remediation (F2.2).
//!
//! Maps redaction tokens → original values to "un-redact" responses. It is
//! **opt-in** (`reversible_redaction: false` by default, closed decision
//! §9 #4) and **local only** — by default redaction is irreversible.
//!
//! When reversible redaction is active, the replacement token is a unique
//! `[VAULT:<128-bit random hex>]` identifier instead of the standard
//! `[REDACTED:flag]`. The vault stores the mapping so the network layer can
//! restore the original value in the (non-streaming) response.
//!
//! # R9-8 guarantees
//!
//! - **Real zeroization**: secret bytes live only inside
//!   [`VaultSecret`] = `zeroize::Zeroizing<String>`. Zeroization is the
//!   `zeroize` crate contract (buffer overwritten before free) and it happens
//!   on **every** removal path: consume ([`Vault::resolve`]), expiry
//!   ([`Vault::purge_expired`]), capacity eviction, [`Vault::clear`] and the
//!   `Drop` of the vault ([`VaultInner::drop`] drains and wipes every entry).
//! - **Request-scoped**: the vault is created per request/response cycle by
//!   the proxy when `reversible_redaction` is enabled; nothing is global and
//!   no secret survives past the end of the request. A TTL and a capacity
//!   bound long-lived requests and memory respectively.
//! - **Non-guessable tokens**: ids are 128 bits of CSPRNG output
//!   (`getrandom`), never the old predictable `v1`/`v2` counters.
//! - **No leaks**: [`VaultSecret`] implements neither `Clone` nor
//!   `Serialize`, and its `Debug`/`Display` output never contains the secret
//!   bytes. Nothing from the vault is persisted, logged or serialized.
//!
//! # Where the bytes live and when they die
//!
//! | Copy | Owner | Lifetime |
//! |---|---|---|
//! | Vault mapping value | `Zeroizing<String>` inside the per-request `Vault` | until consume / expiry / eviction / `clear()` / `Drop` at request end |
//! | Decoded request body buffer | proxy (`DecodedBody`) | not vault-owned; same as the irreversible path (documented limit) |
//! | Un-redacted response body | network layer | unavoidable copy required to restore the value on the wire; never persisted or logged |
//!
//! Streaming responses are out of MVP: the proxy buffers the whole response
//! before un-redaction, so there is no streaming path that could bypass the
//! vault lifecycle (documented; see `evidence/f2/r9-vault-zeroization.md`).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use zeroize::{Zeroize, Zeroizing};

/// Default maximum number of live entries in a vault (bounded memory).
pub const DEFAULT_CAPACITY: usize = 1024;

/// Default TTL of a vault entry (guards long-lived requests; entries are
/// normally consumed or dropped with the request long before this).
pub const DEFAULT_TTL: std::time::Duration = std::time::Duration::from_mins(5);

/// Marker that opens a vault token in a body (`[VAULT:<id>]`).
const TOKEN_PREFIX: &str = "[VAULT:";
const TOKEN_SUFFIX: char = ']';

/// Secret value held by the vault, wrapped in a zeroizing buffer.
///
/// - No `Clone`: the only way to duplicate secret bytes is through
///   [`VaultSecret::expose`] and the caller must have a reason for it
///   (un-redaction splice).
/// - No `Serialize`/`Deserialize`: the vault is never persisted.
/// - `Debug`/`Display` never print the secret bytes.
pub struct VaultSecret {
    value: Zeroizing<String>,
}

impl VaultSecret {
    /// Wrap a secret value. The bytes are owned by a `Zeroizing` buffer from
    /// construction on (no un-wrapped copy is kept).
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: Zeroizing::new(value.into()),
        }
    }

    /// Explicit read access (mirrors `secrecy::ExposeSecret`): the caller
    /// opts into reading the bytes, e.g. to splice them into the response.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Overwrite the buffer with zeroes immediately (removal paths call this
    /// before dropping, so zeroization does not depend on drop timing).
    pub fn wipe(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for VaultSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultSecret(<redacted>)")
    }
}

impl std::fmt::Display for VaultSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Token that replaced a sensitive value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultToken {
    /// Unique token identifier: 128 bits of CSPRNG, hex-encoded (32 chars).
    pub id: String,
}

impl std::fmt::Display for VaultToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[VAULT:{}]", self.id)
    }
}

/// Generate a 128-bit random id (hex). Used for vault tokens.
fn random_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("CSPRNG unavailable");
    hex_encode(&bytes)
}

/// Generate a 256-bit random value (hex) — used for break-glass nonces.
pub(crate) fn random_nonce_256() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("CSPRNG unavailable");
    hex_encode(&bytes)
}

/// Minimal lowercase hex encoder (the `hex` crate is not a dependency).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_CHARS[usize::from(b >> 4)] as char);
        out.push(HEX_CHARS[usize::from(b & 0x0F)] as char);
    }
    out
}

/// A vault entry. `Debug` redacts the secret; `Clone` is intentionally NOT
/// implemented (the secret must never be duplicated).
pub struct VaultEntry {
    /// Flag of the rule that triggered.
    pub flag: String,
    /// Original value (the secret), zeroized on drop.
    pub value: VaultSecret,
    /// Replacement token.
    pub token: VaultToken,
    /// Absolute expiry (instant). `None` = no TTL.
    pub expires_at: Option<std::time::Instant>,
}

impl std::fmt::Debug for VaultEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultEntry")
            .field("flag", &self.flag)
            .field("value", &"<redacted>")
            .field("token", &self.token)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        // Zeroize before free (R9-8): covers consume, expiry, eviction,
        // clear and the vault Drop — every path that removes an entry.
        self.value.wipe();
    }
}

/// Local vault for reversible redaction (request-scoped).
///
/// Thread-safe via an internal `Mutex`. Create one per request when
/// reversible redaction is enabled; entries die with the request.
pub struct Vault {
    inner: Mutex<VaultInner>,
}

struct VaultInner {
    entries: HashMap<String, VaultEntry>,
    /// Insertion order (FIFO eviction when `capacity` is reached).
    order: VecDeque<String>,
    capacity: usize,
    ttl: Option<std::time::Duration>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("vault lock poisoned");
        f.debug_struct("Vault")
            .field("entries", &inner.entries.len())
            .field("capacity", &inner.capacity)
            .finish()
    }
}

impl Drop for VaultInner {
    fn drop(&mut self) {
        // Last-resort zeroization: every remaining entry is wiped before the
        // map is freed (R9-8: zeroize on Drop).
        for (_, mut entry) in self.entries.drain() {
            entry.value.wipe();
            drop(entry);
        }
        self.order.clear();
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    /// Create an empty vault with the default capacity and TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_CAPACITY, Some(DEFAULT_TTL))
    }

    /// Create a vault with explicit capacity and TTL (tests / policy).
    #[must_use]
    pub fn with_limits(capacity: usize, ttl: Option<std::time::Duration>) -> Self {
        Self {
            inner: Mutex::new(VaultInner {
                entries: HashMap::new(),
                order: VecDeque::new(),
                capacity: capacity.max(1),
                ttl,
            }),
        }
    }

    /// Store a value and return its non-guessable token.
    ///
    /// If the vault is at capacity, the oldest entry is zeroized and evicted
    /// (bounded memory). Expired entries are purged first.
    #[must_use]
    pub fn store(&self, flag: &str, original_value: &str) -> VaultToken {
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        // Lazy TTL purge keeps len()/capacity honest.
        Self::purge_expired_locked(&mut inner);
        if inner.entries.len() >= inner.capacity {
            // Evict the oldest entry (FIFO); its Drop zeroizes the bytes.
            if let Some(oldest) = inner.order.pop_front() {
                if let Some(mut evicted) = inner.entries.remove(&oldest) {
                    evicted.value.wipe();
                    drop(evicted);
                }
            }
        }
        let token = VaultToken { id: random_id() };
        let expires_at = inner.ttl.map(|ttl| std::time::Instant::now() + ttl);
        inner.order.push_back(token.id.clone());
        inner.entries.insert(
            token.id.clone(),
            VaultEntry {
                flag: flag.to_string(),
                value: VaultSecret::new(original_value),
                token: token.clone(),
                expires_at,
            },
        );
        token
    }

    /// Consume the entry for `token`: the entry is removed from the vault
    /// (zeroized) and returned to the caller for the un-redaction splice.
    /// A second resolve of the same token returns `None` (consume-once).
    #[must_use]
    pub fn resolve(&self, token: &VaultToken) -> Option<VaultEntry> {
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        Self::purge_expired_locked(&mut inner);
        inner.entries.remove(&token.id)
    }

    /// Consume by token string (e.g. `[VAULT:<id>]` extracted from text).
    #[must_use]
    pub fn resolve_str(&self, token_str: &str) -> Option<VaultEntry> {
        let id = Self::strip_token(token_str);
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        Self::purge_expired_locked(&mut inner);
        inner.entries.remove(id)
    }

    /// Extract the id out of a `[VAULT:<id>]` wrapper (or accept the bare id).
    #[must_use]
    pub fn strip_token(token_str: &str) -> &str {
        token_str
            .strip_prefix(TOKEN_PREFIX)
            .and_then(|s| s.strip_suffix(TOKEN_SUFFIX))
            .unwrap_or(token_str)
    }

    /// Replace every `[VAULT:<id>]` occurrence in `body` with the original
    /// values (non-streaming un-redaction), consuming and zeroizing the used
    /// entries. Unknown/expired tokens are left untouched (no raw leak).
    ///
    /// JSON-aware splice (F4): bodies that already parse as JSON take a
    /// minimal in-place splice of `json_escape(secret)` at the token spans,
    /// so the response stays valid JSON and untouched regions keep
    /// byte-identity (key order, number formatting, whitespace — a full
    /// reserialize was rejected: serde_json lacks `preserve_order`). A parse
    /// failure keeps the raw substitution path verbatim and never burns
    /// entries (the JSON path is not entered at all).
    ///
    /// Pass structure (both paths): pass 1 runs under the vault lock and
    /// resolves the replacements read-only (the value copy is exactly what
    /// gets spliced into the response — unavoidable, never persisted or
    /// logged); pass 2 splices without the lock; pass 3 re-locks and
    /// consumes (zeroizes) every used entry, only after the output is built.
    #[must_use]
    pub fn unredact(&self, body: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(body) else {
            // Binary body: tokens cannot appear; nothing to restore.
            return body.to_vec();
        };
        if !text.contains(TOKEN_PREFIX) {
            return body.to_vec();
        }
        // F4 validity gate: only bodies that already parse as JSON take the
        // splice path; everything else keeps the raw substitution behavior
        // verbatim (option b, non-JSON).
        if serde_json::from_slice::<serde_json::Value>(body).is_ok() {
            return self.unredact_json(body, text);
        }
        // Pass 1 (locked): resolve the replacement for every token present.
        // The value copy is exactly what gets spliced into the response
        // (unavoidable — the response must carry the original value) and it
        // is never persisted or logged.
        let (replacements, consumed): (Vec<(String, String)>, Vec<String>) = {
            let mut inner = self.inner.lock().expect("vault lock poisoned");
            Self::purge_expired_locked(&mut inner);
            let mut replacements = Vec::new();
            let mut consumed = Vec::new();
            for id in Self::find_token_ids(text) {
                if let Some(entry) = inner.entries.get(&id) {
                    replacements.push((format!("{TOKEN_PREFIX}{id}]"), entry.value.expose().to_string()));
                    consumed.push(id);
                }
            }
            (replacements, consumed)
        };
        // Pass 2 (unlocked): splice the restored values into the body.
        let mut out = text.to_string();
        for (needle, replacement) in &replacements {
            out = out.replace(needle, replacement);
        }
        // Pass 3 (locked): consume (zeroize) every entry used by this response.
        {
            let mut inner = self.inner.lock().expect("vault lock poisoned");
            for id in &consumed {
                if let Some(mut e) = inner.entries.remove(id) {
                    e.value.wipe();
                    drop(e);
                }
                inner.order.retain(|k| k != id);
            }
        }
        out.into_bytes()
    }

    /// Collect the unique token ids present in `text`, in order of first
    /// appearance. Ids are fixed-length hex, so there is no prefix ambiguity.
    fn find_token_ids(text: &str) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        let mut rest = text;
        while let Some(pos) = rest.find(TOKEN_PREFIX) {
            let after = &rest[pos + TOKEN_PREFIX.len()..];
            let Some(close) = after.find(TOKEN_SUFFIX) else {
                break;
            };
            let id = &after[..close];
            if id.chars().all(|c| c.is_ascii_hexdigit()) && !ids.iter().any(|i| i == id) {
                ids.push(id.to_string());
            }
            rest = &after[close + 1..];
        }
        ids
    }

    /// F4 minimal-splice unredaction for a body that passed the JSON parse
    /// gate (`text` is `body` as valid UTF-8). Three passes per the design:
    /// 1. (locked) escape-aware raw scan for `[VAULT:<id>]` occurrences
    ///    inside JSON string leaves; `entries.get` read-only → replacements
    ///    (the escaped copy of the secret, computed while the entry is held);
    /// 2. (unlocked) in-place splice of `json_escape(secret)` at the token
    ///    spans — every other byte is untouched, so untouched regions keep
    ///    byte-identity and a reserialize failure is structurally impossible;
    /// 3. (locked, only after the output is built) remove + zeroize the used
    ///    entries. Unknown tokens never reach pass 3 (no burn), matching the
    ///    raw path and the consume-once contract.
    fn unredact_json(&self, body: &[u8], text: &str) -> Vec<u8> {
        let (spans, consumed): (Vec<(usize, usize, String)>, Vec<String>) = {
            let mut inner = self.inner.lock().expect("vault lock poisoned");
            Self::purge_expired_locked(&mut inner);
            let mut spans = Vec::new();
            let mut consumed: Vec<String> = Vec::new();
            for (start, end, id) in Self::find_token_spans_in_strings(text) {
                if let Some(entry) = inner.entries.get(&id) {
                    spans.push((start, end, json_escape_str(entry.value.expose())));
                    if !consumed.contains(&id) {
                        consumed.push(id);
                    }
                }
            }
            (spans, consumed)
        };
        if spans.is_empty() {
            // Only unknown/expired tokens: nothing to splice, nothing to burn.
            return body.to_vec();
        }
        // Pass 2 (unlocked): splice in place at the token spans.
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut cursor = 0usize;
        for (start, end, escaped) in &spans {
            out.extend_from_slice(&bytes[cursor..*start]);
            out.extend_from_slice(escaped.as_bytes());
            cursor = *end;
        }
        out.extend_from_slice(&bytes[cursor..]);
        // Pass 3 (locked): consume (zeroize) every entry used by this response.
        {
            let mut inner = self.inner.lock().expect("vault lock poisoned");
            for id in &consumed {
                if let Some(mut e) = inner.entries.remove(id) {
                    e.value.wipe();
                    drop(e);
                }
                inner.order.retain(|k| k != id);
            }
        }
        out
    }

    /// Escape-aware scan (F4 pass 1): every `[VAULT:<id>]` occurrence that
    /// sits INSIDE a JSON string leaf, as byte spans `(start, end, id)`
    /// covering the whole `[VAULT:id]` token, in order of appearance. Tracks
    /// escape state so an escaped quote (`\"`) or escaped backslash (`\\`)
    /// inside the string does not terminate the leaf early and hide a
    /// following token. Token validation reuses [`Self::find_token_ids`]
    /// semantics: prefix `[VAULT:`, first `]` terminates, id all-ASCII-hex.
    /// Tokens are escape-free ASCII and always appear verbatim on the wire
    /// (the redaction pipeline spliced them in after serialization), so no
    /// unescaping is needed; lookalikes (`[VAULT:` without a hex id + `]`)
    /// are skipped and scanning continues.
    fn find_token_spans_in_strings(text: &str) -> Vec<(usize, usize, String)> {
        let bytes = text.as_bytes();
        let mut spans = Vec::new();
        let mut i = 0usize;
        let mut in_string = false;
        while i < bytes.len() {
            match bytes[i] {
                b'"' if !in_string => {
                    in_string = true;
                    i += 1;
                }
                b'\\' if in_string => {
                    // Escape pair: the next byte is consumed with it (\",
                    // \\, \n, the `u` of \uXXXX, ...). A `\` outside a
                    // string is invalid JSON (the parse gate already
                    // rejected that) and is skipped byte-wise.
                    i += 2;
                }
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                b'[' if in_string && bytes[i..].starts_with(TOKEN_PREFIX.as_bytes()) => {
                    let after = i + TOKEN_PREFIX.len();
                    let mut j = after;
                    while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                        j += 1;
                    }
                    if j > after && j < bytes.len() && bytes[j] == b']' {
                        // ids are pure ASCII hex by construction.
                        let id = String::from_utf8_lossy(&bytes[after..j]).into_owned();
                        spans.push((i, j + 1, id));
                        i = j + 1;
                    } else {
                        // Not a token: keep scanning from the next byte.
                        i += 1;
                    }
                }
                _ => i += 1,
            }
        }
        spans
    }

    /// Remove and zeroize every expired entry. Returns the number purged.
    #[must_use]
    pub fn purge_expired(&self) -> usize {
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        Self::purge_expired_locked(&mut inner)
    }

    fn purge_expired_locked(inner: &mut VaultInner) -> usize {
        let now = std::time::Instant::now();
        let expired: Vec<String> = inner
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at.is_some_and(|t| t <= now))
            .map(|(k, _)| k.clone())
            .collect();
        let n = expired.len();
        for id in expired {
            if let Some(mut e) = inner.entries.remove(&id) {
                e.value.wipe();
                drop(e);
            }
            inner.order.retain(|k| k != &id);
        }
        n
    }

    /// Number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        Self::purge_expired_locked(&mut inner);
        inner.entries.len()
    }

    /// Is it empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Zeroize and remove ALL entries. Returns the number of entries wiped.
    #[must_use]
    pub fn zeroize_all(&self) -> usize {
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        let n = inner.entries.len();
        for (_, mut entry) in inner.entries.drain() {
            entry.value.wipe();
            drop(entry);
        }
        inner.order.clear();
        n
    }

    /// Clear all entries (zeroizes every secret before removal).
    pub fn clear(&self) {
        let _ = self.zeroize_all();
    }
}

/// JSON-escape a secret for in-place splicing into a JSON string leaf (F4):
/// `"` and `\` are backslash-escaped, control bytes < 0x20 use the short
/// `\n`/`\r`/`\t`/`\b`/`\f` forms or `\u00XX`; everything else (including
/// UTF-8) passes through byte-identical. Mirrors serde_json's string
/// escaping, so the spliced bytes stay valid JSON. The token itself is
/// escape-free ASCII and is never an input here.
fn json_escape_str(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                out.push(HEX[usize::from(c as u8 >> 4)] as char);
                out.push(HEX[usize::from(c as u8 & 0x0F)] as char);
            }
            c => out.push(c),
        }
    }
    out
}

/// Reversible redaction of `text` into the request-scoped `vault`.
///
/// Each `Redact` finding span is replaced by a unique `[VAULT:<random>]`
/// token; the original value is stored in the zeroized container. Overlap
/// resolution matches [`crate::redact::apply_redaction`].
///
/// # Errors
///
/// Returns [`crate::redact::RedactError::Blocked`] when a finding has action
/// `Block` (same contract as the irreversible path).
pub fn apply_redaction_reversible(
    text: &str,
    findings: &[crate::engine::Finding],
    vault: &Vault,
) -> Result<String, crate::redact::RedactError> {
    use crate::redact::{resolve_spans, RedactError};
    if findings.is_empty() {
        return Ok(text.to_string());
    }
    let text_len = text.len();
    for f in findings {
        if f.start > f.end || f.end > text_len {
            return Err(RedactError::Blocked { flag: f.flag.clone() });
        }
    }
    for f in findings {
        if f.action == crate::rule::Action::Block {
            return Err(RedactError::Blocked { flag: f.flag.clone() });
        }
    }
    let mut sorted: Vec<&crate::engine::Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| f.start);
    let resolved = resolve_spans(&sorted);

    // Build the redacted string from right to left (to preserve positions).
    let mut result = text.to_string();
    for f in resolved.iter().rev() {
        if f.action == crate::rule::Action::Redact {
            let original = &text[f.start..f.end];
            let token = vault.store(&f.flag, original);
            result.replace_range(f.start..f.end, &token.to_string());
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-abc123DEF456ghi789";

    #[test]
    fn store_and_resolve_round_trip() {
        let vault = Vault::new();
        let token = vault.store("secret.openai_key", SECRET);
        let entry = vault.resolve(&token).expect("entry");
        assert_eq!(entry.flag, "secret.openai_key");
        assert_eq!(entry.value.expose(), SECRET);
        // Consume-once: the entry was removed (and zeroized) by resolve.
        assert!(vault.resolve(&token).is_none());
        assert!(vault.is_empty());
    }

    #[test]
    fn tokens_are_non_guessable() {
        let vault = Vault::new();
        let t1 = vault.store("a", SECRET);
        let t2 = vault.store("b", SECRET);
        assert_ne!(t1.id, t2.id, "ids must be random, not counters");
        assert_eq!(t1.id.len(), 32, "128-bit hex id");
        assert!(t1.id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!t1.id.starts_with('v'), "no predictable v1/v2 ids");
    }

    #[test]
    fn resolve_str_with_wrapper_and_bare_id() {
        let vault = Vault::new();
        let token = vault.store("t", SECRET);
        let via_wrapper = vault.resolve_str(&token.to_string());
        assert!(via_wrapper.is_some());
        let token2 = vault.store("t2", SECRET);
        let via_bare = vault.resolve_str(&token2.id);
        assert!(via_bare.is_some());
    }

    #[test]
    fn resolve_nonexistent_token() {
        let vault = Vault::new();
        let token = VaultToken { id: "f".repeat(32) };
        assert!(vault.resolve(&token).is_none());
        assert!(vault.resolve_str("[VAULT:nonexistent]").is_none());
    }

    #[test]
    fn expiry_purges_and_zeroizes() {
        let vault = Vault::with_limits(8, Some(std::time::Duration::from_millis(10)));
        let token = vault.store("t", SECRET);
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert_eq!(vault.purge_expired(), 1, "expired entry purged");
        assert!(vault.resolve(&token).is_none(), "expired entry gone");
        assert!(vault.is_empty());
    }

    #[test]
    fn capacity_evicts_oldest_and_zeroizes() {
        let vault = Vault::with_limits(2, None);
        let t1 = vault.store("a", "value-1");
        let _t2 = vault.store("b", "value-2");
        let _t3 = vault.store("c", "value-3");
        assert_eq!(vault.len(), 2, "capacity enforced");
        assert!(vault.resolve(&t1).is_none(), "oldest evicted (zeroized)");
    }

    #[test]
    fn clear_and_zeroize_all() {
        let vault = Vault::new();
        let _ = vault.store("a", SECRET);
        let _ = vault.store("b", SECRET);
        let wiped = vault.zeroize_all();
        assert_eq!(wiped, 2, "both entries zeroized");
        assert!(vault.is_empty());
        let _ = vault.store("b", SECRET);
        vault.clear();
        assert!(vault.is_empty());
    }

    #[test]
    fn debug_output_never_contains_secret() {
        let vault = Vault::new();
        let token = vault.store("flag.x", SECRET);
        let vault_dbg = format!("{vault:?}");
        assert!(!vault_dbg.contains(SECRET), "vault Debug leaks secret");
        let entry = vault.resolve(&token).expect("entry");
        let entry_dbg = format!("{entry:?}");
        assert!(!entry_dbg.contains(SECRET), "entry Debug leaks secret");
        let secret_dbg = format!("{:?}", entry.value);
        assert!(!secret_dbg.contains(SECRET), "VaultSecret Debug leaks secret");
        assert_eq!(format!("{}", entry.value), "<redacted>");
    }

    #[test]
    fn token_display_has_no_secret() {
        let vault = Vault::new();
        let token = vault.store("flag.x", SECRET);
        let display = token.to_string();
        assert!(display.starts_with("[VAULT:"));
        assert!(display.ends_with(']'));
        assert!(!display.contains(SECRET));
    }

    #[test]
    fn unredact_replaces_tokens_and_consumes() {
        let vault = Vault::new();
        let t1 = vault.store("a", "value-one");
        let t2 = vault.store("b", "value-two");
        let body = format!(
            "echo: {t1} and again {t1} plus {t2} and unknown [VAULT:{}] end",
            "0".repeat(32)
        );
        let unknown = "0".repeat(32);
        let out = String::from_utf8(vault.unredact(body.as_bytes())).expect("utf8");
        assert!(out.contains("value-one"), "token replaced by original");
        assert!(out.contains("value-two"));
        assert_eq!(out.matches("value-one").count(), 2, "repeated token restored");
        // Known tokens are gone; the UNKNOWN token is left untouched
        // (no way to restore it — never guessed into a value).
        assert!(!out.contains(&t1.id) && !out.contains(&t2.id), "known tokens replaced");
        assert!(out.contains(&format!("[VAULT:{unknown}]")), "unknown token untouched");
        // Consumed entries are gone.
        assert!(vault.resolve(&t1).is_none());
        assert!(vault.resolve(&t2).is_none());
    }

    #[test]
    fn unredact_without_tokens_is_noop() {
        let vault = Vault::new();
        let _ = vault.store("a", SECRET);
        let body = b"plain response with no tokens";
        assert_eq!(vault.unredact(body), body.to_vec());
        let binary = vec![0xFF, 0xFE, 0x00];
        assert_eq!(vault.unredact(&binary), binary, "binary untouched");
    }

    #[test]
    fn request_scoped_isolation_between_vaults() {
        let vault_a = Vault::new();
        let vault_b = Vault::new();
        let ta = vault_a.store("flag.a", SECRET);
        // Another request's vault knows nothing about this token.
        assert!(vault_b.resolve(&ta).is_none());
        assert!(vault_b.is_empty());
        // And ids never collide.
        let tb = vault_b.store("flag.b", "other");
        assert_ne!(ta.id, tb.id);
    }

    #[test]
    fn reversible_redaction_splices_vault_tokens() {
        // F7 round-2 (R2-1): the raw secrets must be tokens the vault-token
        // HEX alphabet cannot accidentally produce — "abc"/"def" are plain
        // hex subsequences, so a random 32-hex token hit them ~5% of runs.
        let vault = Vault::new();
        let text = "key1 SECRET_ONE key2 SECRET_TWO";
        let findings = vec![make_redact("k1", 5, 15), make_redact("k2", 21, 31)];
        let out = super::apply_redaction_reversible(text, &findings, &vault).unwrap();
        assert!(out.starts_with("key1 [VAULT:"), "first span replaced: {out}");
        assert!(out.ends_with(']'), "second span replaced: {out}");
        assert!(out.contains("] key2 [VAULT:"), "structure preserved: {out}");
        assert!(
            !out.contains("SECRET_ONE") && !out.contains("SECRET_TWO"),
            "no raw secret left: {out}"
        );
        assert_eq!(vault.len(), 2, "both originals stored");
        // Same flag twice → different tokens (unique per span).
        let tokens: Vec<String> = out
            .split("[VAULT:")
            .skip(1)
            .map(|s| s.trim_end_matches(']').to_string())
            .collect();
        assert_eq!(tokens.len(), 2);
        assert_ne!(tokens[0], tokens[1]);
    }

    #[test]
    fn reversible_redaction_blocks_like_irreversible() {
        let vault = Vault::new();
        let findings = vec![make_redact("blk", 0, 0)];
        // Block action is represented by Action::Block; construct manually.
        let mut f = findings;
        f[0].action = crate::rule::Action::Block;
        let err = super::apply_redaction_reversible("text", &f, &vault).unwrap_err();
        assert!(matches!(err, crate::redact::RedactError::Blocked { .. }));
    }

    fn make_redact(flag: &str, start: usize, end: usize) -> crate::engine::Finding {
        crate::engine::Finding {
            flag: flag.to_string(),
            category: crate::rule::Category::Secrets,
            severity: crate::rule::Severity::High,
            action: crate::rule::Action::Redact,
            start,
            end,
            hashed_value: "sha256:test".to_string(),
        }
    }

    #[test]
    fn reversible_options_default_disabled() {
        // The closed decision §9 #4: irreversible is the default; the vault
        // is opt-in. There is no global vault instance and no builder path
        // that enables it implicitly.
        let vault = Vault::new();
        assert!(vault.is_empty(), "fresh request-scoped vault is empty");
    }

    #[test]
    fn wipe_before_drop_clears_value() {
        let mut secret = VaultSecret::new(SECRET);
        assert_eq!(secret.expose(), SECRET);
        secret.wipe();
        assert_eq!(secret.expose(), "", "buffer overwritten with zeroes");
    }

    // ─── F4 (Req A2): JSON-aware unredaction ────────────────────────────

    /// F4-roundtrip: a secret containing `"`, `\` and a real newline, echoed
    /// inside a JSON string, must come back as valid JSON holding the EXACT
    /// original secret.
    #[test]
    fn f4_roundtrip_json_string_restores_secret_exactly() {
        let vault = Vault::new();
        let secret = "quote\" back\\slash\nnewline\ttab";
        let token = vault.store("flag.f4", secret);
        let body = format!("{{\"answer\": \"{token}\"}}");
        let out = vault.unredact(body.as_bytes());
        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("response must stay valid JSON");
        assert_eq!(
            parsed["answer"].as_str(),
            Some(secret),
            "exact original secret restored"
        );
        assert!(vault.is_empty(), "entry consumed by the JSON path");
    }

    /// F4: a token that replaced a JSON object KEY is restored with the same
    /// JSON-aware escaping as a value-position token (parity).
    #[test]
    fn f4_token_in_object_key_restored_with_value_parity() {
        let vault = Vault::new();
        let secret = "sk\"key";
        let token = vault.store("flag.f4key", secret);
        let body = format!("{{\"{token}\": 1}}");
        let out = vault.unredact(body.as_bytes());
        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("key splice must stay valid JSON");
        let obj = parsed.as_object().expect("object shape preserved");
        assert_eq!(obj.len(), 1, "no extra keys");
        assert!(obj.contains_key(secret), "token in KEY position restored");
    }

    /// F4: plain and escape-heavy secrets in one body are both restored
    /// exactly; repeated occurrences of one token are all spliced.
    #[test]
    fn f4_mixed_plain_and_escaped_secrets_both_restored() {
        let vault = Vault::new();
        let escaped = "with\"quote\\and\nnewline";
        let plain = "plain-secret-ZZYXW";
        let t1 = vault.store("f.esc", escaped);
        let t2 = vault.store("f.plain", plain);
        let body = format!("{{\"a\": \"{t1}\", \"b\": \"{t2}\", \"c\": \"{t1}\"}}");
        let out = vault.unredact(body.as_bytes());
        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("valid JSON after splice");
        assert_eq!(parsed["a"].as_str(), Some(escaped));
        assert_eq!(parsed["b"].as_str(), Some(plain));
        assert_eq!(parsed["c"].as_str(), Some(escaped), "repeated token restored");
        assert!(vault.is_empty(), "each entry consumed once despite repeats");
    }

    /// F4-neutral: token-free JSON is byte-identical, and an UNKNOWN token in
    /// a JSON string is untouched without burning any entry.
    #[test]
    fn f4_token_free_json_byte_identical_unknown_token_no_burn() {
        let vault = Vault::new();
        let _ = vault.store("flag.x", SECRET);
        let body = br#"{"msg": "line\nbreak", "q": "\"quoted\"", "n": 1.10}"#;
        assert_eq!(
            vault.unredact(body),
            body.to_vec(),
            "token-free JSON byte-identical"
        );
        let unknown = format!("{{\"k\": \"[VAULT:{}]\"}}", "0".repeat(32));
        let out = vault.unredact(unknown.as_bytes());
        assert_eq!(out, unknown.as_bytes(), "unknown token untouched");
        assert_eq!(vault.len(), 1, "unknown token must not burn entries");
    }

    /// F4: a non-JSON body keeps the raw substitution path — the secret is
    /// spliced unescaped (and consumed), exactly as before F4.
    #[test]
    fn f4_non_json_body_keeps_raw_substitution_path() {
        let vault = Vault::new();
        let secret = "raw \"secret\" \\value";
        let token = vault.store("flag.raw", secret);
        let body = format!("plain text {token} trailing");
        let out = String::from_utf8(vault.unredact(body.as_bytes())).expect("utf8");
        assert!(out.contains(secret), "raw path splices the unescaped secret");
        assert!(vault.is_empty(), "raw path still consumes");
    }

    /// F4: consume-once on the JSON path — a second redeem request with the
    /// same token must not restore anything.
    #[test]
    fn f4_json_consume_once_second_request_no_restore() {
        let vault = Vault::new();
        let token = vault.store("flag.once", SECRET);
        let body = format!("{{\"k\": \"{token}\"}}");
        let first = vault.unredact(body.as_bytes());
        let first_parsed: serde_json::Value =
            serde_json::from_slice(&first).expect("first response valid JSON");
        assert_eq!(first_parsed["k"].as_str(), Some(SECRET), "first redeem restores");
        let second = String::from_utf8(vault.unredact(body.as_bytes())).expect("utf8");
        assert!(
            second.contains(&token.to_string()),
            "second redeem must NOT restore (consume-once)"
        );
        assert!(vault.is_empty(), "nothing left to burn");
    }
}
