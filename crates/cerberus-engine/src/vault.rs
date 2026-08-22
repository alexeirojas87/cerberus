//! Bóveda local reversible (§4.4 del build plan).
//!
//! Mapea tokens de redacción → valores originales para "des-redactar"
//! respuestas. Es **opt-in** y **solo local** — por defecto la redacción
//! es irreversible (más seguro).
//!
//! Cuando la redacción reversible está activa, el token de reemplazo
//! es un identificador único (ej. `[VAULT:a1b2c3d4]`) en lugar del
//! `[REDACTED:flag]` estándar. La bóveda almacena el mapeo para que
//! la capa de red pueda restaurar el valor original en la respuesta.

use std::collections::HashMap;
use std::sync::Mutex;

/// Token con el que se reemplazó un valor sensible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultToken {
    /// Identificador único del token.
    pub id: String,
}

impl std::fmt::Display for VaultToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[VAULT:{}]", self.id)
    }
}

/// Entrada de la bóveda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    /// Flag de la regla que disparó.
    pub flag: String,
    /// Valor original (el secreto).
    pub original_value: String,
    /// Token de reemplazo.
    pub token: VaultToken,
}

/// Bóveda local para redacción reversible.
///
/// Thread-safe via `Mutex` interno. En un solo hilo (caso típico del
/// proxy) el overhead del mutex es despreciable.
#[derive(Debug)]
pub struct Vault {
    inner: Mutex<VaultInner>,
}

#[derive(Debug, Default)]
struct VaultInner {
    entries: HashMap<String, VaultEntry>,
    next_id: u64,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    /// Crear una bóveda vacía.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VaultInner {
                entries: HashMap::new(),
                next_id: 1,
            }),
        }
    }

    /// Almacenar un valor y devolver su token.
    ///
    /// El token generado tiene el formato `v<N>` donde `N` es un
    /// contador monótono.
    #[must_use]
    pub fn store(&self, flag: &str, original_value: &str) -> VaultToken {
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        let id = format!("v{}", inner.next_id);
        inner.next_id += 1;
        let token = VaultToken { id };
        inner.entries.insert(
            token.id.clone(),
            VaultEntry {
                flag: flag.to_string(),
                original_value: original_value.to_string(),
                token: token.clone(),
            },
        );
        token
    }

    /// Recuperar el valor original a partir de un token.
    #[must_use]
    pub fn resolve(&self, token: &VaultToken) -> Option<VaultEntry> {
        let inner = self.inner.lock().expect("vault lock poisoned");
        inner.entries.get(&token.id).cloned()
    }

    /// Recuperar el valor original a partir de una string de token
    /// (ej. extraída del texto redactado).
    #[must_use]
    pub fn resolve_str(&self, token_str: &str) -> Option<VaultEntry> {
        let stripped = token_str
            .strip_prefix("[VAULT:")
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(token_str);
        // También soporta el id directo (sin wrapper)
        let inner = self.inner.lock().expect("vault lock poisoned");
        inner.entries.get(stripped).cloned()
    }

    /// Cantidad de entradas en la bóveda.
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().expect("vault lock poisoned");
        inner.entries.len()
    }

    /// ¿Está vacía?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Limpiar todas las entradas.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("vault lock poisoned");
        inner.entries.clear();
    }
}

/// Opciones para habilitar redacción reversible.
#[derive(Debug, Clone, Default)]
pub struct ReversibleOptions {
    /// Si es `true`, se usa la bóveda en lugar de la redacción estándar.
    pub enabled: bool,
}

impl ReversibleOptions {
    /// Create options with reversible vault enabled.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_resolve() {
        let vault = Vault::new();
        let token = vault.store("secret.openai_key", "sk-abc123");
        assert_eq!(token.to_string(), "[VAULT:v1]");
        let entry = vault.resolve(&token).unwrap();
        assert_eq!(entry.flag, "secret.openai_key");
        assert_eq!(entry.original_value, "sk-abc123");
    }

    #[test]
    fn resolve_str_with_wrapper() {
        let vault = Vault::new();
        let token = vault.store("test.flag", "original-value");
        let entry = vault.resolve_str(&token.to_string()).unwrap();
        assert_eq!(entry.original_value, "original-value");
    }

    #[test]
    fn resolve_str_direct_id() {
        let vault = Vault::new();
        let _token = vault.store("t", "val");
        let entry = vault.resolve_str("v1").unwrap();
        assert_eq!(entry.original_value, "val");
    }

    #[test]
    fn resolve_nonexistent_token() {
        let vault = Vault::new();
        let token = VaultToken {
            id: "nonexistent".to_string(),
        };
        assert!(vault.resolve(&token).is_none());
        assert!(vault.resolve_str("[VAULT:nonexistent]").is_none());
    }

    #[test]
    fn vault_is_empty_initially() {
        let vault = Vault::new();
        assert!(vault.is_empty());
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn vault_len_increases() {
        let vault = Vault::new();
        let _ = vault.store("a", "val1");
        assert_eq!(vault.len(), 1);
        let _ = vault.store("b", "val2");
        assert_eq!(vault.len(), 2);
    }

    #[test]
    fn clear_removes_all() {
        let vault = Vault::new();
        let _ = vault.store("a", "val");
        vault.clear();
        assert!(vault.is_empty());
    }

    #[test]
    fn tokens_are_monotonic() {
        let vault = Vault::new();
        let t1 = vault.store("a", "v1");
        let t2 = vault.store("b", "v2");
        assert_eq!(t1.id, "v1");
        assert_eq!(t2.id, "v2");
    }

    #[test]
    fn reversible_options_default_disabled() {
        let opts = ReversibleOptions::default();
        assert!(!opts.enabled);
    }

    #[test]
    fn reversible_options_enabled() {
        let opts = ReversibleOptions::enabled();
        assert!(opts.enabled);
    }

    #[test]
    fn entry_round_trip() {
        let vault = Vault::new();
        let token = vault.store("flag.x", "super-secret-value");
        let entry = vault.resolve(&token).unwrap();
        assert_eq!(entry.token.id, token.id);
        assert_eq!(entry.original_value, "super-secret-value");
        assert_eq!(entry.flag, "flag.x");
    }
}
