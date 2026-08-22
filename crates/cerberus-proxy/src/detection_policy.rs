//! Política de detección **persistente** (F6, fix review v6.1).
//!
//! Cierra la deuda declarada por el builder de la unidad `config-api`: el
//! overlay de política (categorías, reglas propias, allowlist) vivía sólo en
//! la memoria del proceso, no se serializaba al YAML y no llegaba al motor de
//! detección. Aquí vive el modelo que:
//!
//! 1. **persiste** en [`crate::config::ProxyConfig`] → sobrevive al reinicio;
//! 2. **compone** el engine efectivo a partir de las reglas base (default +
//!    rule packs) y la política del operador, sin perder reglas de packs ni
//!    duplicar reglas custom;
//! 3. se **publica en caliente** ([`EngineControl`]) → el dataplane cambia de
//!    reglas sin reiniciar el proxy.
//!
//! ## Precedencia de acciones (una sola regla, sin asimetrías)
//!
//! ```text
//! rule_actions[flag]  >  categories[category]  >  action declarada en la regla
//! ```
//!
//! Es decir: la tabla de categorías es el mando grueso y aplica **también** a
//! las reglas custom del operador (si `secrets: redact` está activo, una regla
//! custom de categoría `secrets` redacta aunque declare `block`). Para
//! exceptuar una regla concreta existe el override por flag, que gana siempre.
//!
//! ## Reglas custom vs reglas de packs
//!
//! Una regla custom cuyo `flag` coincide con una regla base **la sustituye**
//! (no se duplica el flag en el engine). El resto de reglas base sobrevive
//! intacto: instalar un pack no borra las reglas custom y editar la política
//! no borra las reglas del pack ([`EngineControl::rebase`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use cerberus_engine::engine::{CompiledEngine, EngineBuilder};
use cerberus_engine::rule::{Action, Category, Rule};
use serde::{Deserialize, Serialize};

/// Acciones válidas para una categoría o una regla (§A.1 del build plan).
pub const POLICY_ACTIONS: [&str; 4] = ["allow", "warn", "redact", "block"];

/// Categorías válidas del MVP (§A.1): las del enum [`Category`], nada más.
pub const POLICY_CATEGORIES: [&str; 3] = ["secrets", "pii", "internal_code"];

/// Máximo de reglas custom persistidas. Cota defensiva: la política viaja por
/// el control plane (body ≤ 1 MiB) y se compila en el hot-path del engine.
pub const MAX_CUSTOM_RULES: usize = 256;

/// Máximo de entradas de allowlist persistidas (triage de falsos positivos).
pub const MAX_ALLOWLIST_ENTRIES: usize = 1024;

/// Longitud máxima de una entrada de allowlist.
pub const MAX_ALLOWLIST_ENTRY_LEN: usize = 512;

/// Parsear una acción del wire (`"block"`, …) al enum del motor.
///
/// # Errors
///
/// Mensaje accionable (con las acciones válidas) si `raw` no es una de ellas.
pub fn parse_action(raw: &str) -> Result<Action, String> {
    match raw {
        "allow" => Ok(Action::Allow),
        "warn" => Ok(Action::Warn),
        "redact" => Ok(Action::Redact),
        "block" => Ok(Action::Block),
        other => Err(format!(
            "invalid action {other:?} (expected one of {})",
            POLICY_ACTIONS.join("|")
        )),
    }
}

/// Parsear una categoría del wire (`"secrets"`, …) al enum del motor.
///
/// # Errors
///
/// Mensaje accionable (con las categorías válidas) si `raw` no es una de ellas.
pub fn parse_category(raw: &str) -> Result<Category, String> {
    match raw {
        "secrets" => Ok(Category::Secrets),
        "pii" => Ok(Category::Pii),
        "internal_code" => Ok(Category::InternalCode),
        other => Err(format!(
            "invalid category {other:?} (expected one of {})",
            POLICY_CATEGORIES.join("|")
        )),
    }
}

/// Política de detección del operador, **persistida en el YAML** de
/// [`crate::config::ProxyConfig`] bajo la clave `policy`.
///
/// Los nombres del wire se mantienen estables respecto a la API v6.1: la
/// tabla de overrides por regla se serializa como `rules` (lo que consume el
/// dashboard), y las reglas custom reales como `custom_rules`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionPolicy {
    /// Acción por categoría de alto nivel. Mando grueso.
    pub categories: BTreeMap<Category, Action>,
    /// Override de acción por `flag` concreto. Gana sobre la categoría.
    #[serde(rename = "rules")]
    pub rule_actions: BTreeMap<String, Action>,
    /// Reglas propias del operador, con la forma [`Rule`] del MVP (`flag`,
    /// `category`, `severity`, `action`, `patterns`, `validators` y las
    /// constraints `minLength`/`maxLength`/`contextKeywords`/
    /// `allowedExamples`).
    pub custom_rules: Vec<Rule>,
    /// Valores exactos que NO deben generar hallazgo (triage de FP).
    pub allowlist: Vec<String>,
}

impl Default for DetectionPolicy {
    fn default() -> Self {
        Self::seeded()
    }
}

impl DetectionPolicy {
    /// Política inicial sin overrides del operador.
    ///
    /// Las acciones por defecto viven en cada regla y se honran tal como exige
    /// el §4.3 del build plan. `categories` y `rule_actions` sólo contienen
    /// decisiones que el operador configuró explícitamente (API/YAML); esto
    /// evita que un preset implícito rebaje, por ejemplo, una regla `block` a
    /// `redact` durante el arranque cero-config.
    #[must_use]
    pub const fn seeded() -> Self {
        Self {
            categories: BTreeMap::new(),
            rule_actions: BTreeMap::new(),
            custom_rules: Vec::new(),
            allowlist: Vec::new(),
        }
    }

    /// Política vacía (ninguna categoría, ninguna regla): útil en tests y
    /// cuando el operador borra explícitamente el overlay.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            categories: BTreeMap::new(),
            rule_actions: BTreeMap::new(),
            custom_rules: Vec::new(),
            allowlist: Vec::new(),
        }
    }

    /// Validar la política ANTES de persistirla o publicarla.
    ///
    /// Comprueba lo que un YAML editado a mano o un patch del control plane
    /// pueden romper: flags vacíos o duplicados, reglas sin patrón, patrones
    /// que no compilan, constraints incoherentes y cotas de tamaño.
    ///
    /// # Errors
    ///
    /// Un mensaje accionable por el primer problema encontrado.
    pub fn validate(&self) -> Result<(), String> {
        if self.custom_rules.len() > MAX_CUSTOM_RULES {
            return Err(format!(
                "too many custom rules: {} (max {MAX_CUSTOM_RULES})",
                self.custom_rules.len()
            ));
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for rule in &self.custom_rules {
            let flag = rule.flag.trim();
            if flag.is_empty() {
                return Err("custom rule with an empty 'flag'".to_string());
            }
            if flag != rule.flag {
                return Err(format!("custom rule flag {:?} has leading/trailing spaces", rule.flag));
            }
            if !seen.insert(flag) {
                return Err(format!("duplicate custom rule flag {flag:?}"));
            }
            if rule.patterns.is_empty() {
                return Err(format!("custom rule {flag:?} has no 'patterns': it would never fire"));
            }
            if let (Some(min), Some(max)) = (rule.min_length, rule.max_length) {
                if min > max {
                    return Err(format!("custom rule {flag:?} has minLength {min} > maxLength {max}"));
                }
            }
        }
        for flag in self.rule_actions.keys() {
            if flag.trim().is_empty() {
                return Err("rule override with an empty flag".to_string());
            }
        }
        if self.allowlist.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(format!(
                "too many allowlist entries: {} (max {MAX_ALLOWLIST_ENTRIES})",
                self.allowlist.len()
            ));
        }
        for entry in &self.allowlist {
            if entry.is_empty() {
                return Err("empty allowlist entry".to_string());
            }
            if entry.len() > MAX_ALLOWLIST_ENTRY_LEN {
                return Err(format!(
                    "allowlist entry too long: {} bytes (max {MAX_ALLOWLIST_ENTRY_LEN})",
                    entry.len()
                ));
            }
        }
        // Los patrones se validan compilándolos: es el MISMO compilador que
        // usa el engine, así que un regex que aquí pasa no puede tumbar el
        // rebuild del dataplane después.
        EngineBuilder::new(&self.custom_rules)
            .build()
            .map(|_| ())
            .map_err(|e| format!("custom rules do not compile: {e}"))
    }

    /// ¿Está el valor exacto `value` en la allowlist?
    #[must_use]
    pub fn allows(&self, value: &str) -> bool {
        self.allowlist.iter().any(|a| a == value)
    }
}

/// Reglas efectivas del engine: reglas base (default + packs) fusionadas con
/// las reglas custom y con la precedencia de acciones aplicada.
///
/// - Una regla custom **sustituye** a la regla base con el mismo `flag`
///   (nunca se duplica un flag).
/// - El resto de reglas base sobrevive: instalar un pack no borra lo custom y
///   editar la política no borra el pack.
/// - Precedencia: `rule_actions[flag]` > `categories[category]` > la acción
///   declarada en la propia regla.
#[must_use]
pub fn effective_rules(base: &[Rule], policy: &DetectionPolicy) -> Vec<Rule> {
    let custom_flags: BTreeSet<&str> = policy.custom_rules.iter().map(|r| r.flag.as_str()).collect();
    let mut out: Vec<Rule> = base
        .iter()
        .filter(|r| !custom_flags.contains(r.flag.as_str()))
        .cloned()
        .collect();
    out.extend(policy.custom_rules.iter().cloned());
    for rule in &mut out {
        if let Some(action) = policy.rule_actions.get(&rule.flag) {
            rule.action = *action;
        } else if let Some(action) = policy.categories.get(&rule.category) {
            rule.action = *action;
        }
    }
    out
}

/// Compilar el engine efectivo (reglas base + política) sin publicarlo.
///
/// # Errors
///
/// El error del compilador de reglas (p.ej. un patrón que no compila).
pub fn build_engine(
    base: &[Rule],
    policy: &DetectionPolicy,
    payload_secret: Option<&[u8]>,
) -> Result<CompiledEngine, String> {
    let rules = effective_rules(base, policy);
    let mut builder = EngineBuilder::new(&rules);
    if let Some(secret) = payload_secret {
        builder = builder.with_payload_secret(secret.to_vec());
    }
    builder.build()
}

/// Mando del engine vivo del dataplane.
///
/// Guarda (a) el `Arc<RwLock<Arc<CompiledEngine>>>` que lee el hot-path, (b)
/// las reglas **base** del último snapshot de packs y (c) el secreto de
/// payload-hash. Con eso puede recomponer el engine efectivo desde dos
/// direcciones sin perder nada:
///
/// - el control plane cambia la política → [`EngineControl::compile`] +
///   [`EngineControl::publish`] (las reglas de packs siguen ahí);
/// - el worker de packs instala/revierte un pack → [`EngineControl::rebase`]
///   (las reglas custom y los overrides se re-aplican encima).
#[derive(Clone)]
pub struct EngineControl {
    live: Arc<RwLock<Arc<CompiledEngine>>>,
    base_rules: Arc<RwLock<Arc<Vec<Rule>>>>,
    payload_secret: Option<Vec<u8>>,
}

impl std::fmt::Debug for EngineControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // El secreto de payload-hash NUNCA se imprime.
        f.debug_struct("EngineControl")
            .field("live", &self.live_rules())
            .field("base_rules", &self.base_rules().len())
            .field("payload_secret", &self.payload_secret.is_some())
            .finish()
    }
}

impl EngineControl {
    /// Crear el mando sobre un engine vivo ya publicado.
    #[must_use]
    pub fn new(live: Arc<RwLock<Arc<CompiledEngine>>>, base_rules: Vec<Rule>, payload_secret: Option<Vec<u8>>) -> Self {
        Self {
            live,
            base_rules: Arc::new(RwLock::new(Arc::new(base_rules))),
            payload_secret,
        }
    }

    /// Snapshot de las reglas base vigentes (default + packs, sin custom).
    #[must_use]
    pub fn base_rules(&self) -> Arc<Vec<Rule>> {
        self.base_rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Número de reglas del engine vivo.
    #[must_use]
    pub fn live_rules(&self) -> usize {
        self.live
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .num_rules()
    }

    /// Compilar el engine efectivo para `policy` **sin publicarlo**: así el
    /// control plane puede rechazar (400) una política que no compila antes de
    /// tocar el YAML o la memoria viva.
    ///
    /// # Errors
    ///
    /// El error del compilador de reglas.
    pub fn compile(&self, policy: &DetectionPolicy) -> Result<CompiledEngine, String> {
        build_engine(&self.base_rules(), policy, self.payload_secret.as_deref())
    }

    /// Publicar un engine ya compilado en el dataplane (hot-swap). Devuelve el
    /// número de reglas activas.
    #[must_use]
    pub fn publish(&self, engine: CompiledEngine) -> usize {
        let arc = Arc::new(engine);
        let rules = arc.num_rules();
        *self.live.write().unwrap_or_else(std::sync::PoisonError::into_inner) = arc;
        rules
    }

    /// Sustituir las reglas base (nuevo snapshot de packs) y republicar
    /// aplicando `policy` encima. No pierde reglas de packs ni duplica reglas
    /// custom.
    ///
    /// # Errors
    ///
    /// El error del compilador de reglas; en ese caso NO se cambia ni la base
    /// ni el engine vivo.
    pub fn rebase(&self, base: Vec<Rule>, policy: &DetectionPolicy) -> Result<usize, String> {
        let engine = build_engine(&base, policy, self.payload_secret.as_deref())?;
        *self
            .base_rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(base);
        Ok(self.publish(engine))
    }
}

/// Helpers compartidos por los tests de otros módulos del crate (p.ej. los de
/// `api.rs`, que necesitan un engine base creíble para probar el hot-swap).
#[cfg(test)]
pub(crate) mod tests_support {
    use super::{Action, Category, Rule};
    use cerberus_engine::rule::Severity;

    /// Regla base ficticia (hace de "regla que trajo un pack").
    pub(crate) fn base_rule(flag: &str) -> Rule {
        Rule {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action: Action::Warn,
            hash_normalization: None,
            context_keywords: Vec::new(),
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec![r"PACKTOKEN-[0-9]{4}".to_string()],
            validators: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::rule::Severity;

    fn rule(flag: &str, category: Category, action: Action, pattern: &str) -> Rule {
        Rule {
            flag: flag.to_string(),
            category,
            severity: Severity::High,
            action,
            hash_normalization: None,
            context_keywords: Vec::new(),
            min_length: None,
            max_length: None,
            allowed_examples: Vec::new(),
            patterns: vec![pattern.to_string()],
            validators: Vec::new(),
        }
    }

    #[test]
    fn default_openai_rule_keeps_its_declared_block_action() {
        let p = DetectionPolicy::seeded();
        assert!(p.categories.is_empty(), "sin overrides implícitos por categoría");
        assert!(p.rule_actions.is_empty(), "sin overrides implícitos por flag");
        assert!(p.custom_rules.is_empty());
        assert!(p.allowlist.is_empty());

        let base = vec![rule(
            "secret.openai_api_key",
            Category::Secrets,
            Action::Block,
            r"sk-[A-Za-z0-9]{20,}",
        )];
        let effective = effective_rules(&base, &p);
        assert_eq!(
            effective[0].action,
            Action::Block,
            "cero-config debe honrar el block declarado por la regla OpenAI"
        );
    }

    #[test]
    fn explicit_category_override_replaces_the_declared_rule_action() {
        let base = vec![rule(
            "secret.openai_api_key",
            Category::Secrets,
            Action::Block,
            r"sk-[A-Za-z0-9]{20,}",
        )];
        let mut policy = DetectionPolicy::seeded();
        policy.categories.insert(Category::Secrets, Action::Redact);

        let effective = effective_rules(&base, &policy);
        assert_eq!(
            effective[0].action,
            Action::Redact,
            "una categoría configurada explícitamente sí manda sobre la regla"
        );
    }

    #[test]
    fn policy_round_trips_through_yaml_with_stable_wire_names() {
        let mut p = DetectionPolicy::seeded();
        p.rule_actions
            .insert("secret.openai_api_key".to_string(), Action::Block);
        p.custom_rules.push(rule(
            "custom.badge",
            Category::InternalCode,
            Action::Block,
            r"BADGE-\d{4}",
        ));
        p.allowlist.push("sk-EXAMPLE".to_string());

        let yaml = serde_yaml::to_string(&p).expect("serialize");
        // El wire del dashboard usa `rules` para los overrides por flag.
        assert!(yaml.contains("rules:"), "{yaml}");
        assert!(yaml.contains("custom_rules:"), "{yaml}");
        assert!(yaml.contains("internal_code"), "{yaml}");

        let back: DetectionPolicy = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(back, p);
    }

    #[test]
    fn missing_policy_keys_fall_back_to_the_seeded_defaults() {
        // `policy: {}` y `policy` ausente deben dar lo MISMO (struct-level default).
        let from_empty_map: DetectionPolicy = serde_yaml::from_str("{}").expect("parse");
        assert_eq!(from_empty_map, DetectionPolicy::seeded());

        // Backward compatibility: un YAML v6.1 que ya persistió categorías
        // mantiene esas decisiones como overrides explícitos.
        let legacy: DetectionPolicy =
            serde_yaml::from_str("categories:\n  secrets: redact\n  pii: warn\n").expect("parse");
        assert_eq!(legacy.categories.get(&Category::Secrets), Some(&Action::Redact));
        assert_eq!(legacy.categories.get(&Category::Pii), Some(&Action::Warn));
        let effective = effective_rules(
            &[rule(
                "secret.openai_api_key",
                Category::Secrets,
                Action::Block,
                "sk-LEGACY",
            )],
            &legacy,
        );
        assert_eq!(
            effective[0].action,
            Action::Redact,
            "las categorías de YAML v6.1 siguen siendo overrides explícitos"
        );
    }

    #[test]
    fn unknown_policy_key_is_loud() {
        let err = serde_yaml::from_str::<DetectionPolicy>("categorias: {}\n").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn custom_rule_replaces_the_base_rule_with_the_same_flag_without_duplicating() {
        let base = vec![
            rule("secret.a", Category::Secrets, Action::Warn, "AAA"),
            rule("secret.b", Category::Secrets, Action::Warn, "BBB"),
        ];
        let mut policy = DetectionPolicy::empty();
        policy
            .custom_rules
            .push(rule("secret.a", Category::Secrets, Action::Block, "AAA-v2"));

        let eff = effective_rules(&base, &policy);
        assert_eq!(eff.len(), 2, "no se duplica el flag: {eff:?}");
        let a = eff.iter().find(|r| r.flag == "secret.a").expect("custom gana");
        assert_eq!(a.patterns, vec!["AAA-v2".to_string()]);
        assert!(eff.iter().any(|r| r.flag == "secret.b"), "la regla base sobrevive");
    }

    #[test]
    fn action_precedence_is_flag_then_category_then_rule() {
        let base = vec![
            rule("secret.a", Category::Secrets, Action::Warn, "AAA"),
            rule("pii.b", Category::Pii, Action::Warn, "BBB"),
            rule("code.c", Category::InternalCode, Action::Block, "CCC"),
        ];
        let mut policy = DetectionPolicy::seeded();
        policy.categories.insert(Category::Secrets, Action::Redact);
        policy.rule_actions.insert("pii.b".to_string(), Action::Block);

        let eff = effective_rules(&base, &policy);
        let by = |flag: &str| eff.iter().find(|r| r.flag == flag).expect("regla").action;
        assert_eq!(by("secret.a"), Action::Redact, "gana la categoría");
        assert_eq!(by("pii.b"), Action::Block, "gana el override por flag");
        assert_eq!(
            by("code.c"),
            Action::Block,
            "sin categoría ni override: la acción declarada"
        );
    }

    #[test]
    fn category_overrides_a_custom_rule_action_too() {
        let mut policy = DetectionPolicy::seeded();
        policy.categories.insert(Category::Secrets, Action::Redact);
        policy
            .custom_rules
            .push(rule("custom.s", Category::Secrets, Action::Block, "SSS"));
        let eff = effective_rules(&[], &policy);
        assert_eq!(eff[0].action, Action::Redact, "el mando grueso aplica a lo custom");

        // …y el override por flag es la vía para exceptuarla.
        policy.rule_actions.insert("custom.s".to_string(), Action::Block);
        let eff = effective_rules(&[], &policy);
        assert_eq!(eff[0].action, Action::Block);
    }

    #[test]
    fn validate_rejects_broken_custom_rules() {
        let mut p = DetectionPolicy::empty();
        p.custom_rules.push(rule("", Category::Secrets, Action::Block, "X"));
        assert!(p.validate().unwrap_err().contains("empty 'flag'"));

        let mut p = DetectionPolicy::empty();
        p.custom_rules.push(rule("dup", Category::Secrets, Action::Block, "X"));
        p.custom_rules.push(rule("dup", Category::Secrets, Action::Block, "Y"));
        assert!(p.validate().unwrap_err().contains("duplicate"));

        let mut p = DetectionPolicy::empty();
        let mut no_pattern = rule("np", Category::Secrets, Action::Block, "X");
        no_pattern.patterns.clear();
        p.custom_rules.push(no_pattern);
        assert!(p.validate().unwrap_err().contains("no 'patterns'"));

        let mut p = DetectionPolicy::empty();
        p.custom_rules
            .push(rule("bad", Category::Secrets, Action::Block, "([unclosed"));
        assert!(p.validate().unwrap_err().contains("do not compile"));

        let mut p = DetectionPolicy::empty();
        let mut bad_len = rule("len", Category::Secrets, Action::Block, "X");
        bad_len.min_length = Some(50);
        bad_len.max_length = Some(10);
        p.custom_rules.push(bad_len);
        assert!(p.validate().unwrap_err().contains("minLength"));
    }

    #[test]
    fn validate_bounds_the_allowlist() {
        let mut p = DetectionPolicy::empty();
        p.allowlist.push(String::new());
        assert!(p.validate().unwrap_err().contains("empty allowlist"));

        let mut p = DetectionPolicy::empty();
        p.allowlist.push("x".repeat(MAX_ALLOWLIST_ENTRY_LEN + 1));
        assert!(p.validate().unwrap_err().contains("too long"));

        let mut p = DetectionPolicy::empty();
        p.allowlist = (0..=MAX_ALLOWLIST_ENTRIES).map(|i| format!("v{i}")).collect();
        assert!(p.validate().unwrap_err().contains("too many allowlist"));

        let mut p = DetectionPolicy::empty();
        p.custom_rules = (0..=MAX_CUSTOM_RULES)
            .map(|i| rule(&format!("r{i}"), Category::Secrets, Action::Warn, "X"))
            .collect();
        assert!(p.validate().unwrap_err().contains("too many custom rules"));
    }

    #[test]
    fn parse_helpers_are_strict_and_actionable() {
        assert_eq!(parse_action("block").expect("ok"), Action::Block);
        assert!(parse_action("nuke").unwrap_err().contains("allow|warn|redact|block"));
        assert_eq!(parse_category("internal_code").expect("ok"), Category::InternalCode);
        assert!(parse_category("Secrets").unwrap_err().contains("secrets|pii"));
    }

    #[test]
    fn engine_control_rebase_keeps_custom_rules_and_pack_rules() {
        let base_v1 = vec![rule("pack.a", Category::Secrets, Action::Warn, "AAA")];
        let mut policy = DetectionPolicy::empty();
        policy
            .custom_rules
            .push(rule("custom.x", Category::InternalCode, Action::Block, "XXX"));

        let boot = build_engine(&base_v1, &policy, None).expect("boot engine");
        let live = Arc::new(RwLock::new(Arc::new(boot)));
        let control = EngineControl::new(live.clone(), base_v1, None);
        assert_eq!(control.live_rules(), 2);

        // Un pack nuevo trae 2 reglas: las custom no se pierden ni se duplican.
        let base_v2 = vec![
            rule("pack.a", Category::Secrets, Action::Warn, "AAA"),
            rule("pack.b", Category::Pii, Action::Warn, "BBB"),
        ];
        let count = control.rebase(base_v2, &policy).expect("rebase");
        assert_eq!(count, 3);
        let flags: Vec<String> = live.read().unwrap().rules().iter().map(|r| r.flag.clone()).collect();
        assert!(flags.contains(&"pack.b".to_string()), "{flags:?}");
        assert_eq!(
            flags.iter().filter(|f| *f == "custom.x").count(),
            1,
            "la regla custom no se duplica: {flags:?}"
        );
    }

    #[test]
    fn engine_control_compile_does_not_publish() {
        let base = vec![rule("pack.a", Category::Secrets, Action::Warn, "AAA")];
        let boot = build_engine(&base, &DetectionPolicy::empty(), None).expect("boot");
        let live = Arc::new(RwLock::new(Arc::new(boot)));
        let control = EngineControl::new(live, base, None);

        let mut policy = DetectionPolicy::empty();
        policy
            .custom_rules
            .push(rule("custom.x", Category::Secrets, Action::Block, "XXX"));
        let compiled = control.compile(&policy).expect("compile");
        assert_eq!(compiled.num_rules(), 2);
        assert_eq!(control.live_rules(), 1, "compile no publica");
        assert_eq!(control.publish(compiled), 2);
        assert_eq!(control.live_rules(), 2);
    }

    #[test]
    fn engine_control_rebase_failure_leaves_the_live_engine_untouched() {
        let base = vec![rule("pack.a", Category::Secrets, Action::Warn, "AAA")];
        let boot = build_engine(&base, &DetectionPolicy::empty(), None).expect("boot");
        let live = Arc::new(RwLock::new(Arc::new(boot)));
        let control = EngineControl::new(live, base, None);

        let mut broken = DetectionPolicy::empty();
        broken
            .custom_rules
            .push(rule("custom.bad", Category::Secrets, Action::Block, "([unclosed"));
        assert!(control.rebase(vec![], &broken).is_err());
        assert_eq!(control.live_rules(), 1, "el engine vivo no cambió");
        assert_eq!(control.base_rules().len(), 1, "la base tampoco");
    }

    #[test]
    fn debug_never_prints_the_payload_secret() {
        let boot = build_engine(&[], &DetectionPolicy::empty(), None).expect("boot");
        let control = EngineControl::new(
            Arc::new(RwLock::new(Arc::new(boot))),
            Vec::new(),
            Some(b"super-secret-hmac-key".to_vec()),
        );
        let dbg = format!("{control:?}");
        assert!(!dbg.contains("super-secret"), "{dbg}");
        assert!(dbg.contains("payload_secret: true"), "{dbg}");
    }
}
