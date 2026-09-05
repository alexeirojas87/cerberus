//! **Persistent** detection policy (F6, fix review v6.1).
//!
//! Closes the debt declared by the `config-api` unit builder: the policy
//! overlay (categories, custom rules, allowlist) lived only in the
//! process memory, was not serialized to YAML and never reached the
//! detection engine. Here lives the model that:
//!
//! 1. **persists** in [`crate::config::ProxyConfig`] → survives restart;
//! 2. **composes** the effective engine from the base rules (default +
//!    rule packs) and the operator's policy, without losing pack rules or
//!    duplicating custom rules;
//! 3. is **published hot** ([`EngineControl`]) → the dataplane changes
//!    rules without restarting the proxy.
//!
//! ## Action precedence (a single rule, no asymmetries)
//!
//! ```text
//! rule_actions[flag]  >  categories[category]  >  action declared in the rule
//! ```
//!
//! That is: the category table is the coarse control and applies **also**
//! to the operator's custom rules (if `secrets: redact` is active, a custom
//! rule of category `secrets` redacts even if it declares `block`). To
//! except a specific rule there is the per-flag override, which always wins.
//!
//! ## Custom rules vs pack rules
//!
//! A custom rule whose `flag` matches a base rule **replaces it**
//! (the flag is not duplicated in the engine). The rest of the base rules
//! survive intact: installing a pack does not delete custom rules and
//! editing the policy does not delete pack rules
//! ([`EngineControl::rebase`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use cerberus_engine::engine::{CompiledEngine, EngineBuilder};
use cerberus_engine::rule::{Action, Category, Rule};
use serde::{Deserialize, Serialize};

/// Valid actions for a category or a rule (§A.1 of the build plan).
pub const POLICY_ACTIONS: [&str; 4] = ["allow", "warn", "redact", "block"];

/// Valid MVP categories (§A.1): those of the [`Category`] enum, nothing else.
pub const POLICY_CATEGORIES: [&str; 3] = ["secrets", "pii", "internal_code"];

/// Maximum number of persisted custom rules. Defensive bound: the policy
/// travels over the control plane (body ≤ 1 MiB) and is compiled in the
/// engine hot path.
pub const MAX_CUSTOM_RULES: usize = 256;

/// Maximum number of persisted allowlist entries (false-positive triage).
pub const MAX_ALLOWLIST_ENTRIES: usize = 1024;

/// Maximum length of an allowlist entry.
pub const MAX_ALLOWLIST_ENTRY_LEN: usize = 512;

/// Parse an action from the wire (`"block"`, …) into the engine enum.
///
/// # Errors
///
/// Actionable message (with the valid actions) if `raw` is not one of them.
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

/// Parse a category from the wire (`"secrets"`, …) into the engine enum.
///
/// # Errors
///
/// Actionable message (with the valid categories) if `raw` is not one of them.
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

/// Operator detection policy, **persisted in the YAML** of
/// [`crate::config::ProxyConfig`] under the `policy` key.
///
/// The wire names are kept stable with respect to API v6.1: the per-rule
/// override table is serialized as `rules` (what the dashboard consumes),
/// and the real custom rules as `custom_rules`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionPolicy {
    /// Action per high-level category. Coarse control.
    pub categories: BTreeMap<Category, Action>,
    /// Action override per specific `flag`. Wins over the category.
    #[serde(rename = "rules")]
    pub rule_actions: BTreeMap<String, Action>,
    /// Operator's own rules, with the MVP [`Rule`] shape (`flag`,
    /// `category`, `severity`, `action`, `patterns`, `validators` and the
    /// `minLength`/`maxLength`/`contextKeywords`/`allowedExamples`
    /// constraints).
    pub custom_rules: Vec<Rule>,
    /// Exact values that must NOT produce a finding (FP triage).
    pub allowlist: Vec<String>,
}

impl Default for DetectionPolicy {
    fn default() -> Self {
        Self::seeded()
    }
}

impl DetectionPolicy {
    /// Initial policy without operator overrides.
    ///
    /// The default actions live in each rule and are honored as the §4.3 of
    /// the build plan requires. `categories` and `rule_actions` only contain
    /// decisions the operator configured explicitly (API/YAML); this prevents
    /// an implicit preset from downgrading, for example, a `block` rule to
    /// `redact` during zero-config startup.
    #[must_use]
    pub const fn seeded() -> Self {
        Self {
            categories: BTreeMap::new(),
            rule_actions: BTreeMap::new(),
            custom_rules: Vec::new(),
            allowlist: Vec::new(),
        }
    }

    /// Empty policy (no category, no rules): useful in tests and when the
    /// operator explicitly clears the overlay.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            categories: BTreeMap::new(),
            rule_actions: BTreeMap::new(),
            custom_rules: Vec::new(),
            allowlist: Vec::new(),
        }
    }

    /// Validate the policy BEFORE persisting or publishing it.
    ///
    /// Checks what a hand-edited YAML or a control-plane patch can break:
    /// empty or duplicated flags, rules without a pattern, patterns that
    /// do not compile, incoherent constraints and size bounds.
    ///
    /// # Errors
    ///
    /// An actionable message for the first problem found.
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
            // R9-7/F6.3 STORE-LEVEL WRITE GATE: the config store only ever
            // persists allowlist FINGERPRINTS (`hmac:` + 64 hex, domain
            // `cerberus:allowlist:v1`). A raw value here is the R9-7
            // vulnerability (the secret lands in config.yaml and the API):
            // rejected — add it via `POST /api/allowlist` (converts raw →
            // fingerprint) or let the daemon migrate the legacy YAML at boot.
            if !crate::allowlist::is_fingerprint(entry) {
                return Err("allowlist entries must be HMAC fingerprints (hmac:<64 hex>, domain \
                     cerberus:allowlist:v1) — raw secret values are never persisted (R9-7); \
                     add the value via POST /api/allowlist, which converts it to a fingerprint"
                    .to_string());
            }
        }
        // Patterns are validated by compiling them: it is the SAME compiler
        // the engine uses, so a regex that passes here cannot break the
        // dataplane rebuild later.
        EngineBuilder::new(&self.custom_rules)
            .build()
            .map(|_| ())
            .map_err(|e| format!("custom rules do not compile: {e}"))
    }

    /// Is the exact `entry` present in the allowlist? (R9-7: entries are
    /// HMAC fingerprints; the HOT-PATH matcher computes the candidate's
    /// fingerprint in `proxy::filter_with_allowlist` — this exact-match
    /// helper is for fingerprint-shaped entries only.)
    #[must_use]
    pub fn allows(&self, entry: &str) -> bool {
        self.allowlist.iter().any(|a| a == entry)
    }
}

/// Effective engine rules: base rules (default + packs) merged with the
/// custom rules and with action precedence applied.
///
/// - A custom rule **replaces** the base rule with the same `flag`
///   (a flag is never duplicated).
/// - The rest of the base rules survive: installing a pack does not delete
///   custom rules and editing the policy does not delete the pack.
/// - Precedence: `rule_actions[flag]` > `categories[category]` > the action
///   declared in the rule itself.
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

/// Compile the effective engine (base rules + policy) without publishing it.
///
/// # Errors
///
/// The error from the rule compiler (e.g. a pattern that does not compile).
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

/// Control handle for the dataplane's live engine.
///
/// Holds (a) the `Arc<RwLock<Arc<CompiledEngine>>>` the hot path reads, (b)
/// the **base** rules of the last pack snapshot and (c) the payload-hash
/// secret. With that it can rebuild the effective engine from two
/// directions without losing anything:
///
/// - the control plane changes the policy → [`EngineControl::compile`] +
///   [`EngineControl::publish`] (the pack rules stay there);
/// - the pack worker installs/reverts a pack → [`EngineControl::rebase`]
///   (custom rules and overrides are re-applied on top).
#[derive(Clone)]
pub struct EngineControl {
    live: Arc<RwLock<Arc<CompiledEngine>>>,
    base_rules: Arc<RwLock<Arc<Vec<Rule>>>>,
    payload_secret: Option<Vec<u8>>,
}

impl std::fmt::Debug for EngineControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The payload-hash secret is NEVER printed.
        f.debug_struct("EngineControl")
            .field("live", &self.live_rules())
            .field("base_rules", &self.base_rules().len())
            .field("payload_secret", &self.payload_secret.is_some())
            .finish()
    }
}

impl EngineControl {
    /// Create the control handle over an already-published live engine.
    #[must_use]
    pub fn new(live: Arc<RwLock<Arc<CompiledEngine>>>, base_rules: Vec<Rule>, payload_secret: Option<Vec<u8>>) -> Self {
        Self {
            live,
            base_rules: Arc::new(RwLock::new(Arc::new(base_rules))),
            payload_secret,
        }
    }

    /// Snapshot of the current base rules (default + packs, without custom).
    #[must_use]
    pub fn base_rules(&self) -> Arc<Vec<Rule>> {
        self.base_rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Number of rules in the live engine.
    #[must_use]
    pub fn live_rules(&self) -> usize {
        self.live
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .num_rules()
    }

    /// Snapshot of the live engine as a shared handle (F6.B: `/api/scan`
    /// dry-runs exactly the engine the dataplane is using right now).
    #[must_use]
    pub fn live_snapshot(&self) -> Arc<CompiledEngine> {
        Arc::clone(&self.live.read().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// Compile the effective engine for `policy` **without publishing it**: so
    /// the control plane can reject (400) a policy that does not compile
    /// before touching the YAML or the live memory.
    ///
    /// # Errors
    ///
    /// The error from the rule compiler.
    pub fn compile(&self, policy: &DetectionPolicy) -> Result<CompiledEngine, String> {
        build_engine(&self.base_rules(), policy, self.payload_secret.as_deref())
    }

    /// Publish an already-compiled engine into the dataplane (hot-swap).
    /// Returns the number of active rules.
    #[must_use]
    pub fn publish(&self, engine: CompiledEngine) -> usize {
        let arc = Arc::new(engine);
        let rules = arc.num_rules();
        *self.live.write().unwrap_or_else(std::sync::PoisonError::into_inner) = arc;
        rules
    }

    /// Replace the base rules (new pack snapshot) and re-publish applying
    /// `policy` on top. Does not lose pack rules or duplicate custom rules.
    ///
    /// # Errors
    ///
    /// The error from the rule compiler; in that case NEITHER the base nor
    /// the live engine is changed.
    pub fn rebase(&self, base: Vec<Rule>, policy: &DetectionPolicy) -> Result<usize, String> {
        let engine = build_engine(&base, policy, self.payload_secret.as_deref())?;
        *self
            .base_rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(base);
        Ok(self.publish(engine))
    }
}

/// Helpers shared by the tests of other modules in the crate (e.g. those of
/// `api.rs`, which need a credible base engine to test the hot-swap).
#[cfg(test)]
pub(crate) mod tests_support {
    use super::{Action, Category, Rule};
    use cerberus_engine::rule::Severity;

    /// Fictional base rule (acts as the "rule a pack brought").
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
        assert!(p.categories.is_empty(), "no implicit category overrides");
        assert!(p.rule_actions.is_empty(), "no implicit flag overrides");
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
            "zero-config must honor the block declared by the OpenAI rule"
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
            "an explicitly configured category does win over the rule"
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
        // The dashboard wire uses `rules` for per-flag overrides.
        assert!(yaml.contains("rules:"), "{yaml}");
        assert!(yaml.contains("custom_rules:"), "{yaml}");
        assert!(yaml.contains("internal_code"), "{yaml}");

        let back: DetectionPolicy = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(back, p);
    }

    #[test]
    fn missing_policy_keys_fall_back_to_the_seeded_defaults() {
        // `policy: {}` and an absent `policy` must give the SAME result (struct-level default).
        let from_empty_map: DetectionPolicy = serde_yaml::from_str("{}").expect("parse");
        assert_eq!(from_empty_map, DetectionPolicy::seeded());

        // Backward compatibility: a v6.1 YAML that already persisted
        // categories keeps those decisions as explicit overrides.
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
            "v6.1 YAML categories are still explicit overrides"
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
        assert_eq!(eff.len(), 2, "the flag is not duplicated: {eff:?}");
        let a = eff.iter().find(|r| r.flag == "secret.a").expect("custom wins");
        assert_eq!(a.patterns, vec!["AAA-v2".to_string()]);
        assert!(eff.iter().any(|r| r.flag == "secret.b"), "the base rule survives");
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
        let by = |flag: &str| eff.iter().find(|r| r.flag == flag).expect("rule").action;
        assert_eq!(by("secret.a"), Action::Redact, "the category wins");
        assert_eq!(by("pii.b"), Action::Block, "the per-flag override wins");
        assert_eq!(
            by("code.c"),
            Action::Block,
            "no category or override: the declared action"
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
        assert_eq!(
            eff[0].action,
            Action::Redact,
            "the coarse control applies to custom rules too"
        );

        // …and the per-flag override is the way to except it.
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

        // A new pack brings 2 rules: the custom ones are not lost or duplicated.
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
            "the custom rule is not duplicated: {flags:?}"
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
        assert_eq!(control.live_rules(), 1, "compile does not publish");
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
        assert_eq!(control.live_rules(), 1, "the live engine did not change");
        assert_eq!(control.base_rules().len(), 1, "the base did not either");
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
