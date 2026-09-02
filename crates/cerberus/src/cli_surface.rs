//! F6.B — Appendix B CLI surface implementations.
//!
//! Every function here backs one Appendix B command group:
//!
//! - **B.1** lifecycle: `version`, `upgrade` (check + guidance; F8 re-verifies
//!   against real release artifacts), `restart`, `mode`, `allow-once`;
//! - **B.2** agents/providers: `agents list|wire|unwire`, `providers`,
//!   `add-provider`, `remove-provider` (control-plane upstream CRUD);
//! - **B.3** packs/policy: `packs enable|disable|update`, `category set`,
//!   `rules list|add|set`, `allowlist add|list|remove`;
//! - **B.5** observability: `events` (provider/tool/since), `stats --by`,
//!   `logs [-f]` (daemon log file written by `cerberus start`);
//! - **B.6** config/license: `config show|edit|path`, `login`, `dashboard`;
//! - **B.7** Mode A: `validate -f`, `reload` (hot-reload via the daemon).
//!
//! Contract (hard rules): daemon-backed commands are HTTP clients of the
//! control plane with the admin token from config/env (never hardcoded),
//! with a clear error when the daemon is unreachable. Local fallbacks only
//! where Appendix B says so (scan/test/doctor/init/agents/config/validate).
//! No raw allowlist values are ever echoed back — fingerprints only (R9-7).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read as _;

use cerberus_engine::engine::EngineBuilder;
use cerberus_proxy::config::ProxyConfig;

use crate::cli_api::ApiClient;
use crate::daemon;

/// Default releases manifest consulted by `cerberus upgrade` (F6 contract:
/// check + guidance; downloading/replacing the binary is Phase 8). The URL
/// is overridable with `--manifest-url` / `CERBERUS_RELEASES_URL` for local
/// testing against a staging repository.
pub(crate) const DEFAULT_RELEASES_URL: &str = "https://api.github.com/repos/alexeirojas87/cerberus/releases/latest";

// ────────────────────────────── B.1 lifecycle ──────────────────────────────

/// `cerberus version` — same string as `--version` (fix-plan F6.4).
#[must_use]
pub(crate) fn version() -> String {
    format!("cerberus {}", env!("CARGO_PKG_VERSION"))
}

/// `cerberus upgrade` — checks the configured releases manifest, compares
/// with the running version, and prints the upgrade command when outdated.
/// Never downloads or replaces the binary (Phase 8: installers/signed
/// binaries re-verify this contract against real artifacts).
pub(crate) async fn upgrade_check(explicit_url: Option<String>) -> Result<String, String> {
    let url = explicit_url
        .or_else(|| std::env::var("CERBERUS_RELEASES_URL").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| DEFAULT_RELEASES_URL.to_string());
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("user-agent", concat!("cerberus-cli/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("upgrade check failed (offline?): {e} — install manually with `brew upgrade cerberus` or `curl -fsSL https://get.cerberus.dev | sh`"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "upgrade check failed: releases manifest at {url} answered HTTP {}",
            resp.status()
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("releases manifest at {url} is not JSON: {e}"))?;
    let tag = body
        .get("tag_name")
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("releases manifest at {url} has no tag_name"))?;
    let latest = tag.trim_start_matches(['v', 'V']);
    let current = env!("CARGO_PKG_VERSION");
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) if l > c => Ok(format!(
            "upgrade available: {latest} (current {current})\nRun: brew upgrade cerberus\n     or: curl -fsSL https://get.cerberus.dev | sh"
        )),
        (Some(_), Some(_)) => Ok(format!("cerberus {current} is up to date (latest: {latest})")),
        _ => Err(format!(
            "releases manifest at {url} has no recognizable version (tag_name={tag:?}); expected x.y.z"
        )),
    }
}

/// Parse an `x.y.z` semver-ish string into comparable numbers.
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// `cerberus restart` — stop (if running) and start again on the SAME
/// effective port (explicit `--port` wins; otherwise the endpoint the
/// running daemon published, before `stop` removes the runtime files).
pub(crate) async fn restart(port: Option<u16>) -> Result<String, String> {
    let effective = port.unwrap_or_else(|| crate::cli_api::resolve_endpoint().port);
    let mut report = String::new();
    if daemon::is_running() {
        match daemon::stop() {
            Ok(msg) => writeln!(report, "{msg}").ok(),
            Err(e) => return Err(format!("restart: stop failed: {e}")),
        };
    } else {
        writeln!(report, "not running — starting fresh").ok();
    }
    match daemon::start(effective, None).await {
        Ok(msg) => {
            writeln!(report, "{msg}").ok();
        }
        Err(e) => return Err(format!("restart: start failed: {e}")),
    }
    Ok(report)
}

/// `cerberus mode <shadow|enforce>` argument validation (shared by the
/// setter and its unit test).
pub(crate) fn validate_mode_arg(m: &str) -> Result<String, String> {
    let normalized = m.trim().to_lowercase();
    if normalized != "shadow" && normalized != "enforce" {
        return Err(format!("invalid mode {m:?}: expected 'shadow' or 'enforce'"));
    }
    Ok(normalized)
}

/// `cerberus mode` (no arg): show the live global mode.
/// `cerberus mode <shadow|enforce>`: hot-swap via `PUT /api/config`.
pub(crate) async fn set_mode(new_mode: Option<String>) -> Result<String, String> {
    let client = ApiClient::resolve();
    match new_mode {
        None => {
            let cfg = client.get_json("/api/config").await?;
            let mode = cfg.get("mode").and_then(|m| m.as_str()).unwrap_or("unknown");
            Ok(format!(
                "mode: {mode} (live; `cerberus mode <shadow|enforce>` changes it without restarting)"
            ))
        }
        Some(m) => {
            let normalized = validate_mode_arg(&m)?;
            let resp = client
                .send_json("PUT", "/api/config", format!(r#"{{"mode":"{normalized}"}}"#))
                .await?;
            let mode = resp.get("mode").and_then(|m| m.as_str()).unwrap_or(&normalized);
            Ok(format!("mode: {mode} (hot-reload applied — no restart needed)"))
        }
    }
}

/// `cerberus allow-once [--reason <m>]` — break-glass (B.1): issues an
/// audited one-shot bypass via `POST /api/break-glass`. The nonce is the
/// only bearer credential returned; the reason is stored HASHED only.
pub(crate) async fn allow_once(reason: Option<String>) -> Result<String, String> {
    let reason = reason.unwrap_or_else(|| "allow-once via CLI".to_string());
    if reason.trim().is_empty() {
        return Err("reason must be non-empty (it is audited, hashed only)".to_string());
    }
    let client = ApiClient::resolve();
    let resp = client
        .send_json(
            "POST",
            "/api/break-glass",
            serde_json::json!({ "reason": reason }).to_string(),
        )
        .await?;
    let nonce = resp.get("nonce").and_then(|n| n.as_str()).unwrap_or_default();
    let ttl = resp
        .get("ttl_secs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let scope = resp.get("scope").and_then(|s| s.as_str()).unwrap_or("global");
    Ok(format!(
        "break-glass issued: the NEXT matching send within {ttl}s is allowed (scope: {scope}).\nSend it with the header `X-Cerberus-Bypass: {nonce}`.\nThe reason is audited (hash only, never stored raw)."
    ))
}

// ────────────────────── B.2 agents and providers ──────────────────────────

/// Where the agents wire-state lives (`cerberus agents wire/unwire`). Plain
/// JSON, no secrets: `{ "Claude Code": true }`. Wiring an agent means
/// pointing its `*_BASE_URL` at the local daemon — the CLI records the
/// intent and prints the exact line to export (a CLI cannot mutate its
/// parent shell's environment, so the export line IS the wiring action).
fn agents_state_path() -> std::path::PathBuf {
    daemon::config_dir().join("agents.json")
}

fn read_agents_state() -> BTreeMap<String, bool> {
    std::fs::read_to_string(agents_state_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_agents_state(state: &BTreeMap<String, bool>) -> Result<(), String> {
    let dir = daemon::config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let json = serde_json::to_string_pretty(state).map_err(|e| format!("agents state serialize: {e}"))?;
    std::fs::write(agents_state_path(), json).map_err(|e| format!("cannot write agents state: {e}"))
}

/// `cerberus agents` — detected agents + wiring status (B.2).
#[must_use]
pub(crate) fn agents_list() -> String {
    let detected = crate::init::detect_agents();
    let state = read_agents_state();
    let mut out = String::from("Agents (detected on this machine):\n");
    for agent in &detected {
        let presence = agent
            .binary_path
            .as_ref()
            .map_or_else(|| "not found".to_string(), |p| format!("found: {p}"));
        let wired = if state.get(&agent.name).copied().unwrap_or(false) {
            "wired → cerberus"
        } else {
            "not wired"
        };
        writeln!(
            out,
            "  {:<22} {:<28} env:{} [{wired}]",
            agent.name, presence, agent.env_var
        )
        .ok();
    }
    out.push_str("\nWire an agent: cerberus agents wire <name>   (then restart the agent)");
    out
}

/// `cerberus agents wire <agent>` — records the routing and prints the
/// exact export line. Errors with the list of known agents on a bad name.
pub(crate) fn agent_wire(agent: &str) -> Result<String, String> {
    let (name, env_var) = known_agent(agent)?;
    let mut state = read_agents_state();
    state.insert(name.to_string(), true);
    write_agents_state(&state)?;
    Ok(format!(
        "'{name}' wired → Cerberus.\nSet its base URL (one-time, in the shell that launches the agent):\n  export {env_var}=http://127.0.0.1:8787\nUndo with: cerberus agents unwire {agent}"
    ))
}

/// `cerberus agents unwire <agent>` — clears the routing record.
pub(crate) fn agent_unwire(agent: &str) -> Result<String, String> {
    let (name, env_var) = known_agent(agent)?;
    let mut state = read_agents_state();
    state.remove(name);
    write_agents_state(&state)?;
    Ok(format!(
        "'{name}' unwired.\nPoint the agent back at the provider directly:\n  unset {env_var}   (or restore the provider's base URL in the agent config)"
    ))
}

/// Resolve an agent query (display name, first word, or env var) against
/// the known-agents table.
fn known_agent(query: &str) -> Result<(&'static str, &'static str), String> {
    let q = query.trim();
    crate::init::agent_by_name(q).ok_or_else(|| {
        format!("unknown agent {q:?}; known agents: Claude Code, Codex, opencode, pi, Continue (Cursor)")
    })
}

/// `cerberus providers` — configured upstreams (B.2).
pub(crate) async fn providers_list() -> Result<String, String> {
    let client = ApiClient::resolve();
    let resp = client.get_json("/api/upstreams").await?;
    let mut out = String::from("Providers (upstreams):\n");
    let empty = Vec::new();
    let items = resp.as_array().unwrap_or(&empty);
    for item in items {
        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let url = item.get("url").and_then(|u| u.as_str()).unwrap_or("?");
        let mode = item.get("mode").and_then(|m| m.as_str()).unwrap_or("global");
        writeln!(out, "  {name:<16} {url:<45} mode:{mode}").ok();
    }
    if items.is_empty() {
        out.push_str("  (none)\n");
    }
    Ok(out)
}

/// `cerberus add-provider <name> --url <url> [--auth-header <h>]` —
/// registers a custom upstream and prints the local base URL to paste
/// (Appendix C).
pub(crate) async fn add_provider(name: &str, url: &str, auth_header: Option<String>) -> Result<String, String> {
    if name.is_empty() || url.is_empty() {
        return Err("provider name and --url are required".to_string());
    }
    let client = ApiClient::resolve();
    let mut body = serde_json::json!({ "name": name, "url": url });
    if let Some(h) = auth_header {
        body["auth_header"] = serde_json::Value::String(h);
    }
    client.send_json("POST", "/api/upstreams", body.to_string()).await?;
    Ok(format!(
        "provider '{name}' registered → local base URL: {}\nPoint your agent's baseURL there (Appendix C).",
        client.provider_url(name)
    ))
}

/// `cerberus remove-provider <name>` — removes an upstream.
pub(crate) async fn remove_provider(name: &str) -> Result<String, String> {
    let client = ApiClient::resolve();
    client
        .send_json(
            "DELETE",
            &format!("/api/upstreams/{}", crate::cli_api::encode_path_segment(name)),
            "{}".to_string(),
        )
        .await?;
    Ok(format!("provider '{name}' removed"))
}

// ─────────────────── B.3 packs, categories, rules, allowlist ──────────────

/// `cerberus packs enable <pack>` — via `POST /api/packs/enable`.
pub(crate) async fn packs_enable(name: &str) -> Result<String, String> {
    let client = ApiClient::resolve();
    let resp = client
        .send_json(
            "POST",
            "/api/packs/enable",
            serde_json::json!({ "name": name }).to_string(),
        )
        .await?;
    Ok(resp
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("pack enabled")
        .to_string())
}

/// `cerberus packs disable <pack>` — via `POST /api/packs/disable`.
pub(crate) async fn packs_disable(name: &str) -> Result<String, String> {
    let client = ApiClient::resolve();
    let resp = client
        .send_json(
            "POST",
            "/api/packs/disable",
            serde_json::json!({ "name": name }).to_string(),
        )
        .await?;
    Ok(resp
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("pack disabled")
        .to_string())
}

/// `cerberus packs update` — F6 contract: re-verify installed signatures +
/// hot-reload via `POST /api/packs/update`. Fetching NEW versions from a
/// registry is the F7 auto-update unit (DAG: F6 does not open F7 work).
pub(crate) async fn packs_update() -> Result<String, String> {
    let client = ApiClient::resolve();
    let resp = client.send_json("POST", "/api/packs/update", "{}".to_string()).await?;
    Ok(resp
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("packs updated")
        .to_string())
}

/// `cerberus category set <secrets|pii> --action <block|redact|warn|allow>`
pub(crate) async fn category_set(category: &str, action: &str) -> Result<String, String> {
    // Client-side validation for a fast, clear error (the API validates
    // again authoritatively).
    cerberus_proxy::detection_policy::parse_category(category).map_err(|e| format!("invalid category: {e}"))?;
    cerberus_proxy::detection_policy::parse_action(action).map_err(|e| format!("invalid action: {e}"))?;
    let client = ApiClient::resolve();
    let body = serde_json::json!({ "categories": { category: action } });
    client.send_json("PUT", "/api/policy", body.to_string()).await?;
    Ok(format!("category '{category}' action → {action} (hot-reload applied)"))
}

/// `cerberus rules list` — effective rules (base + overrides + custom).
pub(crate) async fn rules_list() -> Result<String, String> {
    let client = ApiClient::resolve();
    let policy = client.get_json("/api/policy").await?;
    let mut out = String::new();
    if let Some(rules) = policy.get("effective_rules").and_then(|r| r.as_array()) {
        writeln!(out, "Effective rules ({} live):", rules.len()).ok();
        for r in rules {
            let flag = r.get("flag").and_then(|f| f.as_str()).unwrap_or("?");
            let category = r.get("category").and_then(|c| c.as_str()).unwrap_or("?");
            let action = r.get("action").and_then(|a| a.as_str()).unwrap_or("?");
            writeln!(out, "  {flag:<40} {category:<14} action:{action}").ok();
        }
    } else {
        out.push_str("Effective rules: (engine not connected — only overrides visible)\n");
    }
    if let Some(overrides) = policy.get("rules").and_then(|r| r.as_object()) {
        if !overrides.is_empty() {
            out.push_str("\nOperator overrides (action per rule):\n");
            for (flag, action) in overrides {
                writeln!(out, "  {flag:<40} action:{action}").ok();
            }
        }
    }
    if let Some(custom) = policy.get("custom_rules").and_then(|r| r.as_array()) {
        writeln!(out, "\nCustom rules: {}", custom.len()).ok();
    }
    Ok(out)
}

/// `cerberus rules add --file <rule.yaml>` — validates the rule locally
/// (parse + compile: bad regexes fail fast with the engine's hard error),
/// then appends it to the live policy (`PUT /api/policy` full-replacement
/// of `custom_rules`) and hot-reloads.
pub(crate) async fn rules_add(file: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(file).map_err(|e| format!("cannot read rule file {file:?}: {e}"))?;
    let rules = parse_rule_file(&raw)?;
    if rules.is_empty() {
        return Err(format!("{file} contains no rules"));
    }
    // Local compile check BEFORE touching the daemon (fail fast, clear
    // error; the daemon re-validates authoritatively).
    EngineBuilder::new(&rules)
        .build()
        .map_err(|e| format!("rule does not compile: {e}"))?;

    let client = ApiClient::resolve();
    let policy = client.get_json("/api/policy").await?;
    let mut custom: Vec<cerberus_engine::rule::Rule> = policy
        .get("custom_rules")
        .and_then(|c| serde_json::from_value(c.clone()).ok())
        .unwrap_or_default();
    let mut added = 0usize;
    for rule in &rules {
        custom.retain(|existing| existing.flag != rule.flag);
        custom.push(rule.clone());
        added += 1;
    }
    let body = serde_json::json!({ "custom_rules": custom });
    client.send_json("PUT", "/api/policy", body.to_string()).await?;
    let flags: Vec<String> = rules.iter().map(|r| r.flag.clone()).collect();
    Ok(format!(
        "{added} custom rule(s) added ({}) — hot-reload applied",
        flags.join(", ")
    ))
}

/// Parse a rule file: a single YAML/JSON rule document, a list, or a
/// multi-document stream.
fn parse_rule_file(raw: &str) -> Result<Vec<cerberus_engine::rule::Rule>, String> {
    match serde_yaml::from_str::<Vec<cerberus_engine::rule::Rule>>(raw) {
        Ok(list) => Ok(list),
        Err(list_err) => match serde_yaml::from_str::<cerberus_engine::rule::Rule>(raw) {
            Ok(rule) => Ok(vec![rule]),
            Err(e) => Err(format!(
                "rule file is neither a rule nor a list of rules: {e} (list error: {list_err})"
            )),
        },
    }
}

/// `cerberus rules set <flag> --action <...>` — per-rule action override.
pub(crate) async fn rules_set(flag: &str, action: &str) -> Result<String, String> {
    cerberus_proxy::detection_policy::parse_action(action).map_err(|e| format!("invalid action: {e}"))?;
    let client = ApiClient::resolve();
    let body = serde_json::json!({ "rules": { flag: action } });
    client.send_json("PUT", "/api/policy", body.to_string()).await?;
    Ok(format!("rule '{flag}' action → {action} (hot-reload applied)"))
}

/// UI-safe display of an allowlist fingerprint: `hmac:<12 hex>…` — the
/// digest is NOT reconstructible into the raw value (R9-7).
#[must_use]
pub(crate) fn display_fingerprint(entry: &str) -> String {
    entry.strip_prefix("hmac:").map_or_else(
        || {
            // Legacy/unknown shape: show it was something else, truncated.
            let shown: String = entry.chars().take(12).collect();
            format!("{shown}…")
        },
        |hex| {
            let shown: String = hex.chars().take(12).collect();
            format!("hmac:{shown}…")
        },
    )
}

/// `cerberus allowlist add <value>` — the raw value travels ONCE to the
/// daemon (over loopback, admin-token gated) and is persisted as an HMAC
/// fingerprint; the CLI output shows only the truncated fingerprint.
pub(crate) async fn allowlist_add(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("allowlist value must be non-empty".to_string());
    }
    let client = ApiClient::resolve();
    let resp = client
        .send_json(
            "POST",
            "/api/allowlist",
            serde_json::json!({ "value": value }).to_string(),
        )
        .await?;
    let fp = resp.get("fingerprint").and_then(|f| f.as_str()).unwrap_or_default();
    Ok(format!("allowlisted (fingerprint {})", display_fingerprint(fp)))
}

/// `cerberus allowlist list` — fingerprints only (raw values are not
/// recoverable by design; R9-7).
pub(crate) async fn allowlist_list() -> Result<String, String> {
    let client = ApiClient::resolve();
    let list = client.get_json("/api/allowlist").await?;
    let empty: Vec<serde_json::Value> = Vec::new();
    let entries: Vec<serde_json::Value> = list.as_array().unwrap_or(&empty).clone();
    let mut out = format!("Allowlist ({} entries, fingerprints only):\n", entries.len());
    for entry in entries {
        let fp = entry.as_str().unwrap_or("?");
        writeln!(out, "  {}", display_fingerprint(fp)).ok();
    }
    Ok(out)
}

/// `cerberus allowlist remove <value|fingerprint>` — the daemon computes
/// the fingerprint of the candidate and removes the matching entry.
pub(crate) async fn allowlist_remove(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("allowlist value must be non-empty".to_string());
    }
    let client = ApiClient::resolve();
    client
        .send_json(
            "DELETE",
            "/api/allowlist",
            serde_json::json!({ "value": value }).to_string(),
        )
        .await?;
    Ok("removed from allowlist (if present)".to_string())
}

// ─────────────────────── B.5 observability ────────────────────────────────

/// `cerberus events [--provider <p>] [--tool <t>] [--since <t>]` (B.5).
///
/// `--since` accepts epoch seconds, RFC 3339, or a relative shorthand
/// (`90s`, `30m`, `2h`, `1d`); the wire param is epoch seconds.
pub(crate) async fn events(
    provider: Option<String>,
    tool: Option<String>,
    since: Option<String>,
) -> Result<String, String> {
    let since_unix = match since.as_deref() {
        Some(s) => Some(parse_since(s)?),
        None => None,
    };
    let client = ApiClient::resolve();
    let mut query = String::new();
    if let Some(p) = provider.filter(|p| !p.is_empty()) {
        write!(query, "provider={}", crate::cli_api::encode_query_component(&p)).ok();
    }
    if let Some(t) = tool.filter(|t| !t.is_empty()) {
        if !query.is_empty() {
            query.push('&');
        }
        write!(query, "tool={}", crate::cli_api::encode_query_component(&t)).ok();
    }
    if let Some(s) = since_unix {
        if !query.is_empty() {
            query.push('&');
        }
        write!(query, "since={s}").ok();
    }
    let path = if query.is_empty() {
        "/api/events".to_string()
    } else {
        format!("/api/events?{query}")
    };
    let events = client.get_json(&path).await?;
    let list = events.as_array().cloned().unwrap_or_default();
    let shown = list.iter().take(50);
    let mut out = format!("Events (showing {} of {}):\n", list.len().min(50), list.len());
    for e in shown {
        let ts = e.get("ts").and_then(|t| t.as_str()).unwrap_or("?");
        let tool = e.get("tool").and_then(|t| t.as_str()).unwrap_or("?");
        let prov = e.get("provider").and_then(|p| p.as_str()).unwrap_or("?");
        let action = e.get("action_taken").and_then(|a| a.as_str()).unwrap_or("?");
        let flags = e
            .get("flags")
            .and_then(|f| f.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        writeln!(out, "  {ts:<25} {tool:<14} {prov:<12} {action:<8} {flags}").ok();
    }
    Ok(out)
}

/// Parse `--since`: integer epoch seconds, RFC 3339, or `Ns|Nm|Nh|Nd`
/// relative to now.
pub(crate) fn parse_since(raw: &str) -> Result<i64, String> {
    if let Ok(epoch) = raw.parse::<i64>() {
        return Ok(epoch);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Ok(dt.timestamp());
    }
    let rel: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let (digits, unit) = rel.split_at(rel.len().saturating_sub(1));
    let n: i64 = digits.parse().map_err(|_| {
        format!("invalid --since {raw:?}: use epoch seconds, RFC 3339, or a relative like 90s / 30m / 2h / 1d")
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(format!("invalid --since {raw:?}: unknown unit (use s/m/h/d)")),
    };
    Ok(chrono::Utc::now().timestamp() - secs)
}

/// `cerberus stats [--by provider|tool|flag]` (B.5). `--by provider` is
/// the per-upstream breakdown (first-class plan requirement, §4.6).
pub(crate) async fn stats(by: Option<String>) -> Result<String, String> {
    if let Some(ref b) = by {
        if !matches!(b.as_str(), "provider" | "tool" | "flag") {
            return Err(format!("invalid --by {b:?}: use provider | tool | flag"));
        }
    }
    let client = ApiClient::resolve();
    let s = client.get_json("/api/stats").await?;
    let total = s.get("total").and_then(serde_json::Value::as_u64).unwrap_or(0);
    let mut out = String::new();
    let want = by.as_deref();

    if want.is_none() || want == Some("provider") {
        writeln!(out, "Events total: {total}").ok();
        if let Some(providers) = s.get("by_provider").and_then(|p| p.as_array()) {
            out.push_str("By provider:\n");
            for p in providers {
                let name = p.get("provider").and_then(|n| n.as_str()).unwrap_or("?");
                let t = p.get("total").and_then(serde_json::Value::as_u64).unwrap_or(0);
                writeln!(out, "  {name:<16} {t:>6} events").ok();
            }
        }
    }
    if want == Some("tool") {
        if let Some(tools) = s.get("by_tool").and_then(|p| p.as_array()) {
            out.push_str("By tool:\n");
            for t in tools {
                let name = t.get("tool").and_then(|n| n.as_str()).unwrap_or("?");
                let total = t.get("total").and_then(serde_json::Value::as_u64).unwrap_or(0);
                writeln!(out, "  {name:<16} {total:>6} events").ok();
            }
        }
    }
    if want == Some("flag") {
        if let Some(flags) = s.get("top_flags").and_then(|p| p.as_array()) {
            out.push_str("Top flags:\n");
            for f in flags {
                if let Some(arr) = f.as_array() {
                    let flag = arr.first().and_then(|v| v.as_str()).unwrap_or("?");
                    let count = arr.get(1).and_then(serde_json::Value::as_u64).unwrap_or(0);
                    writeln!(out, "  {flag:<40} {count}").ok();
                }
            }
        }
    }
    Ok(out)
}

/// `cerberus logs [-f]` (B.5) — daemon log tail from the file `cerberus
/// start` writes. No secrets: the logging layer only emits flags,
/// categories, counts and hashes (F5.1). `-f` follows until interrupted.
pub(crate) fn logs(follow: bool) -> Result<String, String> {
    let path = daemon::log_file_path();
    if !path.exists() {
        return Err(format!(
            "no daemon log at {} — the daemon writes it while running (`cerberus start`)",
            path.display()
        ));
    }
    let mut file = std::fs::File::open(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let tail = tail_lines(&content, 100);
    print!("{tail}");
    if follow {
        let mut offset = content.len() as u64;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if meta.len() < offset {
                // Rotated (cerberus.log.1) — restart from the top.
                offset = 0;
            }
            if meta.len() > offset {
                if let Ok(mut f) = std::fs::File::open(&path) {
                    use std::io::Seek as _;
                    if f.seek(std::io::SeekFrom::Start(offset)).is_ok() {
                        let mut buf = Vec::new();
                        if f.read_to_end(&mut buf).is_ok() {
                            offset += buf.len() as u64;
                            print!("{}", String::from_utf8_lossy(&buf));
                        }
                    }
                }
            }
        }
    }
    Ok(String::new())
}

/// Last `n` lines of a log (pure helper, testable).
#[must_use]
pub(crate) fn tail_lines(content: &str, n: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    let mut out = String::new();
    for line in &lines[start..] {
        writeln!(out, "{line}").ok();
    }
    out
}

// ───────────────────── B.6 config, license, dashboard ─────────────────────

/// `cerberus config path` — locate the config file (B.6).
#[must_use]
pub(crate) fn config_path() -> String {
    daemon::config_dir().join("config.yaml").display().to_string()
}

/// `cerberus config show` — view the config file with the admin token
/// REDACTED (the token is the operator's credential: `config show` output
/// is routinely pasted into issues/logs; `grep admin_token <path>` remains
/// the deliberate reveal path, as `cerberus init` instructs).
pub(crate) fn config_show() -> Result<String, String> {
    let path = daemon::config_dir().join("config.yaml");
    let raw = std::fs::read_to_string(&path)
        .map_err(|_| format!("no config at {} — run `cerberus init` first", path.display()))?;
    let mut out = String::new();
    for line in raw.lines() {
        if line.trim_start().starts_with("admin_token:") {
            writeln!(
                out,
                "admin_token: ***redacted***  (grep admin_token {} to view)",
                path.display()
            )
            .ok();
        } else {
            writeln!(out, "{line}").ok();
        }
    }
    Ok(out)
}

/// `cerberus config edit` — open `$EDITOR` (default: platform editor) on
/// the config file, then validate that the result still parses; the daemon
/// picks changes up via `cerberus reload` (hot) or a restart.
pub(crate) fn config_edit() -> Result<String, String> {
    let path = daemon::config_dir().join("config.yaml");
    if !path.exists() {
        return Err(format!("no config at {} — run `cerberus init` first", path.display()));
    }
    let editor = std::env::var("EDITOR").ok().filter(|e| !e.is_empty());
    #[cfg(target_os = "windows")]
    let fallback = "notepad";
    #[cfg(not(target_os = "windows"))]
    let fallback = "vi";
    let status = editor
        .map_or_else(
            || std::process::Command::new(fallback).arg(&path).status(),
            |e| std::process::Command::new(e).arg(&path).status(),
        )
        .map_err(|e| format!("cannot launch editor: {e}"))?;
    if !status.success() {
        return Err(format!("editor exited with {status}"));
    }
    match ProxyConfig::from_file(&path) {
        Ok(_) => Ok(format!(
            "edited {} — valid. Apply with `cerberus reload` (hot) or restart the daemon.",
            path.display()
        )),
        Err(e) => Err(format!(
            "edited {} but it NO LONGER PARSES ({e}) — fix it with `cerberus validate -f {}` before reloading",
            path.display(),
            path.display()
        )),
    }
}

/// `cerberus login --file <license.json>` — verifies a signed license with
/// the SAME trust root the daemon uses and installs it (0600) at the
/// license path. F6 contract tested against a local issuer; F8 re-verifies
/// against real entitlements. The daemon applies it on next start/restart.
pub(crate) fn login(file: &str) -> Result<String, String> {
    let mgr = cerberus_packs::license::LicenseManager::from_file(file).map_err(|e| format!("license rejected: {e}"))?;
    let dest = daemon::license_path();
    let content = std::fs::read_to_string(file).map_err(|e| format!("cannot read license: {e}"))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    cerberus_proxy::api::write_config_file_0600(&dest, &content).map_err(|e| format!("cannot install license: {e}"))?;
    Ok(format!(
        "license installed at {} (mode 0600)\n{}\nRestart the daemon (`cerberus restart`) to apply Pro features.",
        dest.display(),
        daemon::license_summary(&mgr)
    ))
}

/// `cerberus dashboard` — opens the local UI (B.6). The daemon serves the
/// dashboard at `/api/dashboard`; `/ui` redirects there. Never fails: when
/// no browser opener is available the URL is printed instead.
pub(crate) fn dashboard() -> String {
    let base = crate::cli_api::resolve_endpoint().base_url();
    let url = format!("{base}/ui");
    let launched = open_in_browser(&url);
    let lead = if launched {
        "Opening the dashboard"
    } else {
        "Open the dashboard manually"
    };
    format!(
        "{lead}: {url}\nLogin with the admin token from {} (`grep admin_token <path>`).",
        daemon::config_dir().join("config.yaml").display()
    )
}

/// Best-effort browser launch across platforms. Returns false when the
/// opener could not even be spawned (the caller then just prints the URL).
fn open_in_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

// ─────────────────────────── B.7 Mode A ───────────────────────────────────

/// `cerberus validate -f <config.yaml>` — validates a config BEFORE
/// deploying (B.7): syntax + upstreams + policy + a local compile of the
/// custom rules (`ReDoS` is impossible by construction — the engine only
/// accepts linear-time `regex` patterns and hard-fails lookarounds).
pub(crate) fn validate(file: &str) -> Result<String, String> {
    let cfg = ProxyConfig::from_file(file).map_err(|e| format!("INVALID: {e}"))?;
    cfg.policy.validate().map_err(|e| format!("INVALID policy: {e}"))?;
    for (name, up) in &cfg.upstreams {
        if !up.url.starts_with("http://") && !up.url.starts_with("https://") {
            return Err(format!(
                "INVALID: upstream {name:?} url must be http(s) (got {:?})",
                up.url
            ));
        }
    }
    let compiled = EngineBuilder::new(&cfg.policy.custom_rules)
        .build()
        .map_err(|e| format!("INVALID: custom rules do not compile: {e}"))?;
    Ok(format!(
        "{} is VALID: {} upstreams, mode={:?}, fail_policy={:?}, {} categories, {} rule overrides, {} custom rules → {} compiled patterns",
        file,
        cfg.upstreams.len(),
        cfg.mode,
        cfg.fail_policy,
        cfg.policy.categories.len(),
        cfg.policy.rule_actions.len(),
        cfg.policy.custom_rules.len(),
        compiled.num_rules()
    ))
}

/// `cerberus reload` — forces a hot-reload of the on-disk config on the
/// running daemon (`POST /api/reload`), no restart (B.7 / §4.6).
pub(crate) async fn reload() -> Result<String, String> {
    let client = ApiClient::resolve();
    let resp = client.send_json("POST", "/api/reload", "{}".to_string()).await?;
    Ok(resp
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("config reloaded")
        .to_string())
}

// ─────────────────────────── status enhancement ───────────────────────────

/// `cerberus status` detail: base daemon status + (when the control plane
/// is reachable AND a token is configured) the live port/mode/upstreams
/// from the SAME API the dashboard uses. Degrades silently to the base
/// status when the daemon is down or unauthenticated.
pub(crate) async fn status_detail() -> String {
    let base = daemon::status();
    let mut out = format!("{base}\n{}", crate::mitm::status());
    let client = ApiClient::resolve();
    if let Ok(cfg) = client.get_json("/api/config").await {
        let mode = cfg.get("mode").and_then(|m| m.as_str()).unwrap_or("?");
        let listen = cfg.get("listen").and_then(|l| l.as_str()).unwrap_or("?");
        let upstreams = cfg
            .get("upstreams")
            .and_then(|u| u.as_object())
            .map(|o| o.keys().cloned().collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        writeln!(out, "control plane: {listen} mode={mode} upstreams: {upstreams}").ok();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── version/upgrade ──

    #[test]
    fn version_matches_cargo_pkg() {
        assert_eq!(version(), format!("cerberus {}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn semver_parsing_and_compare() {
        assert_eq!(parse_semver("0.1.2"), Some((0, 1, 2)));
        assert_eq!(parse_semver("1.10.3"), Some((1, 10, 3)));
        assert!(parse_semver("nope").is_none());
        assert!((1, 0, 0) > (0, 99, 99));
    }

    /// `upgrade` against a LOCAL manifest that reports a newer version →
    /// "upgrade available" (fix-plan: functional contract against a local
    /// repository; F8 re-verifies against real artifacts).
    #[tokio::test]
    async fn upgrade_reports_newer_version_from_local_manifest() {
        let server = tiny_http_server(serde_json::json!({ "tag_name": "v9.9.9" }).to_string());
        let url = format!("http://{}", server.addr);
        let out = upgrade_check(Some(url)).await.expect("upgrade check");
        assert!(out.contains("upgrade available"), "{out}");
        assert!(out.contains("9.9.9"), "{out}");
        assert!(out.contains("brew upgrade"), "{out}");
    }

    /// Same current version → up to date (no invented download).
    #[tokio::test]
    async fn upgrade_reports_up_to_date_when_equal() {
        let current = env!("CARGO_PKG_VERSION");
        let server = tiny_http_server(serde_json::json!({ "tag_name": current }).to_string());
        let url = format!("http://{}", server.addr);
        let out = upgrade_check(Some(url)).await.expect("upgrade check");
        assert!(out.contains("up to date"), "{out}");
    }

    /// A manifest without a recognizable version is an ERROR, not a silent
    /// "up to date" (no placeholder acceptance).
    #[tokio::test]
    async fn upgrade_rejects_unrecognizable_manifest() {
        let server = tiny_http_server(r#"{"hello":"world"}"#.to_string());
        let url = format!("http://{}", server.addr);
        let err = upgrade_check(Some(url)).await.expect_err("must fail");
        assert!(err.contains("tag_name"), "{err}");
    }

    // ── mode ──

    #[test]
    fn mode_validation_rejects_garbage() {
        assert_eq!(validate_mode_arg("enforce").expect("ok"), "enforce");
        assert_eq!(validate_mode_arg("SHADOW").expect("ok"), "shadow");
        let err = validate_mode_arg("bogus").expect_err("must fail");
        assert!(err.contains("shadow"), "{err}");
    }

    // ── agents ──

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-cli-surface-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(dir.join(".cerberus")).expect("mkdir");
        std::fs::create_dir_all(dir.join("Cerberus")).expect("mkdir win");
        dir
    }

    /// `agents wire` records the state and prints the export line; `unwire`
    /// clears it; an unknown agent is rejected with the known list.
    #[test]
    fn agents_wire_unwire_roundtrip() {
        let _guard = crate::cli_api::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("agents");
        let prev_home = std::env::var("HOME").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("APPDATA", &home);

        let unknown = agent_wire("not-an-agent");
        assert!(unknown.is_err());
        assert!(unknown.unwrap_err().contains("known agents"));

        let wired = agent_wire("opencode").expect("wire");
        assert!(wired.contains("OPENCODE_BASE_URL"), "{wired}");
        assert!(wired.contains("http://127.0.0.1:8787"), "{wired}");
        let list = agents_list();
        assert!(list.contains("wired → cerberus"), "{list}");

        let unwired = agent_unwire("opencode").expect("unwire");
        assert!(unwired.contains("unset OPENCODE_BASE_URL"), "{unwired}");
        let list = agents_list();
        assert!(list.contains("not wired"), "{list}");

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    // ── allowlist display (R9-7: fingerprints only) ──

    #[test]
    fn fingerprint_display_never_shows_full_digest() {
        let fp = format!("hmac:{}", "a".repeat(64));
        let shown = display_fingerprint(&fp);
        assert!(shown.starts_with("hmac:"), "{shown}");
        assert!(shown.ends_with('…'), "{shown}");
        assert!(shown.len() < "hmac:".len() + 20, "must truncate: {shown}");
        assert!(!shown.contains(&"a".repeat(32)), "never the full digest: {shown}");
    }

    // ── --since parsing ──

    #[test]
    fn since_parses_epoch_rfc3339_and_relative() {
        assert_eq!(parse_since("1700000000").expect("epoch"), 1_700_000_000);
        let rfc = parse_since("2026-01-01T00:00:00Z").expect("rfc3339");
        assert!(rfc > 1_700_000_000);
        let before = chrono::Utc::now().timestamp();
        let rel = parse_since("30m").expect("relative");
        // The call happens within the same second-window: ±2s clock slack.
        assert!(
            (rel - (before - 1_800)).abs() <= 2,
            "relative '30m' must be now-1800s (got {rel}, now {before})"
        );
        let err = parse_since("nope");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("--since"));
    }

    // ── logs tail ──

    #[test]
    fn tail_lines_returns_last_n() {
        let content = (1..=250).map(|i| format!("line-{i}")).collect::<Vec<_>>().join("\n");
        let tail = tail_lines(&content, 100);
        assert!(tail.contains("line-250"), "{tail}");
        assert!(!tail.contains("line-100\n"), "{tail}");
        assert_eq!(tail.lines().count(), 100);
    }

    #[test]
    fn config_path_is_under_cerberus_dir() {
        let p = config_path();
        assert!(p.contains("config.yaml"), "{p}");
    }

    // ── validate ──

    fn write_config(dir: &std::path::Path, yaml: &str) -> String {
        let path = dir.join("cerberus.yaml");
        std::fs::write(&path, yaml).expect("write");
        path.to_string_lossy().to_string()
    }

    #[test]
    fn validate_accepts_a_well_formed_config() {
        let dir = temp_home("validate-ok");
        let file = write_config(
            &dir,
            "listen: 127.0.0.1:8787\nmode: enforce\nfail_policy: closed\nupstreams:\n  openai:\n    url: https://api.openai.com\n",
        );
        let out = validate(&file).expect("valid");
        assert!(out.contains("VALID"), "{out}");
        assert!(out.contains("1 upstreams"), "{out}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn validate_rejects_bad_scheme_and_bad_regex() {
        let dir = temp_home("validate-bad");
        let bad_url = write_config(&dir, "listen: 127.0.0.1:8787\nupstreams:\n  x:\n    url: ftp://nope\n");
        let err = validate(&bad_url).expect_err("must fail");
        assert!(err.contains("http(s)"), "{err}");

        let evil = dir.join("evil.yaml");
        std::fs::write(
            &evil,
            "listen: 127.0.0.1:8787\nupstreams:\n  openai:\n    url: https://api.openai.com\npolicy:\n  custom_rules:\n    - flag: evil.lookaround\n      category: secrets\n      severity: high\n      patterns:\n        - \"(?<=evil)look\"\n",
        )
        .expect("write");
        let err = validate(&evil.to_string_lossy()).expect_err("lookaround must fail");
        assert!(err.contains("INVALID"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── rules add parsing ──

    #[test]
    fn rule_file_parses_single_and_list() {
        let single = "flag: custom.test\ncategory: secrets\nseverity: high\npatterns:\n  - \"sk-TEST-[a-z]+\"\n";
        let rules = parse_rule_file(single).expect("single");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].flag, "custom.test");

        let list = "- flag: custom.a\n  category: secrets\n  severity: high\n  patterns: [\"a\"]\n- flag: custom.b\n  category: pii\n  severity: low\n  patterns: [\"b\"]\n";
        let rules = parse_rule_file(list).expect("list");
        assert_eq!(rules.len(), 2);

        assert!(parse_rule_file("not: [a, rule").is_err());
    }

    /// A custom rule with a catastrophic-looking lookaround is rejected
    /// LOCALLY before any daemon call (engine hard error).
    #[tokio::test]
    async fn rules_add_rejects_bad_regex_before_network() {
        let dir = temp_home("rules-bad");
        let file = dir.join("rule.yaml");
        std::fs::write(
            &file,
            "flag: evil.x\ncategory: secrets\nseverity: high\npatterns:\n  - \"(?<=a)b\"\n",
        )
        .expect("write");
        // No daemon needed: the local compile check fires first.
        let err = rules_add(&file.to_string_lossy()).await.expect_err("must fail");
        assert!(err.contains("does not compile"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── login ──

    /// Writes a signed Pro license (same pattern as the F7 CLI integration
    /// test) and verifies `login` verifies + installs it 0600 at the
    /// license path (local issuer = the F6 contract).
    #[test]
    fn login_verifies_and_installs_signed_license() {
        use ed25519_dalek::Signer;
        let _guard = crate::cli_api::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("login");
        let prev_home = std::env::var("HOME").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        let prev_root = std::env::var("CERBERUS_LICENSE_PUBLIC_KEY").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("APPDATA", &home);

        let keypair = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let license = cerberus_packs::license::License {
            tier: cerberus_packs::license::LicenseTier::Pro,
            email: "dev@cerberus.dev".to_string(),
            license_id: "f6b-login-test".to_string(),
            expires_at: None,
            features: Vec::new(),
        };
        let license_json = serde_json::to_string(&license).expect("serialize");
        let signature = keypair.sign(license_json.as_bytes());
        let signed = cerberus_packs::license::SignedLicense {
            license_json: license_json.clone(),
            signature_hex: hex::encode(signature.to_bytes().as_slice()),
            signer_public_key_hex: hex::encode(keypair.verifying_key().as_bytes()),
            owner_public_key_hex: None,
        };
        let src = home.join("license-src.json");
        std::fs::write(&src, serde_json::to_string(&signed).expect("serialize signed")).expect("write");
        std::env::set_var(
            "CERBERUS_LICENSE_PUBLIC_KEY",
            hex::encode(keypair.verifying_key().as_bytes()),
        );

        let out = login(&src.to_string_lossy()).expect("login");
        assert!(out.contains("installed"), "{out}");
        assert!(out.contains("tier=pro"), "{out}");
        let dest = daemon::license_path();
        assert!(dest.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "license installed 0600");
        }

        // A tampered license is REJECTED and does not replace the good one.
        let mut tampered = signed;
        tampered.license_json = license_json.replace("dev@cerberus.dev", "evil@attacker.dev");
        let bad = home.join("license-bad.json");
        std::fs::write(&bad, serde_json::to_string(&tampered).expect("serialize bad")).expect("write");
        let err = login(&bad.to_string_lossy()).expect_err("tampered license must fail");
        assert!(err.contains("rejected"), "{err}");

        match prev_root {
            Some(v) => std::env::set_var("CERBERUS_LICENSE_PUBLIC_KEY", v),
            None => std::env::remove_var("CERBERUS_LICENSE_PUBLIC_KEY"),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    // ── config show redaction ──

    #[test]
    fn config_show_redacts_the_admin_token() {
        let _guard = crate::cli_api::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("config-show");
        let prev_home = std::env::var("HOME").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("APPDATA", &home);
        let secret = "super-secret-token-0123456789";
        std::fs::write(
            daemon::config_dir().join("config.yaml"),
            format!("listen: 127.0.0.1:8787\nadmin_token: \"{secret}\"\nupstreams:\n  openai:\n    url: https://api.openai.com\n"),
        )
        .expect("write");
        let out = config_show().expect("show");
        assert!(!out.contains(secret), "token must be redacted: {out}");
        assert!(out.contains("***redacted***"), "{out}");
        assert!(out.contains("listen: 127.0.0.1:8787"), "{out}");
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// Minimal one-shot HTTP server for local-manifest tests (thread serves ONE
    /// blocking response then exits).
    struct TinyServer {
        #[allow(dead_code)]
        addr: std::net::SocketAddr,
    }

    fn tiny_http_server(body: String) -> TinyServer {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        TinyServer { addr }
    }
}
