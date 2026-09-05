//! Initialization and agent auto-detection (`cerberus init`).
//!
//! Detects installed agents (Claude Code, Codex, opencode, pi) and configures
//! their `*_BASE_URL` to point to the local Cerberus proxy.

use std::fmt::Write as _;
use std::path::Path;

use cerberus_engine::engine::EngineBuilder;
use cerberus_engine::loader::load_rules_from_str;

use crate::packs::default_rules_json;

/// A detected agent.
#[derive(Debug, Clone)]
pub(crate) struct DetectedAgent {
    /// Name of the agent.
    pub name: String,
    /// Environment variable for the base URL.
    pub env_var: String,
    /// Path to the binary (if found).
    pub binary_path: Option<String>,
    /// Is it configured to use Cerberus?
    pub configured: bool,
}

/// Known agents with their environment variables.
const KNOWN_AGENTS: &[(&str, &str, &[&str])] = &[
    ("Claude Code", "CLAUDE_CODE_BASE_URL", &["claude", "claude-code"]),
    ("Codex", "CODEX_BASE_URL", &["codex"]),
    ("opencode", "OPENCODE_BASE_URL", &["opencode"]),
    ("pi", "PI_BASE_URL", &["pi"]),
    ("Continue (Cursor)", "CONTINUE_BASE_URL", &["continue", "cursor"]),
];

/// Resolve an agent query (display name, first word, or env var) against
/// the known-agents table (F6.B: `cerberus agents wire/unwire <agent>`).
#[must_use]
pub(crate) fn agent_by_name(query: &str) -> Option<(&'static str, &'static str)> {
    let q = query.trim().to_ascii_lowercase();
    KNOWN_AGENTS
        .iter()
        .find(|(name, env_var, aliases)| {
            name.to_ascii_lowercase() == q
                || env_var.eq_ignore_ascii_case(&q)
                || name
                    .split_whitespace()
                    .next()
                    .is_some_and(|n| n.to_ascii_lowercase() == q)
                || aliases.iter().any(|a| a.eq_ignore_ascii_case(&q))
        })
        .map(|(name, env_var, _)| (*name, *env_var))
}

/// Run `cerberus init`.
///
/// # Errors
///
/// Returns an error if the configuration directory cannot be created.
pub(crate) fn run_init(config_dir: &str) -> Result<String, String> {
    let cfg_path = Path::new(config_dir);
    std::fs::create_dir_all(cfg_path).map_err(|e| format!("cannot create config dir: {e}"))?;

    let agents = detect_agents();

    let mut report = String::from("✦ Cerberus Init ✦\n\n");
    writeln!(report, "Config: {config_dir}").ok();
    writeln!(report, "Rules: {} loaded", load_rule_count()).ok();
    report.push_str("\n📋 Detected agents:\n");

    let mut configured = 0;
    for agent in &agents {
        let status = if agent.configured {
            configured += 1;
            "✅ configured"
        } else if agent.binary_path.is_some() {
            "⚠️  detected, requires setting env var"
        } else {
            "❌ not found"
        };
        writeln!(report, "  {:<20} {status}", agent.name).ok();
    }

    writeln!(report, "\nSummary: {configured}/{} agents configured", agents.len()).ok();

    // R9-5 (F6): the DEFAULT install must not boot a closed control plane —
    // `init` generates a strong random admin token and persists it in
    // config.yaml (file written 0600) so the default init → start flow is
    // authenticated AND usable. The token is NOT printed to stdout/logs
    // (bootstrap channel = the 0600 config file; paste it into the
    // dashboard login card from there).
    let admin_token = generate_admin_token();
    let yaml = init_config_yaml(&admin_token);
    let config_path = cfg_path.join("config.yaml");
    write_config_0600(&config_path, &yaml).map_err(|e| format!("cannot write config: {e}"))?;
    // F6.A attempt 2 (P2-1): the mode in the report is stat-ed from the file,
    // so the output tells the truth (the old text claimed "mode 0600" even
    // when a re-init left a pre-existing 0644 file untouched).
    writeln!(
        report,
        "\n🔐 Control plane: a random admin token was generated and written to {} ({}, R9-5). \
         View it with `grep admin_token {}` and paste it into the dashboard login card; it is never \
         served by the API or printed here. Without it every data /api/* route responds 401.",
        config_path.display(),
        actual_mode_note(&config_path),
        config_path.display()
    )
    .ok();

    if !agents.iter().any(|a| a.configured) {
        report.push_str("\n💡 Tip: manually set your agent's environment variable:\n");
        for agent in &agents {
            if agent.binary_path.is_some() {
                writeln!(report, "  export {}=http://127.0.0.1:8787", agent.env_var).ok();
            }
        }
    }

    report.push_str("\n▶ Next steps (real operation):\n");
    report.push_str("  1. cerberus start --port 8787\n");
    report.push_str("     (default upstreams already exist: openai → api.openai.com, anthropic → api.anthropic.com;\n");
    report.push_str(
        "      you do not need CERBERUS_UPSTREAM_URL on first boot — edit config.yaml if you change provider)\n",
    );
    report.push_str("  2. export <YOUR_AGENT>_BASE_URL=http://127.0.0.1:8787  (e.g. OPENCODE_BASE_URL)\n");

    Ok(report)
}

/// Default boot config YAML (zero-config, F4): EXPLICIT upstreams for
/// openai/anthropic → `cerberus start` boots without `CERBERUS_UPSTREAM_URL`.
/// The operator can edit `URLs`/`path_prefix` in `config.yaml` without
/// touching code.
///
/// R9-5 (F6): `admin_token` is included — a fresh install boots with an
/// AUTHENTICATED control plane instead of the R9-5 open-by-default state.
fn init_config_yaml(admin_token: &str) -> String {
    format!(
        "listen: 127.0.0.1:8787\nmode: enforce\nfail_policy: closed\nadmin_token: {admin_token}\nupstreams:\n  anthropic:\n    url: https://api.anthropic.com\n  openai:\n    url: https://api.openai.com\n"
    )
}

/// Generate a strong random admin token: 32 CSPRNG bytes, 64 lowercase hex
/// (≥ [`cerberus_proxy::api::ADMIN_TOKEN_MIN_BYTES`], comfortably above the
/// non-loopback strong-token requirement).
fn generate_admin_token() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("CSPRNG unavailable");
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Write config.yaml with restrictive permissions (it carries the admin
/// token). F6.A attempt 2 (P2-1): delegates to the shared atomic helper —
/// the file is REPLACED via a tmp created 0600 + rename (F5 F-1 discipline,
/// no umask window), so a re-init over an existing non-0600 config REPAIRS
/// the mode instead of preserving it (the old in-place create/truncate
/// applied 0600 only at creation). Every error is handled (init fails
/// loudly instead of leaving a world-readable credential file).
fn write_config_0600(path: &Path, content: &str) -> std::io::Result<()> {
    cerberus_proxy::api::write_config_file_0600(path, content)
}

/// Truthful permission note for the init report (F6.A attempt 2, P2-1): the
/// mode claim is DERIVED from the file itself (stat), not asserted — on unix
/// it reports the actual octal mode (the helper guarantees 0600); when the
/// platform has no unix mode or the stat fails, no numeric claim is made.
fn actual_mode_note(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).map_or_else(
            |_| "permissions applied".to_string(),
            |m| format!("mode {:04o}", m.permissions().mode() & 0o777),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        "permissions applied".to_string()
    }
}

/// Detect installed agents on the system.
#[must_use]
pub(crate) fn detect_agents() -> Vec<DetectedAgent> {
    KNOWN_AGENTS
        .iter()
        .map(|(name, env_var, bins)| {
            let binary_path = bins.iter().find_map(|bin| find_binary(bin));
            let configured = if binary_path.is_some() {
                std::env::var(env_var).is_ok()
            } else {
                false
            };
            DetectedAgent {
                name: name.to_string(),
                env_var: env_var.to_string(),
                binary_path,
                configured,
            }
        })
        .collect()
}

/// Find a binary in the PATH.
///
/// The global constant `KNOWN_AGENTS` stores names **without** extension; here
/// `.exe` is added as a priority candidate on Windows (never in the constant).
fn find_binary(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            for candidate in binary_candidates(name) {
                let full_path = dir.join(&candidate);
                if full_path.is_file() && is_executable_candidate(&full_path) {
                    return Some(full_path.to_string_lossy().to_string());
                }
            }
            None
        })
    })
}

/// File names to try for a binary: on Windows `name.exe` first (avoids false
/// positives from an extensionless file) then `name`; on other platforms just
/// `name`.
fn binary_candidates(name: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![format!("{name}.exe"), name.to_string()]
    }
    #[cfg(not(windows))]
    {
        vec![name.to_string()]
    }
}

/// Check that `path` is an executable candidate (execution bit on unix; on
/// Windows it is enough that the file exists).
#[allow(clippy::missing_const_for_fn)]
fn is_executable_candidate(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

/// Load rules and return the count.
fn load_rule_count() -> usize {
    load_rules_from_str(&default_rules_json()).map_or(0, |rules| rules.len())
}

/// Scan a file (dry-run mode).
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub(crate) fn scan_file(path: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read file: {e}"))?;
    Ok(scan_text(&content))
}

/// Scan text (dry-run mode).
#[must_use]
pub(crate) fn scan_text(text: &str) -> String {
    let rules_json = default_rules_json();
    let rules = match load_rules_from_str(&rules_json) {
        Ok(r) => r,
        Err(e) => return format!("error loading rules: {e}"),
    };
    // R9-16 (F5.2): dry-run hashes are keyed too — env/file key when present
    // (consistent with the daemon's audit hashes), else an ephemeral
    // per-process CSPRNG key. NEVER unkeyed; the read-only resolution never
    // writes the key file from a diagnostic command.
    let (audit_key, key_source) =
        crate::audit_key::resolve_existing_or_ephemeral_key(&crate::audit_key::default_config_dir());
    let engine = match EngineBuilder::new(&rules).with_payload_secret(audit_key).build() {
        Ok(e) => e,
        Err(e) => return format!("engine build error: {e}"),
    };

    let output = engine.scan(text);
    if output.findings.is_empty() {
        return "✓ No sensitive data detected.".to_string();
    }

    let mut report = String::from("🔍 Scan findings:\n\n");
    for f in &output.findings {
        // Never expose the raw value on screen (P1-12): only flag, action,
        // position, and hash of the detected value.
        writeln!(
            report,
            "  [{:>8}] {} (pos {}..{}) hash={}",
            f.action, f.flag, f.start, f.end, f.hashed_value
        )
        .ok();
    }
    // F5 F-3: an EPHEMERAL dry-run key makes the hashes per-process and NOT
    // comparable across runs — the output must disclose that (loudness, not
    // silence). A normal boot (key file present) never reaches this state.
    if matches!(key_source, crate::audit_key::KeySource::Ephemeral) {
        writeln!(
            report,
            "\n⚠ note: no persisted audit key found — these hashes use an EPHEMERAL per-process \
             key and are not comparable across runs (dry-run display only)"
        )
        .ok();
    }
    writeln!(report, "\nGlobal action: {}", output.action_overall).ok();
    report
}

/// System diagnostics.
#[must_use]
pub(crate) fn doctor() -> String {
    let mut report = String::new();
    report.push_str("✦ Cerberus Doctor ✦\n\n");

    writeln!(report, "Daemon: {}", crate::daemon::status()).ok();

    let rules_count = load_rule_count();
    writeln!(report, "Rules loaded: {rules_count}").ok();

    report.push_str("\nAgents:\n");
    for agent in detect_agents() {
        let status = if let Some(_path) = &agent.binary_path {
            if agent.configured {
                "✅ ready"
            } else {
                "⚠️  not configured"
            }
        } else {
            "❌ not installed"
        };
        writeln!(report, "  {:<20} {status}", agent.name).ok();
    }

    let cfg_dir = crate::daemon::config_dir();
    writeln!(
        report,
        "\nConfig dir: {} {}",
        cfg_dir.display(),
        if cfg_dir.exists() { "✅" } else { "❌ does not exist" }
    )
    .ok();

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guard to serialize tests that mutate `std::env` and the PATH.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn detect_agents_returns_vec() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let agents = detect_agents();
        assert!(agents.len() >= 4);
    }

    /// F4 cross-platform: `find_binary` discovers a real binary in an isolated
    /// PATH. On Windows it prefers the `.exe` candidate and an extensionless
    /// file is not enough; on unix it requires the execution bit.
    #[test]
    fn find_binary_discovers_executable_only() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");

        let real = dir.path().join(if cfg!(windows) { "opencode.exe" } else { "opencode" });
        std::fs::write(&real, "fake binary").expect("write real");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&real).expect("metadata").permissions();
            perms.set_mode(0o755); // executable
            std::fs::set_permissions(&real, perms).expect("chmod");
        }

        #[cfg(windows)]
        {
            // False positive: an extensionless file must not win over the .exe.
            let plain = dir.path().join("opencode");
            std::fs::write(&plain, "not a real exe").expect("write plain");
        }

        let prev_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());

        assert_eq!(
            find_binary("opencode").as_deref(),
            Some(real.to_string_lossy().as_ref())
        );

        match prev_path {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn scan_empty_text_returns_clean() {
        let report = scan_text("no secrets here");
        assert!(report.contains("No sensitive data"));
    }

    #[test]
    fn scan_with_skey_detects() {
        // "openai" is a contextKeyword of the secret.openai_api_key rule →
        // with constraints applied, it is detected.
        let report = scan_text("my openai api key is sk-abcDEFghijklmnopqrstuvwxyz1234");
        assert!(report.contains("Scan findings"));
    }

    #[test]
    fn scan_nonexistent_file_returns_error() {
        let result = scan_file("/tmp/cerberus_nonexistent_XX_test.txt");
        assert!(result.is_err());
    }

    // ─── F4: zero-config — init leaves explicit default upstreams ─────────

    #[test]
    fn init_writes_config_with_default_upstreams() {
        let dir = std::env::temp_dir().join(format!(
            "cercerberus_init_upstream_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        // R9-5 (F6): the init YAML carries a strong admin token.
        let token = generate_admin_token();
        assert!(
            token.len() >= cerberus_proxy::api::ADMIN_TOKEN_MIN_BYTES,
            "strong token"
        );
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        let yaml = init_config_yaml(&token);
        let parsed = cerberus_proxy::config::ProxyConfig::parse(&yaml).expect("default yaml parses");
        assert!(parsed.upstreams.contains_key("openai"), "openai default required");
        assert!(parsed.upstreams.contains_key("anthropic"), "anthropic default required");
        assert_eq!(
            parsed.upstreams["openai"].url, "https://api.openai.com",
            "without env, the first boot must reach OpenAI"
        );

        // `cerberus init` in an isolated dir writes that YAML to config.yaml.
        let report = run_init(dir.to_str().expect("utf8")).expect("init");
        assert!(
            report.contains("you do not need CERBERUS_UPSTREAM_URL"),
            "init must announce zero-config: {report}"
        );
        let written = std::fs::read_to_string(dir.join("config.yaml")).expect("config written by init");
        assert!(
            written.contains("https://api.openai.com"),
            "the written config must preserve the upstreams: {written}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// F6.A attempt 2 (P2-1 regression): re-running init over an existing
    /// non-0600 config.yaml must ENFORCE 0600 on the rewritten file (the
    /// rotated token must never live in a world-readable file) and the
    /// report's mode claim must match the real file.
    #[test]
    fn reinit_over_non_0600_config_enforces_0600_and_tells_the_truth() {
        let dir = std::env::temp_dir().join(format!(
            "cerberus_f6a2_reinit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let config_path = dir.join("config.yaml");
        std::fs::write(&config_path, "listen: 127.0.0.1:8787\nadmin_token: stale\n").expect("seed config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        }

        // `report` is asserted in the unix block below (mode-truth check); on
        // non-unix targets that use is cfg'd out (clippy/rustc -D warnings).
        #[cfg_attr(not(unix), allow(unused_variables))]
        let report = run_init(dir.to_str().expect("utf8")).expect("re-init");

        let yaml = std::fs::read_to_string(&config_path).expect("rewritten config");
        assert!(yaml.contains("admin_token"), "a fresh token must be present: {yaml}");
        assert!(!yaml.contains("stale"), "the old token must be rotated away: {yaml}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&config_path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "re-init must repair the mode to 0600, got {mode:o}");
            // The report tells the truth: it claims 0600 and the file IS 0600.
            assert!(
                report.contains("mode 0600"),
                "the report must state the real mode: {report}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
