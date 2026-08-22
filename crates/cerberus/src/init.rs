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

    let yaml = init_config_yaml();
    let config_path = cfg_path.join("config.yaml");
    std::fs::write(&config_path, yaml).map_err(|e| format!("cannot write config: {e}"))?;

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
#[must_use]
const fn init_config_yaml() -> &'static str {
    "listen: 127.0.0.1:8787\nmode: enforce\nfail_policy: closed\nupstreams:\n  anthropic:\n    url: https://api.anthropic.com\n  openai:\n    url: https://api.openai.com\n"
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
    let engine = match EngineBuilder::new(&rules).build() {
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
        let yaml = init_config_yaml();
        let parsed = cerberus_proxy::config::ProxyConfig::parse(yaml).expect("default yaml parses");
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
}
