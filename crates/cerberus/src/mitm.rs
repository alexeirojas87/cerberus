//! Explicit management of the opt-in forward proxy + local CA (F4/mitm-opt-in).
//!
//! Generating the CA, enabling the listener, and trusting the certificate are
//! separate actions. Cerberus only implements the first two; it never
//! modifies the system trust store.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use cerberus_proxy::forward::{
    generate_local_ca, normalize_allowed_hosts, validate_ca_files, CaPaths, ForwardProxyConfig,
};
use serde::{Deserialize, Serialize};

const DEFAULT_MITM_LISTEN: &str = "127.0.0.1:8788";

/// Persisted config of the advanced mode. Absence of the file unambiguously
/// means `enabled = false`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MitmConfig {
    pub(crate) enabled: bool,
    pub(crate) listen: String,
    pub(crate) hosts: Vec<String>,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: DEFAULT_MITM_LISTEN.to_string(),
            hosts: Vec::new(),
        }
    }
}

/// Path to the CA certificates directory.
pub(crate) fn ca_dir() -> PathBuf {
    crate::daemon::config_dir().join("ca")
}

/// Path to the public CA certificate.
pub(crate) fn ca_cert_path() -> PathBuf {
    ca_dir().join("cerberus-ca.cert")
}

/// Path to the CA private key.
pub(crate) fn ca_key_path() -> PathBuf {
    ca_dir().join("cerberus-ca.key")
}

fn ca_paths() -> CaPaths {
    CaPaths {
        cert: ca_cert_path(),
        key: ca_key_path(),
    }
}

fn config_path() -> PathBuf {
    crate::daemon::config_dir().join("mitm.json")
}

/// Loads and validates the effective opt-in consumed by the daemon. An
/// existing CA alone never enables the listener.
pub(crate) fn runtime_config() -> Result<Option<ForwardProxyConfig>, String> {
    runtime_config_from(&config_path(), ca_paths())
}

fn runtime_config_from(path: &Path, ca: CaPaths) -> Result<Option<ForwardProxyConfig>, String> {
    let config = load_config_from(path)?;
    if !config.enabled {
        return Ok(None);
    }
    validate_ca_files(&ca)?;
    let listen: SocketAddr = config
        .listen
        .parse()
        .map_err(|_| "invalid MITM listen address".to_string())?;
    ForwardProxyConfig::new(listen, &config.hosts, ca).map(Some)
}

/// Generates the CA after an explicit CLI action. It does not trust it nor
/// run privileged tools.
pub(crate) fn init_ca() -> Result<String, String> {
    let paths = ca_paths();
    generate_local_ca(&paths)?;
    Ok(format!(
        "Local CA generated (NOT trusted)\n  Certificate: {}\n  Private key: {}\n\n{}",
        paths.cert.display(),
        paths.key.display(),
        trust_instructions()
    ))
}

/// Enables the listener for exact hosts, after checking that the CA was
/// explicitly generated. Does not start the daemon nor touch the trust store.
pub(crate) fn enable(hosts: &[String], listen: &str) -> Result<String, String> {
    validate_ca_files(&ca_paths())
        .map_err(|error| format!("CA not ready ({error}); run `cerberus mitm init-ca` explicitly first"))?;
    let hosts = normalize_allowed_hosts(hosts)?;
    let listen_addr: SocketAddr = listen.parse().map_err(|_| "invalid MITM listen address".to_string())?;
    let _validated = ForwardProxyConfig::new(listen_addr, &hosts, ca_paths())?;
    let config = MitmConfig {
        enabled: true,
        listen: listen_addr.to_string(),
        hosts: hosts.clone(),
    };
    save_config_to(&config_path(), &config)?;
    Ok(format!(
        "MITM opt-in enabled on {} for [{}].\nConfig persisted at {} — effective on the next Cerberus boot.\nSet HTTPS_PROXY=http://{} only on the chosen tool.",
        config.listen,
        hosts.join(", "),
        config_path().display(),
        config.listen
    ))
}

/// Disables the listener without deleting the CA (a distinct destructive action).
pub(crate) fn disable() -> Result<String, String> {
    let mut config = load_config_from(&config_path())?;
    config.enabled = false;
    save_config_to(&config_path(), &config)?;
    Ok(format!(
        "MITM disabled; the reverse proxy remains the default mode.\nConfig persisted at {} — effective on the next boot.",
        config_path().display()
    ))
}

/// F4 (MITM connected to the daemon): apply `enable` taking into account
/// whether the daemon is running. The config is ALWAYS persisted (effective
/// at boot), and if the daemon is live the restart note is attached: there is
/// no `/api/mitm` at runtime (the control plane is another agent's), so the
/// change applies only after `cerberus stop && cerberus start`.
pub(crate) fn enable_with_daemon_state(hosts: &[String], listen: &str, daemon_running: bool) -> Result<String, String> {
    let mut msg = enable(hosts, listen)?;
    if daemon_running {
        msg.push_str(&daemon_restart_note());
    }
    Ok(msg)
}

/// Same as [`Self::enable_with_daemon_state`] for `disable`.
pub(crate) fn disable_with_daemon_state(daemon_running: bool) -> Result<String, String> {
    let mut msg = disable()?;
    if daemon_running {
        msg.push_str(&daemon_restart_note());
    }
    Ok(msg)
}

/// Note for when the daemon IS already running: the MITM listener is read
/// only at boot and there is no control endpoint to change it at runtime.
#[must_use]
fn daemon_restart_note() -> String {
    format!(
        "\nNOTICE: the current daemon is running and does NOT apply MITM changes at runtime.\n  Edit {} and restart: cerberus stop && cerberus start",
        config_path().display()
    )
}

/// Safe summary: never prints key contents nor sets up trust.
#[must_use]
pub(crate) fn status() -> String {
    let path = config_path();
    let config = match load_config_from(&path) {
        Ok(config) => config,
        Err(error) => return format!("MITM: invalid config ({error})"),
    };
    let ca = match validate_ca_files(&ca_paths()) {
        Ok(()) => "ready (not automatically trusted)".to_string(),
        Err(error) => format!("not ready ({error})"),
    };
    format!(
        "MITM: {} | listen={} | hosts=[{}] | CA={ca}",
        if config.enabled {
            "enabled (opt-in)"
        } else {
            "disabled (default)"
        },
        config.listen,
        config.hosts.join(", ")
    )
}

fn load_config_from(path: &Path) -> Result<MitmConfig, String> {
    if !path.exists() {
        return Ok(MitmConfig::default());
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect MITM config: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("MITM config must be a regular file, not a symlink".to_string());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("cannot read MITM config: {e}"))?;
    let mut config: MitmConfig = serde_json::from_str(&raw).map_err(|e| format!("invalid MITM config: {e}"))?;
    // An explicitly disabled file cannot prevent the reverse proxy from
    // booting. Its inert fields are sanitized only for status/editing.
    if !config.enabled {
        config.hosts = normalize_allowed_hosts(&config.hosts).unwrap_or_default();
        config.listen = config
            .listen
            .parse::<SocketAddr>()
            .ok()
            .filter(|listen| listen.ip().is_loopback() && listen.port() != 0)
            .map_or_else(|| DEFAULT_MITM_LISTEN.to_string(), |listen| listen.to_string());
        return Ok(config);
    }
    config.hosts = normalize_allowed_hosts(&config.hosts)?;
    let listen: SocketAddr = config
        .listen
        .parse()
        .map_err(|_| "invalid MITM listen address".to_string())?;
    if !listen.ip().is_loopback() || listen.port() == 0 {
        return Err("MITM listen must be a non-zero loopback address".to_string());
    }
    config.listen = listen.to_string();
    Ok(config)
}

fn save_config_to(path: &Path, config: &MitmConfig) -> Result<(), String> {
    let parent = path.parent().ok_or("MITM config path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create config directory: {e}"))?;
    let temp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let raw = serde_json::to_vec_pretty(config).map_err(|e| format!("cannot serialize MITM config: {e}"))?;
    let mut file = create_private_file(&temp)?;
    if let Err(error) = file.write_all(&raw).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(format!("cannot write MITM config: {error}"));
    }
    drop(file);
    if let Err(first) = fs::rename(&temp, path) {
        if path.exists() {
            fs::remove_file(path).map_err(|e| format!("cannot replace MITM config: {e}"))?;
            fs::rename(&temp, path).map_err(|e| format!("cannot publish MITM config: {e}"))?;
        } else {
            let _ = fs::remove_file(&temp);
            return Err(format!("cannot publish MITM config: {first}"));
        }
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| format!("cannot create MITM config temp file: {e}"))
}

/// Only returns instructions: it does not run `sudo`, `security`, `certutil`
/// nor modifies trust stores.
#[must_use]
pub(crate) fn trust_instructions() -> String {
    let cert = ca_cert_path();
    #[cfg(target_os = "macos")]
    return format!(
        "Optional manual action to trust on macOS:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
        cert.display()
    );
    #[cfg(target_os = "linux")]
    return format!(
        "Optional manual action to trust on Linux:\n  sudo cp {} /usr/local/share/ca-certificates/cerberus-ca.crt\n  sudo update-ca-certificates",
        cert.display()
    );
    #[cfg(target_os = "windows")]
    return format!(
        "Optional manual action to trust on Windows (elevated PowerShell):\n  certutil -addstore Root \"{}\"",
        cert.display()
    );
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    format!("Manually trust {} only if you accept the MITM risk.", cert.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_config_is_disabled_and_does_not_create_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mitm.json");
        assert_eq!(load_config_from(&path).unwrap(), MitmConfig::default());
        assert!(
            runtime_config_from(
                &path,
                CaPaths {
                    cert: temp.path().join("missing.cert"),
                    key: temp.path().join("missing.key"),
                }
            )
            .unwrap()
            .is_none(),
            "default reverse mode must not require or create a CA"
        );
        assert!(!path.exists());
    }

    #[test]
    fn disabled_invalid_fields_cannot_block_reverse_default() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mitm.json");
        fs::write(&path, r#"{"enabled":false,"listen":"0.0.0.0:1","hosts":["*"]}"#).unwrap();
        let loaded = load_config_from(&path).unwrap();
        assert!(!loaded.enabled);
        assert_eq!(loaded.listen, DEFAULT_MITM_LISTEN);
        assert!(loaded.hosts.is_empty());
    }

    #[test]
    fn config_round_trip_preserves_explicit_hosts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mitm.json");
        let config = MitmConfig {
            enabled: true,
            listen: "127.0.0.1:9443".to_string(),
            hosts: vec!["api.openai.com".to_string(), "api.anthropic.com".to_string()],
        };
        save_config_to(&path, &config).unwrap();
        assert_eq!(load_config_from(&path).unwrap(), config);
    }

    #[test]
    fn enabled_config_rejects_empty_hosts_and_public_bind() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mitm.json");
        fs::write(&path, r#"{"enabled":true,"listen":"127.0.0.1:8788","hosts":[]}"#).unwrap();
        assert!(load_config_from(&path).is_err());
        fs::write(
            &path,
            r#"{"enabled":true,"listen":"0.0.0.0:8788","hosts":["api.openai.com"]}"#,
        )
        .unwrap();
        assert!(load_config_from(&path).is_err());
    }

    #[test]
    fn trust_help_is_instructions_only() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let instructions = trust_instructions();
        assert!(instructions.contains("manual"));
        assert!(instructions.contains(&ca_cert_path().display().to_string()));
    }

    // ─── F4: MITM connected to the daemon ──────────────────────────────────────

    /// Serializes tests that mutate `HOME` (process-global).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Isolated HOME to test the flow against a real user config.
    fn temp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-mitm-daemon-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        // Create both the unix config dir (.cerberus) and the Windows config
        // dir (Cerberus) so config_dir() resolves correctly on either platform.
        std::fs::create_dir_all(dir.join(".cerberus")).expect("create home");
        std::fs::create_dir_all(dir.join("Cerberus")).expect("create home (windows)");
        dir
    }

    #[test]
    fn enable_without_daemon_persists_for_next_start() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("off");
        let prev_home = std::env::var("HOME").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("APPDATA", &home);
        let dir_error = enable_with_daemon_state(&["api.openai.com".to_string()], "127.0.0.1:8788", false)
            .expect_err("missing CA must fail BEFORE touching config");
        assert!(dir_error.contains("CA not ready"), "{dir_error}");

        init_ca().expect("init CA in isolated HOME");
        let msg = enable_with_daemon_state(&["api.openai.com".to_string()], "127.0.0.1:8788", false)
            .expect("enable without daemon");
        assert!(msg.contains("Config persisted"), "{msg}");
        assert!(
            !msg.contains("NOTICE"),
            "without daemon must not warn about restart: {msg}"
        );
        let saved = load_config_from(&config_path()).expect("config written");
        assert!(saved.enabled);
        assert_eq!(saved.hosts, vec!["api.openai.com".to_string()]);
        assert!(saved.listen.contains("8788"));

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

    #[test]
    fn strict_ca_material_is_rejected_by_status_enable_and_daemon_runtime() {
        use std::io::Write as _;

        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("strict-ca");
        let prev_home = std::env::var("HOME").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("APPDATA", &home);
        init_ca().expect("init CA");
        std::fs::OpenOptions::new()
            .append(true)
            .open(ca_cert_path())
            .unwrap()
            .write_all(b"\nTRAILING-NON-PEM\n")
            .unwrap();

        let status_text = status();
        assert!(status_text.contains("not ready"), "{status_text}");
        let enable_error = enable(&["api.openai.com".to_string()], "127.0.0.1:8788").unwrap_err();
        assert!(enable_error.contains("CA not ready"), "{enable_error}");

        let enabled = MitmConfig {
            enabled: true,
            listen: "127.0.0.1:8788".to_string(),
            hosts: vec!["api.openai.com".to_string()],
        };
        save_config_to(&config_path(), &enabled).unwrap();
        assert!(
            runtime_config_from(&config_path(), ca_paths()).is_err(),
            "daemon runtime must reject invalid CA material before listener bind"
        );

        match prev_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        match prev_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn enable_with_running_daemon_warns_restart_and_persists() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = temp_home("on");
        let prev_home = std::env::var("HOME").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("APPDATA", &home);
        init_ca().expect("init CA");

        // "Daemon running": pid file with the current live process.
        crate::daemon::config_dir();
        std::fs::write(
            crate::daemon::config_dir().join("cerberus.pid"),
            std::process::id().to_string(),
        )
        .expect("write pid");

        if crate::daemon::is_running() {
            let msg = enable_with_daemon_state(&["api.openai.com".to_string()], "127.0.0.1:8788", true)
                .expect("enable with daemon");
            assert!(msg.contains("NOTICE"), "must warn about restart: {msg}");
            assert!(msg.contains("cerberus stop && cerberus start"), "{msg}");
            let saved = load_config_from(&config_path()).expect("config");
            assert!(saved.enabled, "the config is persisted for the next boot");
        }

        // `disable` with daemon also carries the restart note.
        if crate::daemon::is_running() {
            let msg = disable_with_daemon_state(true).expect("disable with daemon");
            assert!(msg.contains("NOTICE"), "{msg}");
            let saved = load_config_from(&config_path()).expect("config");
            assert!(!saved.enabled);
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
}
