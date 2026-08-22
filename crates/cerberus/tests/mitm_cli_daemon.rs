//! Integration test: `cerberus mitm` as the forward proxy mode CLI (F4).
//!
//! Checks the observable behavior of the command (exit code + message):
//!   1. `mitm status` with no config → disabled (default), exit 0.
//!   2. `mitm enable` without CA → fails with instructions (`init-ca`), exit != 0.
//!   3. `mitm init-ca` → exit 0 and local CA generated.
//!   4. `mitm enable` (daemon stopped) → as config for the next boot,
//!      announces the persisted path and does NOT warn about restart, exit 0.
//!   5. `mitm enable` with daemon "running" (pid file + live process) → persists
//!      the config AND adds the clear restart note (`cerberus stop && start`).
//!   6. `mitm disable` → exit 0 and `enabled=false` in mitm.json.
//!
//! The "daemon running" is simulated the same way as `pack_cli_via_api.rs`: a
//! pid file with the PID of this live process → `daemon::is_running()` = true.

use std::path::PathBuf;
use std::process::Command;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
}

fn temp_dir(prefix: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cerberus_mitm_cli_{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).expect("create tmp dir");
    d
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], home: &std::path::Path) -> Run {
    let out = Command::new(binary())
        .args(args)
        .env("HOME", home)
        .output()
        .expect("run cerberus");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Simulate the daemon "running": pid file with the PID of this LIVE process.
fn fake_running_daemon(home: &std::path::Path) {
    std::fs::create_dir_all(home.join(".cerberus")).expect("create .cerberus");
    std::fs::write(
        home.join(".cerberus").join("cerberus.pid"),
        std::process::id().to_string(),
    )
    .expect("write pid");
}

#[test]
fn mitm_status_reports_disabled_by_default() {
    let dir = temp_dir("status");
    let r = run(&["mitm", "status"], &dir);
    assert_eq!(r.status, 0, "stderr: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(r.stdout.contains("MITM:"), "stdout: {}", r.stdout);
    assert!(r.stdout.contains("disabled (default)"), "stdout: {}", r.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mitm_enable_without_ca_fails_with_instructions() {
    let dir = temp_dir("noca");
    let r = run(&["mitm", "enable", "--host", "api.openai.com"], &dir);
    assert_ne!(r.status, 0, "without CA it must fail");
    assert!(r.stderr.contains("CA not ready"), "stderr: {}", r.stderr);
    assert!(
        r.stderr.contains("mitm init-ca"),
        "must point to init-ca: {}",
        r.stderr
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mitm_init_ca_then_enable_without_daemon() {
    let dir = temp_dir("off");
    assert_eq!(run(&["mitm", "init-ca"], &dir).status, 0, "init-ca fails");
    assert!(
        dir.join(".cerberus").join("ca").join("cerberus-ca.cert").exists(),
        "init-ca must generate the certificate"
    );

    let r = run(&["mitm", "enable", "--host", "api.openai.com"], &dir);
    assert_eq!(r.status, 0, "enable without daemon: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(r.stdout.contains("Config persisted"), "stdout: {}", r.stdout);
    assert!(
        !r.stdout.contains("NOTICE"),
        "without daemon there is no restart note: {}",
        r.stdout
    );

    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".cerberus").join("mitm.json")).expect("mitm.json"))
            .expect("mitm.json is valid JSON");
    assert_eq!(config["enabled"], true, "config must remain enabled");

    let r = run(&["mitm", "disable"], &dir);
    assert_eq!(r.status, 0, "disable: {}", r.stderr);
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".cerberus").join("mitm.json")).expect("mitm.json"))
            .expect("mitm.json");
    assert_eq!(config["enabled"], false, "config must remain disabled");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mitm_enable_with_running_daemon_warns_restart() {
    let dir = temp_dir("on");
    assert_eq!(run(&["mitm", "init-ca"], &dir).status, 0, "init-ca");
    fake_running_daemon(&dir);

    let r = run(&["mitm", "enable", "--host", "api.anthropic.com"], &dir);
    assert_eq!(r.status, 0, "enable with daemon: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(r.stdout.contains("NOTICE"), "must warn about restart: {}", r.stdout);
    assert!(
        r.stdout.contains("cerberus stop && cerberus start"),
        "must give the restart command: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("mitm.json"),
        "must cite the config to edit: {}",
        r.stdout
    );

    // The config is persisted anyway for the next boot.
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".cerberus").join("mitm.json")).expect("mitm.json"))
            .expect("mitm.json");
    assert_eq!(config["enabled"], true);

    std::fs::remove_dir_all(&dir).ok();
}
