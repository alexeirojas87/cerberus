//! Integration test: `cerberus mitm` como CLI del modo forward proxy (F4).
//!
//! Comprueba el comportamiento observable del comando (exit code + mensaje):
//!   1. `mitm status` sin ninguna config → disabled (default), exit 0.
//!   2. `mitm enable` sin CA → falla con instrucciones (`init-ca`), exit != 0.
//!   3. `mitm init-ca` → exit 0 y CA local generada.
//!   4. `mitm enable` (daemon parado) → como config para el siguiente arranque,
//!      anuncia la ruta persistida y NO avisa de reinicio, exit 0.
//!   5. `mitm enable` con daemon "en marcha" (pid file + proceso vivo) → persiste
//!      la config Y añade la nota clara de reinicio (`cerberus stop && start`).
//!   6. `mitm disable` → exit 0 y `enabled=false` en mitm.json.
//!
//! El "daemon en marcha" se simula igual que `pack_cli_via_api.rs`: un pid file
//! con el PID de este proceso vivo → `daemon::is_running()` = true.

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

/// Simular el daemon "en marcha": pid file con el PID de este proceso VIVO.
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
    assert_ne!(r.status, 0, "sin CA debe fallar");
    assert!(r.stderr.contains("CA not ready"), "stderr: {}", r.stderr);
    assert!(
        r.stderr.contains("mitm init-ca"),
        "debe apuntar a init-ca: {}",
        r.stderr
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mitm_init_ca_then_enable_without_daemon() {
    let dir = temp_dir("off");
    assert_eq!(run(&["mitm", "init-ca"], &dir).status, 0, "init-ca falla");
    assert!(
        dir.join(".cerberus").join("ca").join("cerberus-ca.cert").exists(),
        "init-ca debe generar el certificado"
    );

    let r = run(&["mitm", "enable", "--host", "api.openai.com"], &dir);
    assert_eq!(r.status, 0, "enable sin daemon: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(r.stdout.contains("Config persistida"), "stdout: {}", r.stdout);
    assert!(
        !r.stdout.contains("AVISO"),
        "sin daemon no hay nota de reinicio: {}",
        r.stdout
    );

    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".cerberus").join("mitm.json")).expect("mitm.json"))
            .expect("mitm.json es JSON válido");
    assert_eq!(config["enabled"], true, "config debe quedar habilitada");

    let r = run(&["mitm", "disable"], &dir);
    assert_eq!(r.status, 0, "disable: {}", r.stderr);
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".cerberus").join("mitm.json")).expect("mitm.json"))
            .expect("mitm.json");
    assert_eq!(config["enabled"], false, "config debe quedar deshabilitado");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mitm_enable_with_running_daemon_warns_restart() {
    let dir = temp_dir("on");
    assert_eq!(run(&["mitm", "init-ca"], &dir).status, 0, "init-ca");
    fake_running_daemon(&dir);

    let r = run(&["mitm", "enable", "--host", "api.anthropic.com"], &dir);
    assert_eq!(r.status, 0, "enable con daemon: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(r.stdout.contains("AVISO"), "debe advertir del reinicio: {}", r.stdout);
    assert!(
        r.stdout.contains("cerberus stop && cerberus start"),
        "debe dar el comando de reinicio: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("mitm.json"),
        "debe citar la config a editar: {}",
        r.stdout
    );

    // La config se persiste igualmente para el próximo arranque.
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".cerberus").join("mitm.json")).expect("mitm.json"))
            .expect("mitm.json");
    assert_eq!(config["enabled"], true);

    std::fs::remove_dir_all(&dir).ok();
}
