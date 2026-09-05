//! F6.B — Appendix B CLI commands as CLIENTS of the control plane.
//!
//! Same deterministic strategy as `pack_cli_via_api.rs` (no real daemon):
//!
//! 1. a mini control plane (mock HTTP TCP) records the raw request and
//!    answers `{"status":"ok",...}`;
//! 2. `~/.cerberus/config.yaml` points the CLI at the mock and
//!    `~/.cerberus/cerberus.pid` holds THIS process's pid, so the CLI
//!    resolves a "running daemon";
//! 3. each new Appendix B command runs through the REAL binary
//!    (`CARGO_BIN_EXE_cerberus`) and the test asserts (a) the endpoint
//!    called, (b) the admin token attached, (c) the body contract.
//!
//! These tests are the CLI→API legs of `evidence/f6/parity-matrix.md`;
//! the CLI→route-table walk lives in `main.rs` (`cli_tests`) and the
//! API-side behavior in `crates/cerberus-proxy/tests/f6b_api_surface.rs`.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
}

/// Token ≥ 24 bytes (the control plane requires at least 24, review v4 #1).
const ADMIN_TOKEN: &str = "cerberus-cli-surface-test-token-0123456789";

fn config_subdir(home: &std::path::Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        home.join("Cerberus")
    }
    #[cfg(not(target_os = "windows"))]
    {
        home.join(".cerberus")
    }
}

/// Build a `cerberus` subprocess with HOME (and APPDATA on Windows) set to
/// `home` so that `config_dir()` resolves to the isolated temp directory.
fn cerberus_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.env("HOME", home);
    #[cfg(target_os = "windows")]
    cmd.env("APPDATA", home);
    cmd
}

fn temp_dir(prefix: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cerberus_surface_{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).expect("create tmp dir");
    std::fs::create_dir_all(config_subdir(&d)).expect("create cfg dir");
    d.canonicalize().unwrap_or(d)
}

/// Wire the isolated HOME so the CLI resolves a "running daemon" whose
/// control plane is the mock: config.yaml → mock listen + token; pid file →
/// this live process.
fn install_mock_home(home: &std::path::Path, addr: SocketAddr) {
    std::fs::write(
        config_subdir(home).join("config.yaml"),
        format!("listen: {addr}\nadmin_token: {ADMIN_TOKEN}\n"),
    )
    .expect("write config.yaml");
    std::fs::write(config_subdir(home).join("cerberus.pid"), std::process::id().to_string()).expect("write pid");
}

/// Run `cerberus <args>` against the mock home; asserts exit 0 and returns
/// (stdout, stderr, recorded hits).
fn run_cli(home: &std::path::Path, hits: &Arc<Mutex<Vec<String>>>, args: &[&str]) -> (String, String, String) {
    let out = cerberus_cmd(home)
        .args(args)
        .env("CERBERUS_ADMIN_TOKEN", ADMIN_TOKEN)
        .output()
        .unwrap_or_else(|e| panic!("run cerberus {args:?}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "cerberus {args:?} must exit OK — stderr: {stderr}\nstdout: {stdout}"
    );
    let recv = hits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("\n");
    (stdout, stderr, recv)
}

/// Mini control plane: records every raw request; answers `{"status":"ok",`
/// `"message":"mock-ok","fingerprint":"hmac:<64x>","nonce":"n-1",`
/// `"ttl_secs":300,"scope":"global","mode":"enforce"}` style bodies.
fn spawn_mock_control_plane() -> (SocketAddr, std::thread::JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
    let hits_thread = hits.clone();
    let handle = std::thread::Builder::new()
        .name("cerberus-surface-mock".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("mock runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("bind mock control plane");
                let addr = listener.local_addr().expect("addr");
                addr_tx.send(addr).ok();
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        break;
                    };
                    let h = hits_thread.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16384];
                        let _ = sock.read(&mut buf).await;
                        let raw = String::from_utf8_lossy(&buf).to_string();
                        // Reply with a generic success envelope that every
                        // CLI command can parse (config-view responses get
                        // the JSON fields they read, tolerantly).
                        let body = if raw.contains("/api/policy") {
                            r#"{"status":"ok","categories":{},"rules":{},"custom_rules":[],"allowlist":[],"effective_rules":[{"flag":"secret.openai_api_key","category":"secrets","action":"block"}],"engine_rules":14}"#
                        } else if raw.contains("/api/allowlist") {
                            r#"{"status":"ok","fingerprint":"hmac:0000000000000000000000000000000000000000000000000000000000000000"}"#
                        } else if raw.contains("/api/break-glass") {
                            r#"{"status":"ok","nonce":"n-123","reason_hash":"h:1","scope":"global","ttl_secs":300,"expires_at_nanos":1}"#
                        } else if raw.contains("/api/upstreams") {
                            r#"{"status":"ok","message":"mock-ok"}"#
                        } else if raw.contains("/api/packs") {
                            r#"{"status":"ok","message":"packs mock-ok"}"#
                        } else {
                            r#"{"status":"ok","message":"mock-ok","mode":"enforce"}"#
                        };
                        h.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(raw);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });
        })
        .expect("cannot spawn mock control plane");
    let addr = addr_rx.recv().expect("control plane addr");
    (addr, handle, hits)
}

/// ── B.1: mode → PUT /api/config ──────────────────────────────────────────
#[test]
fn cli_mode_shadow_puts_the_config() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("mode");
    install_mock_home(&home, addr);
    let (stdout, _, recv) = run_cli(&home, &hits, &["mode", "shadow"]);
    assert!(stdout.contains("mode:"), "mode reports the live value: {stdout}");
    assert!(recv.contains("PUT /api/config"), "mode must PUT the config: {recv}");
    assert!(recv.contains("\"mode\":\"shadow\""), "mode body: {recv}");
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── B.1: allow-once → POST /api/break-glass ──────────────────────────────
#[test]
fn cli_allow_once_posts_break_glass() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("allow-once");
    install_mock_home(&home, addr);
    let (stdout, _, recv) = run_cli(&home, &hits, &["allow-once", "--reason", "vendor demo"]);
    assert!(stdout.contains("break-glass"), "{stdout}");
    assert!(recv.contains("POST /api/break-glass"), "break-glass endpoint: {recv}");
    assert!(recv.contains("vendor demo"), "the reason travels for hashing: {recv}");
    assert!(recv.contains(ADMIN_TOKEN), "token attached: {recv}");
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── F2 (r9-remediation): the allow-once output must pin the EXACT
/// redeemable header (`break-glass:` prefix — the data plane redeems ONLY
/// that prefix via the ledger, proxy.rs:89) AND say that the
/// `X-Cerberus-Admin-Token` header is required. The legacy bare-nonce form
/// (replayable Legacy arm) must never be printed.
#[test]
fn cli_allow_once_prints_exact_break_glass_header_and_admin_note() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("allow-once-f2");
    install_mock_home(&home, addr);
    let (stdout, _, _) = run_cli(&home, &hits, &["allow-once", "--reason", "f2 header pin"]);
    assert!(
        stdout.contains("X-Cerberus-Bypass: break-glass:n-123"),
        "printed header must be the redeemable break-glass form: {stdout}"
    );
    assert!(
        stdout.contains("X-Cerberus-Admin-Token"),
        "the admin-token requirement must be explicit: {stdout}"
    );
    assert!(
        !stdout.contains("X-Cerberus-Bypass: n-123"),
        "legacy bare nonce must NOT be printed: {stdout}"
    );
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── B.2: providers / add-provider / remove-provider → /api/upstreams ────
#[test]
fn cli_provider_crud_hits_upstreams_routes() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("providers");
    install_mock_home(&home, addr);

    let (stdout, _, _) = run_cli(
        &home,
        &hits,
        &[
            "add-provider",
            "nanbuilders",
            "--url",
            "https://api.nan.builders/v1",
            "--auth-header",
            "x-api-key",
        ],
    );
    assert!(stdout.contains("nanbuilders"), "{stdout}");

    let (_, _, recv) = run_cli(&home, &hits, &["providers"]);
    assert!(recv.contains("GET /api/upstreams"), "providers lists: {recv}");

    let (_, _, recv) = run_cli(&home, &hits, &["remove-provider", "nanbuilders"]);
    assert!(
        recv.contains("DELETE /api/upstreams/nanbuilders"),
        "remove-provider deletes by name: {recv}"
    );

    // add-provider's POST carried the body contract (Appendix C).
    let recv = hits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("\n");
    assert!(recv.contains("POST /api/upstreams"), "add-provider posts: {recv}");
    assert!(recv.contains("nanbuilders"), "name in body: {recv}");
    assert!(recv.contains("x-api-key"), "auth_header in body: {recv}");

    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── B.3: packs enable/disable/update → /api/packs/* ─────────────────────
#[test]
fn cli_packs_enable_disable_update_hit_pack_routes() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("packs-b3");
    install_mock_home(&home, addr);

    let (stdout, _, _) = run_cli(&home, &hits, &["packs", "enable", "aws"]);
    assert!(stdout.contains("mock-ok"), "{stdout}");
    let (stdout, _, _) = run_cli(&home, &hits, &["packs", "disable", "aws"]);
    assert!(stdout.contains("mock-ok"), "{stdout}");
    let (_, _, _) = run_cli(&home, &hits, &["packs", "update"]);

    let recv = hits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("\n");
    assert!(recv.contains("POST /api/packs/enable"), "{recv}");
    assert!(recv.contains("POST /api/packs/disable"), "{recv}");
    assert!(recv.contains("POST /api/packs/update"), "{recv}");
    assert!(
        recv.contains("\"name\":\"aws\"") || recv.contains("\"name\": \"aws\""),
        "{recv}"
    );
    assert!(recv.contains(ADMIN_TOKEN), "token on pack ops: {recv}");
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── B.3: category set / rules set → PUT /api/policy ─────────────────────
#[test]
fn cli_category_and_rules_set_hit_the_policy_route() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("policy-b3");
    install_mock_home(&home, addr);

    let (stdout, _, _) = run_cli(&home, &hits, &["category", "set", "secrets", "--action", "block"]);
    assert!(stdout.contains("secrets"), "{stdout}");
    let (stdout, _, _) = run_cli(
        &home,
        &hits,
        &["rules", "set", "secret.openai_api_key", "--action", "redact"],
    );
    assert!(stdout.contains("secret.openai_api_key"), "{stdout}");
    let (stdout, _, _) = run_cli(&home, &hits, &["rules", "list"]);
    assert!(
        stdout.contains("secret.openai_api_key"),
        "rules list shows effective: {stdout}"
    );

    let recv = hits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("\n");
    assert!(recv.contains("PUT /api/policy"), "{recv}");
    assert!(recv.contains("\"categories\""), "{recv}");
    assert!(recv.contains("\"rules\""), "{recv}");
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── B.3: allowlist add/list/remove → /api/allowlist (fingerprints only) ─
#[test]
fn cli_allowlist_hits_the_allowlist_routes() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("allowlist-b3");
    install_mock_home(&home, addr);

    let (stdout, _, _) = run_cli(&home, &hits, &["allowlist", "add", "sk-EXAMPLE-value"]);
    assert!(stdout.contains("hmac:"), "fingerprint shown: {stdout}");
    assert!(
        !stdout.contains("sk-EXAMPLE-value"),
        "the raw value is NEVER echoed: {stdout}"
    );
    let (_, _, _) = run_cli(&home, &hits, &["allowlist", "list"]);
    let (_, _, _) = run_cli(&home, &hits, &["allowlist", "remove", "sk-EXAMPLE-value"]);

    let recv = hits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("\n");
    assert!(recv.contains("POST /api/allowlist"), "{recv}");
    assert!(recv.contains("GET /api/allowlist"), "{recv}");
    assert!(recv.contains("DELETE /api/allowlist"), "{recv}");
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── B.5: events (filters) / stats (--by) / reload ────────────────────────
#[test]
fn cli_events_stats_reload_hit_their_routes() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("b5");
    install_mock_home(&home, addr);

    let (_, _, _) = run_cli(
        &home,
        &hits,
        &["events", "--provider", "openai", "--tool", "codex", "--since", "30m"],
    );
    let (_, _, _) = run_cli(&home, &hits, &["stats", "--by", "provider"]);
    let (stdout, _, _) = run_cli(&home, &hits, &["reload"]);
    assert!(stdout.contains("reloaded") || stdout.contains("mock-ok"), "{stdout}");

    let recv = hits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("\n");
    assert!(
        recv.contains("GET /api/events?provider=openai&tool=codex&since="),
        "{recv}"
    );
    assert!(recv.contains("GET /api/stats"), "{recv}");
    assert!(recv.contains("POST /api/reload"), "{recv}");
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── Unreachable daemon → clear, actionable error (hard rule) ────────────
#[test]
fn cli_reports_a_clear_error_when_the_daemon_is_unreachable() {
    let home = temp_dir("unreachable");
    // NO pid file, NO endpoint descriptor: the CLI dials 127.0.0.1:8787,
    // where nothing listens (we cannot bind-guard the default port, so we
    // point the config at a dead port instead).
    std::fs::write(
        config_subdir(&home).join("config.yaml"),
        format!("listen: 127.0.0.1:9\nadmin_token: {ADMIN_TOKEN}\n"),
    )
    .expect("write config");
    let out = cerberus_cmd(&home)
        .args(["providers"])
        .env("CERBERUS_ADMIN_TOKEN", ADMIN_TOKEN)
        .output()
        .expect("run");
    assert_ne!(out.status.code(), Some(0), "unreachable daemon must fail the command");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot reach the Cerberus daemon") && stderr.contains("127.0.0.1:9"),
        "actionable error: {stderr}"
    );
    assert!(
        stderr.contains("cerberus start"),
        "error must suggest the fix: {stderr}"
    );
    std::fs::remove_dir_all(&home).ok();
}

/// ── B.2: agents wire/unwire are LOCAL (no daemon) and print the export ──
#[test]
fn cli_agents_wire_works_without_a_daemon() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("agents-e2e");
    install_mock_home(&home, addr);

    // agents wire succeeds even though the "daemon" is a mock that would
    // reject nothing — but the command must NOT touch the control plane.
    let hits_before = hits.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    let (stdout, _, recv) = run_cli(&home, &hits, &["agents", "wire", "opencode"]);
    assert!(stdout.contains("OPENCODE_BASE_URL"), "{stdout}");
    let hits_after = hits.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    assert_eq!(
        hits_before, hits_after,
        "agents wire is local — no control-plane call: {recv}"
    );

    // The wire state persisted where `cerberus agents` lists it.
    let out = cerberus_cmd(&home).args(["agents"]).output().expect("agents");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("wired → cerberus"), "{stdout}");

    let (stdout, _, _) = run_cli(&home, &hits, &["agents", "unwire", "opencode"]);
    assert!(stdout.contains("unset OPENCODE_BASE_URL"), "{stdout}");
    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}
/// ── B.1/B.3/B.5/B.6/B.7: the remaining local + daemon-backed commands ───
#[test]
fn cli_status_packs_list_and_rules_add_hit_expected_routes() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let home = temp_dir("misc-e2e");
    install_mock_home(&home, addr);

    // status consults /api/config (when reachable) for live detail.
    let (stdout, _, recv) = run_cli(&home, &hits, &["status"]);
    assert!(stdout.contains("Cerberus:"), "{stdout}");
    assert!(recv.contains("GET /api/config"), "status detail: {recv}");

    // packs list shares the pack-list path.
    let (_, _, recv) = run_cli(&home, &hits, &["packs", "list"]);
    assert!(recv.contains("/api/packs") || recv.is_empty(), "packs list: {recv}");

    // rules add: a locally-compiled rule travels as a custom_rules
    // full-replacement PUT (hot-reload).
    let rule_file = home.join("rule.yaml");
    std::fs::write(
        &rule_file,
        "flag: custom.badge_id\ncategory: internal_code\nseverity: low\npatterns:\n  - \"BADGE-[0-9]{4}\"\n",
    )
    .expect("write rule");
    let (stdout, _, _) = run_cli(&home, &hits, &["rules", "add", "--file", &rule_file.to_string_lossy()]);
    assert!(stdout.contains("custom.badge_id"), "{stdout}");
    let recv = hits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("\n");
    assert!(recv.contains("PUT /api/policy"), "rules add PUTs the policy: {recv}");
    assert!(recv.contains("custom.badge_id"), "the rule travels in the body: {recv}");

    std::fs::remove_dir_all(&home).ok();
    drop(handle);
}

/// ── B.5/B.6: logs, config show/edit/path, validate — local commands ─────
#[test]
fn cli_local_commands_work_without_a_daemon() {
    let home = temp_dir("local-e2e");
    std::fs::write(
        config_subdir(&home).join("config.yaml"),
        format!("listen: 127.0.0.1:8787\nmode: enforce\nfail_policy: closed\nadmin_token: {ADMIN_TOKEN}\nupstreams:\n  openai:\n    url: https://api.openai.com\n"),
    )
    .expect("write config");

    // config show redacts the token.
    let out = cerberus_cmd(&home)
        .args(["config", "show"])
        .output()
        .expect("config show");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(!stdout.contains(ADMIN_TOKEN), "token must be redacted: {stdout}");
    assert!(stdout.contains("***redacted***"), "{stdout}");

    // config path prints the location.
    let out = cerberus_cmd(&home)
        .args(["config", "path"])
        .output()
        .expect("config path");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim().ends_with("config.yaml"), "{stdout}");

    // validate accepts the good config.
    let out = cerberus_cmd(&home)
        .args([
            "validate",
            "-f",
            &config_subdir(&home).join("config.yaml").to_string_lossy(),
        ])
        .output()
        .expect("validate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("VALID"), "{stdout}");

    // config edit with EDITOR=true (no-op editor) → validates fine.
    let out = cerberus_cmd(&home)
        .args(["config", "edit"])
        .env("EDITOR", "true")
        .output()
        .expect("config edit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("valid"), "{stdout}");

    // logs: a daemon log file is readable; content is printed verbatim.
    let logs_dir = config_subdir(&home).join("logs");
    std::fs::create_dir_all(&logs_dir).expect("mkdir logs");
    std::fs::write(
        logs_dir.join("cerberus.log"),
        "2026-09-02T00:00:00Z INFO request blocked by Cerberus flags=[secret.openai_api_key]\n",
    )
    .expect("write log");
    let out = cerberus_cmd(&home).args(["logs"]).output().expect("logs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("request blocked by Cerberus"), "{stdout}");

    std::fs::remove_dir_all(&home).ok();
}
