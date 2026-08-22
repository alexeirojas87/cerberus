//! Integration test: `cerberus pack` as a CLIENT of the control plane (reviewer v6).
//!
//! Reviewer v6 (P1): when the daemon is running, the CLI does NOT open another
//! `PackManager` nor modify disk — it invokes `/api/packs/*` of the control
//! plane. The daemon (its worker) is the ONLY writer of the manifest at runtime.
//!
//! Deterministic strategy (no real daemon):
//!   1. a mini control plane (mock HTTP TCP) is spun up in its own thread
//!      that records the raw request and responds `{"status":"ok",...}`;
//!   2. `~/.cerberus/config.yaml` is written with `listen` pointing to the mock
//!      and `~/.cerberus/cerberus.pid` with the PID of this LIVE process → the
//!      CLI deduces that the daemon "is running" and decides to go over HTTP;
//!   3. `cerberus pack install <f>` is launched and it is checked that (a) the
//!      CLI calls the API (the mock records it) and (b) does NOT create a
//!      manifest on disk (does not touch `.cerberus/packs`).
//!   4. Without a pid file → fallback to local mode (single process).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
}

/// Token ≥ 24 bytes (the control plane requires at least 24, review v4 #1).
const ADMIN_TOKEN: &str = "cerberus-cli-control-plane-test-token-0123";

/// Success response from the mock control plane.
const MOCK_RESPONSE: &str = r#"{"status":"ok","message":"installed via control plane API"}"#;

fn temp_dir(prefix: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cerberus_{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).expect("create tmp dir");
    d.canonicalize().unwrap_or(d)
}

/// Mini daemon control plane in its own thread (with its own tokio runtime).
/// Records the raw request in `hits` and responds
/// `{"status":"ok","message":"installed via control plane API"}`.
fn spawn_mock_control_plane() -> (
    SocketAddr,
    std::thread::JoinHandle<()>,
    Arc<std::sync::Mutex<Vec<String>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let hits: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
    let hits_thread = hits.clone();
    let handle = std::thread::Builder::new()
        .name("cerberus-pack-mock-control-plane".to_string())
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
                        h.lock().unwrap().push(String::from_utf8_lossy(&buf).to_string());
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{MOCK_RESPONSE}",
                            MOCK_RESPONSE.len()
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

#[test]
fn cli_pack_uses_control_plane_when_daemon_running() {
    let (addr, handle, hits) = spawn_mock_control_plane();

    let dir = temp_dir("pack_cli_api");
    let cfg_dir = dir.join(".cerberus");
    std::fs::create_dir_all(&cfg_dir).expect("create .cerberus");

    // The control plane points to the mock and the pid to a live process.
    std::fs::write(
        cfg_dir.join("config.yaml"),
        format!("listen: {addr}\nadmin_token: {ADMIN_TOKEN}\n"),
    )
    .expect("write config.yaml");
    std::fs::write(cfg_dir.join("cerberus.pid"), std::process::id().to_string()).expect("write pid");

    // v6.1: the CLI reads the pack and sends its BYTES (never the path). The
    // pack lives in a subdirectory with a space to prove that the path does
    // not travel.
    let pack_dir = dir.join("packs origin");
    std::fs::create_dir_all(&pack_dir).expect("create pack dir");
    let pack_file = pack_dir.join("wire-demo.json");
    std::fs::write(&pack_file, sample_signed_pack()).expect("write signed pack");

    let out = Command::new(binary())
        .arg("pack")
        .arg("install")
        .arg(&pack_file)
        .env("HOME", &dir)
        .env("CERBERUS_ADMIN_TOKEN", ADMIN_TOKEN)
        .output()
        .expect("run cerberus pack install via control plane");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the CLI must exit OK via the API — stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("installed via control plane API"),
        "the CLI prints the control plane message: {stdout}"
    );

    // The control plane RECORDED the call with the token and the pack BYTES.
    let pack_path = pack_file.to_string_lossy().to_string();
    let recv = hits.lock().unwrap().join("\n");
    assert!(
        recv.contains("/api/packs/install"),
        "mock did not see the install: {recv}"
    );
    assert!(
        recv.contains(ADMIN_TOKEN),
        "mock did not receive X-Cerberus-Admin-Token: {recv}"
    );
    assert!(
        recv.contains("\"wire_version\":2"),
        "the body must declare the v2 contract (bytes): {recv}"
    );
    assert!(
        recv.contains("signer_public_key_hex"),
        "the body must carry the full signed pack: {recv}"
    );
    assert!(
        recv.contains("wire-demo.json"),
        "the body must carry the informational basename: {recv}"
    );
    assert!(
        !recv.contains(pack_path.as_str()),
        "the body must NOT carry the client path (remote cwd semantics): {recv}"
    );
    assert!(
        !recv.contains("packs origin"),
        "no component of the client path must travel: {recv}"
    );

    // The CLI did NOT create the local packs layout (does not touch disk in
    // API mode → a single runtime writer: the daemon's worker).
    assert!(
        !cfg_dir.join("packs").exists(),
        "the CLI must not create ~/.cerberus/packs in API mode"
    );

    std::fs::remove_dir_all(&dir).ok();
    drop(handle);
}

#[test]
fn cli_pack_falls_back_to_local_without_daemon() {
    let dir = temp_dir("pack_cli_local");
    let cfg_dir = dir.join(".cerberus");
    std::fs::create_dir_all(&cfg_dir).expect("create .cerberus");
    // WITHOUT a pid file → the daemon is NOT running → local mode.
    // The mock must not receive any call (no daemon to query).

    let out = Command::new(binary())
        .arg("pack")
        .arg("list")
        .env("HOME", &dir)
        .env_remove("CERBERUS_ADMIN_TOKEN")
        .output()
        .expect("run cerberus pack list (local)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}\nstdout: {stdout}");
    assert!(
        stdout.contains("no rule packs found"),
        "local mode expected — stdout: {stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Structurally valid `SignedRulePack` (fictitious signature: the daemon is
/// the one that verifies it against its trust root; the CLI only validates the
/// file's form).
fn sample_signed_pack() -> String {
    let pack_json = r#"{"metadata":{"name":"wire-demo","version":"1.0.0","description":"d","author":"a","published":"2026-01-01T00:00:00Z","min_engine_version":"0.1.0"},"rules":[]}"#;
    format!(
        r#"{{"pack_json":{pack_json:?},"signature_hex":"{}","signer_public_key_hex":"{}"}}"#,
        "aa".repeat(64),
        "bb".repeat(32)
    )
}

/// [v6.1] Client fail-safe: if the pack does not exist (or is not a pack),
/// the CLI fails BEFORE calling the control plane — the mock sees nothing.
#[test]
fn cli_pack_install_rejects_missing_pack_without_calling_api() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let dir = temp_dir("pack_cli_missing");
    let cfg_dir = dir.join(".cerberus");
    std::fs::create_dir_all(&cfg_dir).expect("create .cerberus");
    std::fs::write(
        cfg_dir.join("config.yaml"),
        format!("listen: {addr}\nadmin_token: {ADMIN_TOKEN}\n"),
    )
    .expect("write config.yaml");
    std::fs::write(cfg_dir.join("cerberus.pid"), std::process::id().to_string()).expect("write pid");

    let out = Command::new(binary())
        .arg("pack")
        .arg("install")
        .arg(dir.join("no-existe.json"))
        .env("HOME", &dir)
        .env("CERBERUS_ADMIN_TOKEN", ADMIN_TOKEN)
        .output()
        .expect("run cerberus pack install (missing)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "must fail: {stdout}{stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("cannot resolve pack"),
        "expected actionable message: {combined}"
    );
    assert!(
        hits.lock().unwrap().is_empty(),
        "the CLI must not call the control plane with an unreadable pack"
    );

    std::fs::remove_dir_all(&dir).ok();
    drop(handle);
}

/// [v6.1] Effective endpoint discovery: `endpoint.json` (published by the
/// daemon) wins over the `listen` of `config.yaml`, which here points to a
/// dead port. If the CLI did not use the descriptor, the call would not arrive.
#[test]
fn cli_pack_discovers_effective_endpoint_from_descriptor() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let dir = temp_dir("pack_cli_endpoint");
    let cfg_dir = dir.join(".cerberus");
    std::fs::create_dir_all(&cfg_dir).expect("create .cerberus");
    // config.yaml lies about the port (e.g. the daemon bound an ephemeral one).
    std::fs::write(
        cfg_dir.join("config.yaml"),
        format!("listen: 127.0.0.1:9\nadmin_token: {ADMIN_TOKEN}\n"),
    )
    .expect("write config.yaml");
    std::fs::write(cfg_dir.join("cerberus.pid"), std::process::id().to_string()).expect("write pid");
    let endpoint = cerberus_packs::wire::ControlPlaneEndpoint::new(&addr.to_string(), std::process::id())
        .expect("endpoint descriptor");
    std::fs::write(
        cfg_dir.join(cerberus_packs::wire::ENDPOINT_FILE),
        endpoint.to_json().expect("endpoint json"),
    )
    .expect("write endpoint.json");

    let out = Command::new(binary())
        .arg("pack")
        .arg("list")
        .env("HOME", &dir)
        .env_remove("CERBERUS_LISTEN")
        .env("CERBERUS_ADMIN_TOKEN", ADMIN_TOKEN)
        .output()
        .expect("run cerberus pack list via descriptor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the CLI must reach the published endpoint — stderr: {stderr}\nstdout: {stdout}"
    );
    let recv = hits.lock().unwrap().join("\n");
    assert!(
        recv.contains("/api/packs"),
        "the mock (descriptor port) must receive the call: {recv}"
    );

    std::fs::remove_dir_all(&dir).ok();
    drop(handle);
}
