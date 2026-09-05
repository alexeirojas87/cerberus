//! Integration test (F6.B attempt 2, finding F3): the REAL packs
//! enable/disable success path, end-to-end through the real daemon worker.
//!
//! Attempt 1's reviewer found the composed path API → `PackCommand` →
//! worker arm → `PackManager::set_active` → `snapshot_engine` → engine
//! rebase had NO executing test (`f6b_api_surface` stubs the worker with a
//! channel echo; the honest 400 gates were live-verified but never the
//! success round-trip). This test spawns the actual `cerberus start`
//! daemon with a signed Pro license and a trust root, then drives:
//!
//!   install (activates) → `/api/scan` DETECTS the pack marker
//!     → disable (Free-tier allowed) → scan does NOT detect
//!     → enable (Pro gate passes) → scan DETECTS again
//!     → the mutations are audited via `/api/events`
//!
//! Everything in the chain is the production code path: the HTTP handler
//! sends the command to the REAL worker loop in `daemon.rs`, which calls
//! `set_active` on a REAL `PackManager` over a REAL signed pack and
//! republishes the engine the proxy scans with.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use ed25519_dalek::Signer;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
}

/// Token ≥ 24 bytes (the control plane requires at least 24).
const ADMIN_TOKEN: &str = "cerberus-worker-e2e-admin-token-012345";

/// Kills the daemon on drop so a failing assert never leaks a listener.
struct DaemonGuard(Child);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config_subdir(home: &Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        home.join("Cerberus")
    }
    #[cfg(not(target_os = "windows"))]
    {
        home.join(".cerberus")
    }
}

fn temp_dir(prefix: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cerberus_{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).expect("create tmp dir");
    std::fs::create_dir_all(config_subdir(&d)).expect("create cfg dir");
    d.canonicalize().unwrap_or(d)
}

/// Writes a signed Pro license to `dir/license.json`; returns the license
/// trust root (the signer's public key hex). Same pattern as the F7 CLI
/// e2e (`pack_cli_e2e.rs`).
fn write_pro_license(dir: &Path) -> String {
    let license = cerberus_packs::license::License {
        tier: cerberus_packs::license::LicenseTier::Pro,
        email: "dev@cerberus.dev".to_string(),
        license_id: "worker-e2e".to_string(),
        expires_at: None,
        features: Vec::new(),
    };
    let license_json = serde_json::to_string(&license).expect("serialize license");
    let keypair = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let signature = keypair.sign(license_json.as_bytes());
    let signed = cerberus_packs::license::SignedLicense {
        license_json,
        signature_hex: hex::encode(signature.to_bytes().as_slice()),
        signer_public_key_hex: hex::encode(keypair.verifying_key().as_bytes()),
        owner_public_key_hex: None,
    };
    std::fs::write(
        dir.join("license.json"),
        serde_json::to_string(&signed).expect("serialize signed"),
    )
    .expect("write license");
    hex::encode(keypair.verifying_key().as_bytes())
}

/// Writes a signed rule pack carrying one unique marker rule; returns the
/// pack trust root (the pack signer's public key hex).
fn write_signed_pack(path: &Path, marker: &str) -> String {
    let rule = cerberus_engine::rule::Rule {
        flag: "pack.e2e.marker".to_string(),
        category: cerberus_engine::rule::Category::Secrets,
        severity: cerberus_engine::rule::Severity::High,
        action: cerberus_engine::rule::Action::Block,
        hash_normalization: None,
        context_keywords: vec!["e2e".to_string()],
        min_length: None,
        max_length: None,
        allowed_examples: Vec::new(),
        patterns: vec![marker.to_string()],
        validators: Vec::new(),
    };
    let pack = cerberus_packs::pack::RulePack {
        metadata: cerberus_packs::pack::PackMetadata {
            name: "e2e-pack".to_string(),
            version: "1.0.0".to_string(),
            description: "Worker e2e test pack (F6.B attempt 2)".to_string(),
            author: "Cerberus".to_string(),
            published: "2026-09-02T00:00:00Z".to_string(),
            min_engine_version: "0.1.0".to_string(),
        },
        rules: vec![rule],
    };
    let keypair = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let signed = cerberus_packs::pack::SignedRulePack::sign(&pack, &keypair).expect("sign pack");
    std::fs::write(path, serde_json::to_string(&signed).expect("serialize pack")).expect("write pack");
    hex::encode(keypair.verifying_key().as_bytes())
}

/// Picks a free loopback port (bind 0 → read → drop). The tiny bind race is
/// the repo-standard trade-off for binary e2e tests.
fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind :0")
        .local_addr()
        .expect("local addr")
        .port()
}

fn auth_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        "x-cerberus-admin-token",
        reqwest::header::HeaderValue::from_static(ADMIN_TOKEN),
    );
    h
}

#[test]
#[allow(clippy::too_many_lines)] // e2e clarity > brevity (repo test style)
fn pack_enable_disable_round_trip_through_the_real_worker() {
    let dir = temp_dir("worker_e2e");
    let license_root = write_pro_license(&dir);
    let marker = format!(
        "CERBERUS_E2E_{}_{}_SIGNAL",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
    );
    let pack_file = dir.join("pack.json");
    let pack_root = write_signed_pack(&pack_file, &marker);

    let port = free_port();
    std::fs::write(
        config_subdir(&dir).join("config.yaml"),
        format!(
            "listen: 127.0.0.1:{port}\nmode: enforce\nfail_policy: closed\nadmin_token: {ADMIN_TOKEN}\nupstreams:\n  openai:\n    url: https://api.openai.com\n"
        ),
    )
    .expect("write config.yaml");

    // The REAL daemon: packs trust root + Pro license wired exactly as the
    // product wiring resolves them (env), so the worker's Pro gate passes
    // for enable/install. stdout/stderr go to a FILE (a full pipe would
    // block the daemon's console writes and deadlock the round trip).
    let log_file = std::fs::File::create(dir.join("daemon.log")).expect("create daemon log");
    let child = Command::new(binary())
        .arg("start")
        .arg("--port")
        .arg(port.to_string())
        .env("HOME", &dir)
        .env("APPDATA", &dir)
        .env("CERBERUS_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("CERBERUS_LICENSE_PUBLIC_KEY", &license_root)
        .env("CERBERUS_LICENSE_PATH", dir.join("license.json"))
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .stdout(log_file.try_clone().expect("clone log file"))
        .stderr(log_file)
        .spawn()
        .expect("spawn cerberus start");
    let guard = DaemonGuard(child);

    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(drive_round_trip(port, &marker, &pack_file));

    drop(guard);
    std::fs::remove_dir_all(&dir).ok();
}

/// Drives the whole round trip against the running daemon.
#[allow(clippy::too_many_lines)] // e2e clarity > brevity (repo test style)
async fn drive_round_trip(port: u16, marker: &str, pack_file: &Path) {
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client");
    let headers = auth_headers();

    // Wait for the daemon to become healthy.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "daemon never became healthy on port {port}"
        );
        if let Ok(resp) = client.get(format!("{base}/health")).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Install through the control plane: the worker installs the signed
    // pack and ACTIVATES it (manifest default). Pro gate passes (license).
    let pack_json = std::fs::read_to_string(pack_file).expect("read pack");
    let install_body =
        cerberus_packs::wire::PackInstallRequest::from_pack_bytes(pack_json.as_bytes(), Some("worker-e2e"))
            .and_then(|req| req.to_body())
            .expect("install body");
    let resp = client
        .post(format!("{base}/api/packs/install"))
        .header("content-type", "application/json")
        .headers(headers.clone())
        .body(install_body)
        .send()
        .await
        .expect("install");
    let status = resp.status();
    let body = resp.text().await.expect("install body");
    assert_eq!(status, 200, "install must succeed through the worker: {body}");
    assert!(body.contains("installed"), "install message: {body}");

    // The worker rebased the LIVE engine: the proxy's dry-run scan detects
    // the pack marker (install = active).
    let scan = |headers: reqwest::header::HeaderMap| {
        let client = &client;
        let base = &base;
        async move {
            client
                .post(format!("{base}/api/scan"))
                .header("content-type", "application/json")
                .headers(headers)
                .body(serde_json::json!({ "text": format!("payload {marker} reached the upstream") }).to_string())
                .send()
                .await
                .expect("scan")
                .json::<serde_json::Value>()
                .await
                .expect("scan json")
        }
    };
    let after_install = scan(headers.clone()).await;
    assert!(
        after_install["flags"]
            .as_object()
            .is_some_and(|f| f.contains_key("pack.e2e.marker")),
        "installed (active) pack must feed the live engine: {after_install}"
    );

    // DISABLE through the worker (no Pro gate by design): the rule must
    // leave the live engine WITHOUT a restart.
    let resp = client
        .post(format!("{base}/api/packs/disable"))
        .header("content-type", "application/json")
        .headers(headers.clone())
        .body(r#"{"name":"e2e-pack"}"#)
        .send()
        .await
        .expect("disable");
    let status = resp.status();
    let body = resp.text().await.expect("disable body");
    assert_eq!(status, 200, "disable success path must work: {body}");
    assert!(body.contains("disabled"), "disable message: {body}");
    let after_disable = scan(headers.clone()).await;
    assert!(
        !after_disable["flags"]
            .as_object()
            .is_some_and(|f| f.contains_key("pack.e2e.marker")),
        "disabled pack must NOT feed the live engine: {after_disable}"
    );

    // ENABLE through the worker (Pro gate passes with the signed license):
    // set_active(true) → snapshot → rebase → the rule is BACK.
    let resp = client
        .post(format!("{base}/api/packs/enable"))
        .header("content-type", "application/json")
        .headers(headers.clone())
        .body(r#"{"name":"e2e-pack"}"#)
        .send()
        .await
        .expect("enable");
    let status = resp.status();
    let body = resp.text().await.expect("enable body");
    assert_eq!(status, 200, "enable success path must work (Pro license wired): {body}");
    assert!(body.contains("enabled"), "enable message: {body}");
    let after_enable = scan(headers.clone()).await;
    assert!(
        after_enable["flags"]
            .as_object()
            .is_some_and(|f| f.contains_key("pack.e2e.marker")),
        "re-enabled pack must feed the live engine again: {after_enable}"
    );

    // The worker mutations are AUDITED (security P2-1) — visible on the
    // real daemon via /api/events, with the honest action names.
    let events = client
        .get(format!("{base}/api/events?tool=control-plane"))
        .headers(headers)
        .send()
        .await
        .expect("events")
        .text()
        .await
        .expect("events body");
    assert!(events.contains("pack-enable"), "enable audited: {events}");
    assert!(events.contains("pack-disable"), "disable audited: {events}");
    assert!(!events.contains(ADMIN_TOKEN), "no token in the audit trail: {events}");
    assert!(!events.contains(marker), "no rule pattern echoed: {events}");
}
