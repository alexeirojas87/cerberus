//! Integration test: `cerberus pack` (F7) end-to-end against the binary.
//!
//! Validates the full flow WITHOUT touching `proxy.rs`:
//!   1. A signed Pro license and a signed rule pack are generated.
//!   2. `cerberus pack install` merges the pack's rules into the engine
//!      (output "engine rules N → M") — Pro license gate.
//!   3. At the library level, the `PackManager` engine detects the pack's
//!      marker (the pack stays connected to the engine the proxy uses at boot
//!      when the pack is in `~/.cerberus/packs` before `start`).
//!   4. `cerberus pack list` shows the pack with a valid signature.
//!   5. `cerberus pack rollback` reverts to the previous engine.
//!   6. Without a Pro license, `pack install` fails with a gating message.

use std::path::PathBuf;
use std::process::Command;

use ed25519_dalek::Signer;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
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
        "cerberus_{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).expect("create tmp dir");
    d.canonicalize().unwrap_or(d)
}

/// Writes a signed Pro license to `dir/license.json`; returns the root.
fn write_pro_license(dir: &std::path::Path) -> String {
    let license = cerberus_packs::license::License {
        tier: cerberus_packs::license::LicenseTier::Pro,
        email: "dev@cerberus.dev".to_string(),
        license_id: "pack-e2e".to_string(),
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
    let path = dir.join("license.json");
    std::fs::write(&path, serde_json::to_string(&signed).expect("serialize signed")).expect("write license");
    hex::encode(keypair.verifying_key().as_bytes())
}

/// Writes a signed rule pack with a unique marker; returns the root.
fn write_signed_pack(path: &std::path::Path, marker: &str) -> String {
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
            description: "E2E F7 test pack".to_string(),
            author: "Cerberus".to_string(),
            published: "2026-08-20T00:00:00Z".to_string(),
            min_engine_version: "0.1.0".to_string(),
        },
        rules: vec![rule],
    };
    let keypair = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let signed = cerberus_packs::pack::SignedRulePack::sign(&pack, &keypair).expect("sign pack");
    std::fs::write(path, serde_json::to_string(&signed).expect("serialize pack")).expect("write pack");
    hex::encode(keypair.verifying_key().as_bytes())
}

#[test]
#[allow(clippy::significant_drop_tightening)]
fn pack_cli_install_list_rollback_e2e() {
    let dir = temp_dir("pack_e2e");
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

    // 2) install: exit 0, the engine grows (N → N+1).
    let out = cerberus_cmd(&dir)
        .arg("pack")
        .arg("install")
        .arg(&pack_file)
        .env("CERBERUS_LICENSE_PUBLIC_KEY", &license_root)
        .env("CERBERUS_LICENSE_PATH", dir.join("license.json"))
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .output()
        .expect("run cerberus pack install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "pack install exit 0 — stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(stdout.contains("installed"), "stdout: {stdout}");
    assert!(stdout.contains("engine rules"), "stdout: {stdout}");

    // 3) The pack STAYS connected to the engine: the installed engine detects
    //    the marker (the same install the daemon does at boot).
    let found = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async {
            let base = cerberus_engine::engine::EngineBuilder::new(&[]).build()?;
            let packs_dir = if cfg!(target_os = "windows") {
                dir.join("Cerberus/packs")
            } else {
                dir.join(".cerberus/packs")
            };
            let mgr = cerberus_packs::updater::PackManager::new(packs_dir, base)?;
            let signed = cerberus_packs::updater::PackManager::load_pack_from_file(&pack_file)?;
            mgr.install_with_root(signed, &pack_root).await?;
            let engine = mgr.engine();
            let guard = engine.lock().await;
            let findings = guard.scan(&format!("payload {marker} reached the upstream"));
            Ok::<bool, String>(!findings.findings.is_empty())
        })
        .expect("pack engine proof");
    assert!(found, "the installed engine must detect the E2E pack marker");

    // 4) list: the pack appears with a valid signature against the trust root.
    let out = cerberus_cmd(&dir)
        .arg("pack")
        .arg("list")
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .output()
        .expect("run cerberus pack list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("e2e-pack") && stdout.contains("valid signature"),
        "pack list must show the verified pack:\n{stdout}"
    );

    // 5) rollback: reverts to the previous engine. (Finding v6: rollback is
    //    Pro-gated in local mode; this e2e runs with a Pro license from step 2.)
    let out = cerberus_cmd(&dir)
        .arg("pack")
        .arg("rollback")
        .env("CERBERUS_LICENSE_PUBLIC_KEY", &license_root)
        .env("CERBERUS_LICENSE_PATH", dir.join("license.json"))
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .output()
        .expect("run cerberus pack rollback");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("rollback"), "stdout: {stdout}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pack_install_requires_pro_license() {
    let dir = temp_dir("pack_e2e_gate");
    let marker = "CERBERUS_GATE_MARKER_VAL";
    let pack_file = dir.join("pack.json");
    let pack_root = write_signed_pack(&pack_file, marker);

    // Without a trained license nor license trust root: default → Free tier.
    let out = cerberus_cmd(&dir)
        .arg("pack")
        .arg("install")
        .arg(&pack_file)
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .env_remove("CERBERUS_LICENSE_PUBLIC_KEY")
        .env_remove("CERBERUS_LICENSE_PATH")
        .output()
        .expect("run cerberus pack install (free tier)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code(),
        Some(0),
        "the CLI must block pack install without Pro — stdout: {stdout}"
    );
    assert!(
        stderr.contains("Pro") || stderr.contains("open-core") || stderr.contains("license"),
        "expected gating message — stderr: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Finding v6: `pack rollback` in local mode (without daemon) must also be
/// gated by a Pro license — under Free it must fail before rehydrating packs.
#[test]
#[allow(clippy::significant_drop_tightening)]
fn pack_rollback_requires_pro_license() {
    let dir = temp_dir("pack_e2e_gate_rollback");
    let marker = "CERBERUS_GATE_ROLLBACK_MARK";
    let pack_file = dir.join("pack.json");
    let pack_root = write_signed_pack(&pack_file, marker);

    // First install with a Pro license to leave manifest/history.
    let license_root = write_pro_license(&dir);
    let install = cerberus_cmd(&dir)
        .arg("pack")
        .arg("install")
        .arg(&pack_file)
        .env("CERBERUS_LICENSE_PUBLIC_KEY", &license_root)
        .env("CERBERUS_LICENSE_PATH", dir.join("license.json"))
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .output()
        .expect("install with pro");
    assert_eq!(install.status.code(), Some(0), "install with Pro must pass");

    // Now rollback WITHOUT Pro (remove license) → must fail with gating.
    let out = cerberus_cmd(&dir)
        .arg("pack")
        .arg("rollback")
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .env_remove("CERBERUS_LICENSE_PUBLIC_KEY")
        .env_remove("CERBERUS_LICENSE_PATH")
        .output()
        .expect("rollback without pro");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code(),
        Some(0),
        "the CLI must block pack rollback without Pro — stdout: {stdout}"
    );
    assert!(
        stderr.contains("Pro") || stderr.contains("open-core") || stderr.contains("license"),
        "expected gating message — stderr: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
