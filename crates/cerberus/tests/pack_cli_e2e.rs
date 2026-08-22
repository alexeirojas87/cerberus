//! Integration test: `cerberus pack` (F7) extremo a extremo contra el binario.
//!
//! Valida el flujo completo SIN tocar `proxy.rs`:
//!   1. Se genera una licencia Pro firmada y un rule pack firmado.
//!   2. `cerberus pack install` fusiona las reglas del pack en el engine
//!      (salida "reglas del engine N → M") — gate de licencia Pro.
//!   3. A nivel librería, el engine del `PackManager` detecta el marcador del
//!      pack (el pack queda conectado al engine que el proxy usa en el arranque
//!      cuando el pack está en `~/.cerberus/packs` antes de `start`).
//!   4. `cerberus pack list` muestra el pack con firma válida.
//!   5. `cerberus pack rollback` revierte al engine anterior.
//!   6. Sin licencia Pro, `pack install` falla con mensaje de gating.

use std::path::PathBuf;
use std::process::Command;

use ed25519_dalek::Signer;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
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

/// Escribe una licencia Pro firmada en `dir/license.json`; devuelve la root.
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

/// Escribe un rule pack firmado con un marcador único; devuelve el root.
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
            description: "Pack de prueba E2E F7".to_string(),
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

    // 2) install: exit 0, el engine crece (N → N+1).
    let out = Command::new(binary())
        .arg("pack")
        .arg("install")
        .arg(&pack_file)
        .env("HOME", &dir)
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
    assert!(stdout.contains("instalado"), "stdout: {stdout}");
    assert!(stdout.contains("reglas del engine"), "stdout: {stdout}");

    // 3) El pack QUEDA conectado al engine: el motor instalado detecta el
    //    marcador (la misma instalación que el daemon hace en el arranque).
    let found = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async {
            let base = cerberus_engine::engine::EngineBuilder::new(&[]).build()?;
            let mgr = cerberus_packs::updater::PackManager::new(dir.join(".cerberus/packs"), base)?;
            let signed = cerberus_packs::updater::PackManager::load_pack_from_file(&pack_file)?;
            mgr.install_with_root(signed, &pack_root).await?;
            let engine = mgr.engine();
            let guard = engine.lock().await;
            let findings = guard.scan(&format!("payload {marker} llegó al upstream"));
            Ok::<bool, String>(!findings.findings.is_empty())
        })
        .expect("pack engine proof");
    assert!(found, "el engine instalado debe detectar el marcador del pack E2E");

    // 4) list: el pack figura con firma válida frente al trust root.
    let out = Command::new(binary())
        .arg("pack")
        .arg("list")
        .env("HOME", &dir)
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .output()
        .expect("run cerberus pack list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("e2e-pack") && stdout.contains("firma válida"),
        "pack list debe mostrar el pack verificado:\n{stdout}"
    );

    // 5) rollback: revierte al engine anterior. (Hallazgo v6: rollback es
    //    Pro-gated en modo local; este e2e corre con licencia Pro del paso 2.)
    let out = Command::new(binary())
        .arg("pack")
        .arg("rollback")
        .env("HOME", &dir)
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

    // Sin licencia entrenada ni trust root de licencia: default → tier Free.
    let out = Command::new(binary())
        .arg("pack")
        .arg("install")
        .arg(&pack_file)
        .env("HOME", &dir)
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
        "el CLI debe bloquear pack install sin Pro — stdout: {stdout}"
    );
    assert!(
        stderr.contains("Pro") || stderr.contains("open-core") || stderr.contains("licencia"),
        "mensaje de gating esperado — stderr: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Hallazgo v6: `pack rollback` en modo local (sin daemon) también debe estar
/// gated por licencia Pro — bajo Free debe fallar antes de rehidratar packs.
#[test]
#[allow(clippy::significant_drop_tightening)]
fn pack_rollback_requires_pro_license() {
    let dir = temp_dir("pack_e2e_gate_rollback");
    let marker = "CERBERUS_GATE_ROLLBACK_MARK";
    let pack_file = dir.join("pack.json");
    let pack_root = write_signed_pack(&pack_file, marker);

    // Primero instalar con una licencia Pro para dejar manifest/historial.
    let license_root = write_pro_license(&dir);
    let install = Command::new(binary())
        .arg("pack")
        .arg("install")
        .arg(&pack_file)
        .env("HOME", &dir)
        .env("CERBERUS_LICENSE_PUBLIC_KEY", &license_root)
        .env("CERBERUS_LICENSE_PATH", dir.join("license.json"))
        .env("CERBERUS_PACK_TRUST_ROOT", &pack_root)
        .output()
        .expect("install with pro");
    assert_eq!(install.status.code(), Some(0), "install con Pro debe pasar");

    // Ahora rollback SIN Pro (quitar licencia) → debe fallar con gating.
    let out = Command::new(binary())
        .arg("pack")
        .arg("rollback")
        .env("HOME", &dir)
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
        "el CLI debe bloquear pack rollback sin Pro — stdout: {stdout}"
    );
    assert!(
        stderr.contains("Pro") || stderr.contains("open-core") || stderr.contains("licencia"),
        "mensaje de gating esperado — stderr: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
