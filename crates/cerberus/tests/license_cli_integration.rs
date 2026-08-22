//! Integration test: `cerberus license` lee y verifica una licencia firmada
//! desde el archivo señalado por `CERBERUS_LICENSE_PATH` (F7 en el producto,
//! code review item 12).
//!
//! El binario del crate (`CARGO_BIN_EXE_cerberus`) es el MISMO código que el
//! daemon usa en `start()` (vía `daemon::load_license` + `license_summary`), de
//! modo que esta prueba demuestra que el arranque del producto reconoce una
//! licencia Pro válida y NO cae cuando la licencia falta/invalida.

use std::path::PathBuf;
use std::process::Command;

/// Genera una licencia Pro firmada y la escribe en `dir/license.json`.
/// Devuelve (ruta, trust-root hex).
fn write_signed_pro_license(dir: &std::path::Path) -> (PathBuf, String) {
    use ed25519_dalek::Signer;

    let keypair = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let license = cerberus_packs::license::License {
        tier: cerberus_packs::license::LicenseTier::Pro,
        email: "dev@cerberus.dev".to_string(),
        license_id: "f7-cli-integration".to_string(),
        expires_at: None,
        features: Vec::new(),
    };
    let license_json = serde_json::to_string(&license).expect("serialize license");
    let signature = keypair.sign(license_json.as_bytes());
    let signed = cerberus_packs::license::SignedLicense {
        license_json,
        signature_hex: hex::encode(signature.to_bytes().as_slice()),
        signer_public_key_hex: hex::encode(keypair.verifying_key().as_bytes()),
        owner_public_key_hex: None,
    };
    let path = dir.join("license.json");
    std::fs::write(&path, serde_json::to_string(&signed).expect("serialize signed license")).expect("write license");
    (path, hex::encode(keypair.verifying_key().as_bytes()))
}

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
}

#[test]
fn cli_license_activates_pro_from_signed_file() {
    let dir = std::env::temp_dir().join(format!(
        "cerberus_cli_license_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let (license_file, root_hex) = write_signed_pro_license(&dir);

    let out = Command::new(binary())
        .arg("license")
        .env("CERBERUS_LICENSE_PUBLIC_KEY", root_hex)
        .env("CERBERUS_LICENSE_PATH", &license_file)
        .output()
        .expect("run cerberus license");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "exit 0 — daemon path no cae\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("tier=pro"),
        "el log del producto debe incluir tier=pro:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_license_falls_back_to_free_without_trust_root() {
    let dir = std::env::temp_dir().join(format!(
        "cerberus_cli_license_free_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let (license_file, _root) = write_signed_pro_license(&dir);

    // Licencia firmada presente pero SIN trust root: el producto responde
    // fail-open → Free, exit 0 (el daemon no cae).
    let out = Command::new(binary())
        .arg("license")
        .env("CERBERUS_LICENSE_PATH", &license_file)
        .env_remove("CERBERUS_LICENSE_PUBLIC_KEY")
        .output()
        .expect("run cerberus license");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("tier=free"),
        "sin trust root el producto responde Free:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
