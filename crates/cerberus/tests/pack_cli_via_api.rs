//! Integration test: `cerberus pack` como CLIENTE del control plane (revisor v6).
//!
//! Revisor v6 (P1): cuando el daemon está en marcha, el CLI NO abre otro
//! `PackManager` ni modifica disco — invoca `/api/packs/*` del control plane.
//! El daemon (su worker) es el ÚNICO escritor del manifest en runtime.
//!
//! Estrategia determinista (sin sb daemon real):
//!   1. se levanta un mini control plane (mock HTTP TCP) en un hilo propio
//!      que registra la request cruda y responde `{"status":"ok",...}`;
//!   2. se escribe `~/.cerberus/config.yaml` con `listen` apuntando al mock y
//!      `~/.cerberus/cerberus.pid` con el PID de este proceso VIVO → el CLI
//!      deduce que el daemon "está en marcha" y decide ir por HTTP;
//!   3. se lanza `cerberus pack install <f>` y se comprueba que (a) el CLI
//!      llama a la API (el mock lo registra) y (b) NO crea manif en disco
//!      (no toca `.cerberus/packs`).
//!   4. Sin pid file → fallback al modo local (un solo proceso).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cerberus")
}

/// Token ≥ 24 bytes (el control plane exige mínimo 24, review v4 #1).
const ADMIN_TOKEN: &str = "cerberus-cli-control-plane-test-token-0123";

/// Respuesta de éxito del mock control plane.
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

/// Mini control plane del daemon en un hilo propio (con su propio runtime
/// tokio). Registra la request cruda en `hits` y responde
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

    // El control plane apunta al mock y el pid a un proceso vivo.
    std::fs::write(
        cfg_dir.join("config.yaml"),
        format!("listen: {addr}\nadmin_token: {ADMIN_TOKEN}\n"),
    )
    .expect("write config.yaml");
    std::fs::write(cfg_dir.join("cerberus.pid"), std::process::id().to_string()).expect("write pid");

    // v6.1: el CLI lee el pack y envía sus BYTES (nunca el path). El pack
    // vive en un subdirectorio con espacio para probar que la ruta no viaja.
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
        "el CLI debe salir OK por la API — stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("installed via control plane API"),
        "el CLI imprime el mensaje del control plane: {stdout}"
    );

    // El control plane REGISTRÓ la llamada con el token y los BYTES del pack.
    let pack_path = pack_file.to_string_lossy().to_string();
    let recv = hits.lock().unwrap().join("\n");
    assert!(recv.contains("/api/packs/install"), "mock no vio el install: {recv}");
    assert!(
        recv.contains(ADMIN_TOKEN),
        "mock no recibió X-Cerberus-Admin-Token: {recv}"
    );
    assert!(
        recv.contains("\"wire_version\":2"),
        "el body debe declarar el contrato v2 (bytes): {recv}"
    );
    assert!(
        recv.contains("signer_public_key_hex"),
        "el body debe transportar el pack firmado completo: {recv}"
    );
    assert!(
        recv.contains("wire-demo.json"),
        "el body debe llevar el basename informativo: {recv}"
    );
    assert!(
        !recv.contains(pack_path.as_str()),
        "el body NO debe llevar la ruta del cliente (semántica de cwd remota): {recv}"
    );
    assert!(
        !recv.contains("packs origin"),
        "ningún componente de la ruta del cliente debe viajar: {recv}"
    );

    // El CLI NO creó el layout local de packs (no toca disco en modo API →
    // un solo escritor en runtime: el worker del daemon).
    assert!(
        !cfg_dir.join("packs").exists(),
        "el CLI no debe crear ~/.cerberus/packs en modo API"
    );

    std::fs::remove_dir_all(&dir).ok();
    drop(handle);
}

#[test]
fn cli_pack_falls_back_to_local_without_daemon() {
    let dir = temp_dir("pack_cli_local");
    let cfg_dir = dir.join(".cerberus");
    std::fs::create_dir_all(&cfg_dir).expect("create .cerberus");
    // SIN pid file → el daemon NO está en marcha → modo local.
    // El mock no debe recibir ninguna llamada (no hay daemon que consultar).

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
        stdout.contains("no se encontraron"),
        "modo local esperado — stdout: {stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `SignedRulePack` estructuralmente válido (firma ficticia: el daemon es quien
/// la verifica contra su trust root; el CLI solo valida la forma del archivo).
fn sample_signed_pack() -> String {
    let pack_json = r#"{"metadata":{"name":"wire-demo","version":"1.0.0","description":"d","author":"a","published":"2026-01-01T00:00:00Z","min_engine_version":"0.1.0"},"rules":[]}"#;
    format!(
        r#"{{"pack_json":{pack_json:?},"signature_hex":"{}","signer_public_key_hex":"{}"}}"#,
        "aa".repeat(64),
        "bb".repeat(32)
    )
}

/// [v6.1] Fallo seguro del cliente: si el pack no existe (o no es un pack), el
/// CLI falla ANTES de llamar al control plane — el mock no ve nada.
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
    assert_ne!(out.status.code(), Some(0), "debe fallar: {stdout}{stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("no se puede resolver el pack"),
        "mensaje accionable esperado: {combined}"
    );
    assert!(
        hits.lock().unwrap().is_empty(),
        "el CLI no debe llamar al control plane con un pack ilegible"
    );

    std::fs::remove_dir_all(&dir).ok();
    drop(handle);
}

/// [v6.1] Descubrimiento del endpoint efectivo: `endpoint.json` (publicado por
/// el daemon) gana sobre el `listen` de `config.yaml`, que aquí apunta a un
/// puerto muerto. Si el CLI no usara el descriptor, la llamada no llegaría.
#[test]
fn cli_pack_discovers_effective_endpoint_from_descriptor() {
    let (addr, handle, hits) = spawn_mock_control_plane();
    let dir = temp_dir("pack_cli_endpoint");
    let cfg_dir = dir.join(".cerberus");
    std::fs::create_dir_all(&cfg_dir).expect("create .cerberus");
    // config.yaml miente sobre el puerto (p.ej. el daemon ligó un efímero).
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
        "el CLI debe alcanzar el endpoint publicado — stderr: {stderr}\nstdout: {stdout}"
    );
    let recv = hits.lock().unwrap().join("\n");
    assert!(
        recv.contains("/api/packs"),
        "el mock (puerto del descriptor) debe recibir la llamada: {recv}"
    );

    std::fs::remove_dir_all(&dir).ok();
    drop(handle);
}
