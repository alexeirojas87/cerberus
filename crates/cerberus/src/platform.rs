//! Soporte multiplataforma (macOS, Linux, Windows).
//!
//! Paths, detección y gestión de procesos específicos por plataforma para el
//! daemon local. Fuente de verdad única de rutas y de lifecycle de procesos:
//! el daemon delega aquí `config_dir()`, `process_alive()` y la detención
//! cooperativa (`stop_process_graceful()`).
//!
//! `config_dir()` mantiene la convención ya existente del daemon en
//! macOS/Linux (`~/.cerberus`) —varios tests y tools dependen de esa ruta
//! bajo `HOME`— y usa `%APPDATA%\Cerberus` en Windows.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::{Duration, Instant};

/// Obtener el directorio de configuración del usuario según la plataforma.
#[must_use]
pub(crate) fn config_dir() -> PathBuf {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        dirs::home_dir().map_or_else(|| PathBuf::from("/tmp/cerberus"), |p| p.join(".cerberus"))
    }
    #[cfg(target_os = "windows")]
    {
        // %APPDATA%/Cerberus
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("Cerberus"))
            .unwrap_or_else(|_| PathBuf::from("C:\\Cerberus"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/tmp/cerberus")
    }
}

/// Obtener el directorio de logs según la plataforma.
#[must_use]
pub(crate) fn log_dir() -> PathBuf {
    config_dir().join("logs")
}

/// Nombre del binario del daemon según la plataforma.
#[must_use]
pub(crate) const fn daemon_binary_name() -> &'static str {
    #[cfg(windows)]
    {
        "cerberus.exe"
    }
    #[cfg(not(windows))]
    {
        "cerberus"
    }
}

/// ¿El proceso con `pid` sigue vivo?
///
/// unix: `kill -0` (existe el proceso). Windows: `tasklist /FI "PID eq N"` y
/// se verifica que la salida contenga un token de PID como tal (la línea
/// "INFO: No tasks..." de stdout no debe confundirse con un proceso vivo).
#[must_use]
pub(crate) fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let output = StdCommand::new("kill").arg("-0").arg(pid.to_string()).output();
        matches!(output, Ok(o) if o.status.success())
    }

    #[cfg(windows)]
    {
        let Ok(output) = StdCommand::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
        else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        let pid_token = pid.to_string();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.split_whitespace().any(|tok| tok == pid_token))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Detener un proceso de forma cooperativa y esperar a que salga.
///
/// Centraliza el shutdown loop de `cerberus stop` por plataforma:
/// - unix: SIGTERM (`kill -TERM`) → espera ≤5 s → SIGKILL si sigue vivo.
/// - windows: `taskkill /PID <pid>` **sin** `/F` (cierre cooperativo, el daemon
///   hace flush del store) → espera ≤ 5 s → `taskkill /PID <pid> /F` si sigue.
///
/// # Errors
///
/// Devuelve error si no se puede enviar la señal de parada ni forzar la salida.
pub(crate) fn stop_process_graceful(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        // SIGTERM → graceful shutdown (flush de auditoría) en el daemon.
        let result = StdCommand::new("kill").args(["-TERM", &pid.to_string()]).output();
        if let Err(e) = result {
            return Err(format!("cannot send SIGTERM: {e}"));
        }

        wait_for_process_exit(pid);

        if process_alive(pid) {
            // Fallback: SIGKILL (kill por defecto).
            let kill = StdCommand::new("kill").arg(pid.to_string()).output();
            if matches!(kill, Ok(o) if !o.status.success()) {
                return Err(format!("cannot force-kill daemon (PID {pid})"));
            }
        }
    }

    #[cfg(windows)]
    {
        // Graceful primero: taskkill SIN /F pide cierre cooperativo (el daemon
        // hace flush del store). Solo si sigue vivo tras la espera se fuerza /F.
        let graceful = StdCommand::new("taskkill").args(["/PID", &pid.to_string()]).output();
        let _ = graceful;

        wait_for_process_exit(pid);

        if process_alive(pid) {
            let hard = StdCommand::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .output();
            if !matches!(hard, Ok(o) if o.status.success()) {
                return Err(format!("cannot force-stop daemon (PID {pid})"));
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        return Err("unsupported platform".to_string());
    }

    Ok(())
}

/// Esperar (hasta ~5 s) a que el proceso salga. Loop de apagado compartido por
/// las ramas unix/windows de `stop_process_graceful`.
fn wait_for_process_exit(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guard para serializar los tests que mutan `std::env` (global del proceso).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn config_dir_is_not_empty() {
        let dir = config_dir();
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn log_dir_is_under_config() {
        let log = log_dir();
        assert!(log.to_string_lossy().contains("log"));
    }

    #[test]
    fn daemon_name_has_no_spaces() {
        let name = daemon_binary_name();
        assert!(!name.contains(' '));
        assert!(!name.is_empty());
    }

    /// En Windows el binario del daemon se reporta con extensión `.exe`.
    #[cfg(target_os = "windows")]
    #[test]
    fn daemon_binary_name_reports_exe_on_windows() {
        assert_eq!(daemon_binary_name(), "cerberus.exe");
    }

    /// En macOS/Linux el binario se reporta sin extensión.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn daemon_binary_name_without_extension_on_unix_like() {
        assert_eq!(daemon_binary_name(), "cerberus");
    }

    /// Windows: la config dir debe vivir bajo `%APPDATA%\Cerberus`.
    #[cfg(target_os = "windows")]
    #[test]
    fn config_dir_windows_uses_appdata() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let original = std::env::var("APPDATA").ok();
        std::env::set_var("APPDATA", "C:\\Users\\tester\\AppData\\Roaming");
        let dir = config_dir();
        assert_eq!(dir.to_string_lossy(), "C:\\Users\\tester\\AppData\\Roaming\\Cerberus");
        match original {
            Some(value) => std::env::set_var("APPDATA", value),
            None => std::env::remove_var("APPDATA"),
        }
    }

    /// Un PID imposible nunca es "vivo" en ninguna de las 3 plataformas.
    #[test]
    fn process_alive_false_for_garbage_pid() {
        assert!(!process_alive(u32::MAX));
    }

    /// El proceso actual siempre está vivo (smoke del `tasklist`/`kill -0`).
    #[test]
    fn process_alive_true_for_current_process() {
        assert!(process_alive(std::process::id()));
    }
}
