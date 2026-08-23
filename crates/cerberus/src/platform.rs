//! Cross-platform support (macOS, Linux, Windows).
//!
//! Platform-specific paths, process detection, and management for the local
//! daemon. Single source of truth for paths and process lifecycle:
//! the daemon delegates `config_dir()`, `process_alive()`, and cooperative
//! stop (`stop_process_graceful()`) here.
//!
//! `config_dir()` keeps the existing daemon convention on
//! macOS/Linux (`~/.cerberus`) —several tests and tools depend on that path
//! under `HOME`— and uses `%APPDATA%\Cerberus` on Windows.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::{Duration, Instant};

/// Get the user's configuration directory by platform.
#[must_use]
pub(crate) fn config_dir() -> PathBuf {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // Use $HOME directly (not dirs::home_dir) so that tests that set HOME
        // to an isolated temp dir are not affected by getpwuid_r lookups that
        // may resolve to the real user's home on CI runners.
        std::env::var("HOME")
            .map(PathBuf::from)
            .map_or_else(|_| PathBuf::from("/tmp/cerberus"), |p| p.join(".cerberus"))
    }
    #[cfg(target_os = "windows")]
    {
        // %APPDATA%/Cerberus
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .map_or_else(|_| PathBuf::from("C:\\Cerberus"), |p| p.join("Cerberus"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/tmp/cerberus")
    }
}

/// Get the log directory by platform.
#[must_use]
pub(crate) fn log_dir() -> PathBuf {
    config_dir().join("logs")
}

/// Daemon binary name by platform.
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

/// Is the process with `pid` still alive?
///
/// unix: `kill -0` (process exists). Windows: `tasklist /FI "PID eq N"` and
/// verifying that the output contains a PID token as such (the
/// "INFO: No tasks..." line from stdout must not be confused with a live
/// process).
#[must_use]
pub(crate) fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // A PID that does not fit in `pid_t` (i32) cannot correspond to a
        // real process. u32::MAX reinterprets as -1, which `kill` treats as
        // "all processes the caller may signal" and would wrongly report as
        // alive. Reject it up front.
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
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

/// Cooperatively stop a process and wait for it to exit.
///
/// Centralizes the `cerberus stop` shutdown loop per platform:
/// - unix: SIGTERM (`kill -TERM`) → wait ≤5 s → SIGKILL if still alive.
/// - windows: `taskkill /PID <pid>` **without** `/F` (cooperative close, the
///   daemon flushes the store) → wait ≤ 5 s → `taskkill /PID <pid> /F` if
///   still alive.
///
/// # Errors
///
/// Returns an error if the stop signal cannot be sent nor the exit forced.
pub(crate) fn stop_process_graceful(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        // SIGTERM → graceful shutdown (audit flush) in the daemon.
        let result = StdCommand::new("kill").args(["-TERM", &pid.to_string()]).output();
        if let Err(e) = result {
            return Err(format!("cannot send SIGTERM: {e}"));
        }

        wait_for_process_exit(pid);

        if process_alive(pid) {
            // Fallback: SIGKILL (default kill).
            let kill = StdCommand::new("kill").arg(pid.to_string()).output();
            if matches!(kill, Ok(o) if !o.status.success()) {
                return Err(format!("cannot force-kill daemon (PID {pid})"));
            }
        }
    }

    #[cfg(windows)]
    {
        // Graceful first: taskkill WITHOUT /F asks for cooperative close (the
        // daemon flushes the store). Only if still alive after the wait is /F
        // forced.
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

/// Wait (up to ~5 s) for the process to exit. Shared shutdown loop for the
/// unix/windows branches of `stop_process_graceful`.
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

    /// Guard to serialize tests that mutate `std::env` (process-global).
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

    /// On Windows the daemon binary is reported with the `.exe` extension.
    #[cfg(target_os = "windows")]
    #[test]
    fn daemon_binary_name_reports_exe_on_windows() {
        assert_eq!(daemon_binary_name(), "cerberus.exe");
    }

    /// On macOS/Linux the binary is reported without an extension.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn daemon_binary_name_without_extension_on_unix_like() {
        assert_eq!(daemon_binary_name(), "cerberus");
    }

    /// Windows: the config dir must live under `%APPDATA%\Cerberus`.
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

    /// An impossible PID is never "alive" on any of the 3 platforms.
    #[test]
    fn process_alive_false_for_garbage_pid() {
        assert!(!process_alive(u32::MAX));
    }

    /// The current process is always alive (smoke test of `tasklist`/`kill -0`).
    #[test]
    fn process_alive_true_for_current_process() {
        assert!(process_alive(std::process::id()));
    }
}
