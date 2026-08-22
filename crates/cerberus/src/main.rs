//! Cerberus Local CLI — punto de entrada para el Modo B.
//!
//! Comandos disponibles:
//! - `init`: autodetecta agentes instalados y configura sus `*_BASE_URL`
//! - `start`: inicia el daemon local
//! - `stop`: detiene el daemon local
//! - `status`: estado del daemon
//! - `scan <file>`: escanea un archivo sin enviarlo
//! - `test <text>`: prueba detección con texto inline
//! - `doctor`: diagnóstico del sistema

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod cli_pack;
mod daemon;
mod feedback_ux;
mod init;
mod mitm;
mod packs;
mod platform;

/// Cerberus Local — cortafuegos de datos sensibles para agentes LLM.
#[derive(Parser)]
#[command(name = "cerberus", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Autodetecta agentes instalados y configura Cerberus
    Init {
        /// Ruta al directorio de configuración (default: el config dir por plataforma)
        #[arg(short, long)]
        config_dir: Option<String>,
    },
    /// Inicia el daemon local
    Start {
        /// Puerto de escucha (default: 8787)
        #[arg(short, long, default_value_t = 8787)]
        port: u16,
    },
    /// Detiene el daemon local
    Stop,
    /// Muestra el estado del daemon
    Status,
    /// Muestra la licencia activa (tier y expiración)
    License,
    /// Gestiona rule packs firmados (requiere licencia Pro)
    Pack {
        #[command(subcommand)]
        pack: PackCmd,
    },
    /// Gestiona el forward proxy TLS avanzado (siempre opt-in)
    Mitm {
        #[command(subcommand)]
        mitm: MitmCmd,
    },
    /// Escanea un archivo en busca de secretos
    Scan {
        /// Ruta al archivo a escanear
        file: String,
    },
    /// Prueba detección con texto inline
    Test {
        /// Texto a escanear
        text: String,
    },
    /// Diagnóstico del sistema
    Doctor,
}

/// Subcomandos de `cerberus pack` (F7: rule packs firmados).
#[derive(Subcommand)]
enum PackCmd {
    /// Instala un rule pack firmado (verifica `CERBERUS_PACK_TRUST_ROOT`)
    Install {
        /// Ruta al JSON firmado del pack
        file: String,
    },
    /// Lista los rule packs presentes en `~/.cerberus/packs`
    List,
    /// Revierte al engine anterior (última instalación)
    Rollback,
}

/// Subcomandos explícitos del modo forward proxy + CA local.
#[derive(Subcommand)]
enum MitmCmd {
    /// Muestra si el listener está habilitado y si la CA está lista
    Status,
    /// Genera una CA local; NO la instala ni confía automáticamente
    InitCa,
    /// Habilita el listener sólo para hosts DNS exactos
    Enable {
        /// Host autorizado; repetir para cada endpoint hardcodeado
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        /// Listener loopback separado del reverse proxy
        #[arg(long, default_value = "127.0.0.1:8788")]
        listen: String,
    },
    /// Deshabilita el listener sin borrar la CA
    Disable,
    /// Imprime instrucciones manuales; nunca modifica el trust store
    TrustInstructions,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    match cli.command {
        Command::Init { config_dir } => {
            let dir = config_dir.unwrap_or_else(|| platform::config_dir().to_string_lossy().to_string());
            let result = init::run_init(&dir);
            match result {
                Ok(summary) => {
                    println!("{summary}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("init failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Start { port } => match daemon::start(port).await {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("start failed: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Stop => match daemon::stop() {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("stop failed: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Status => {
            let msg = daemon::status();
            println!("{msg}");
            println!("{}", mitm::status());
            ExitCode::SUCCESS
        }
        Command::License => {
            let path = daemon::license_path();
            let mgr = daemon::load_license(Some(&path));
            println!("Licencia cargada desde: {}", path.display());
            println!("{}", daemon::license_summary(&mgr));
            ExitCode::SUCCESS
        }
        Command::Pack { pack } => {
            // Revisor v6 (P1): si el daemon está en marcha, el CLI es CLIENTE
            // del control plane HTTP — NO abre otro PackManager ni toca disco
            // (el worker del daemon es el único escritor del manifest). Solo
            // sin daemon (pid file ausente/muerto) se usa el modo local.
            if cli_pack::daemon_is_running() {
                match pack {
                    PackCmd::Install { file } => match cli_pack::install(&file).await {
                        Ok(msg) => {
                            println!("{msg}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("pack install failed: {e}");
                            ExitCode::FAILURE
                        }
                    },
                    PackCmd::List => match cli_pack::list().await {
                        Ok(msg) => {
                            println!("{msg}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("pack list failed: {e}");
                            ExitCode::FAILURE
                        }
                    },
                    PackCmd::Rollback => match cli_pack::rollback().await {
                        Ok(msg) => {
                            println!("{msg}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("pack rollback failed: {e}");
                            ExitCode::FAILURE
                        }
                    },
                }
            } else {
                match pack {
                    PackCmd::Install { file } => match daemon::pack_install(&file).await {
                        Ok(msg) => {
                            println!("{msg}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("pack install failed: {e}");
                            ExitCode::FAILURE
                        }
                    },
                    PackCmd::List => match daemon::pack_list() {
                        Ok(msg) => {
                            println!("{msg}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("pack list failed: {e}");
                            ExitCode::FAILURE
                        }
                    },
                    PackCmd::Rollback => match daemon::pack_rollback().await {
                        Ok(msg) => {
                            println!("{msg}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("pack rollback failed: {e}");
                            ExitCode::FAILURE
                        }
                    },
                }
            }
        }
        Command::Mitm { mitm: command } => {
            // F4: el enmadrado de `enable`/`disable` comprueba si el daemon
            // está en marcha. La config MITM se lee SOLO al arrancar y no hay
            // `/api/mitm` en caliente (el control plane es de otro agente):
            // si el daemon vive, el comando persiste la config y añade la nota
            // clara de "edita ~/.cerberus/mitm.json y reinicia".
            let daemon_running = crate::daemon::is_running();
            let result = match command {
                MitmCmd::Status => Ok(mitm::status()),
                MitmCmd::InitCa => mitm::init_ca(),
                MitmCmd::Enable { hosts, listen } => mitm::enable_with_daemon_state(&hosts, &listen, daemon_running),
                MitmCmd::Disable => mitm::disable_with_daemon_state(daemon_running),
                MitmCmd::TrustInstructions => Ok(mitm::trust_instructions()),
            };
            match result {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("mitm command failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Scan { file } => match init::scan_file(&file) {
            Ok(report) => {
                println!("{report}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("scan failed: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Test { text } => {
            let report = init::scan_text(&text);
            println!("{report}");
            ExitCode::SUCCESS
        }
        Command::Doctor => {
            let report = init::doctor();
            println!("{report}");
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn mitm_enable_requires_an_explicit_host() {
        assert!(Cli::try_parse_from(["cerberus", "mitm", "enable"]).is_err());
        let parsed = Cli::try_parse_from(["cerberus", "mitm", "enable", "--host", "api.openai.com"]).unwrap();
        match parsed.command {
            Command::Mitm {
                mitm: MitmCmd::Enable { hosts, listen },
            } => {
                assert_eq!(hosts, vec!["api.openai.com"]);
                assert_eq!(listen, "127.0.0.1:8788");
            }
            _ => panic!("wrong command parsed"),
        }
    }
}
