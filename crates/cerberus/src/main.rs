//! Cerberus Local CLI — entry point for Mode B.
//!
//! Available commands:
//! - `init`: auto-detects installed agents and configures their `*_BASE_URL`
//! - `start`: starts the local daemon
//! - `stop`: stops the local daemon
//! - `status`: daemon status
//! - `scan <file>`: scans a file without sending it
//! - `test <text>`: test detection with inline text
//! - `doctor`: system diagnostics

#![allow(unknown_lints)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod cli_pack;
mod daemon;
mod feedback_ux;
mod init;
mod mitm;
mod packs;
mod platform;

/// Cerberus Local — sensitive-data firewall for LLM agents.
#[derive(Parser)]
#[command(name = "cerberus", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Auto-detects installed agents and configures Cerberus
    Init {
        /// Path to the configuration directory (default: the platform config dir)
        #[arg(short, long)]
        config_dir: Option<String>,
    },
    /// Starts the local daemon
    Start {
        /// Listen port (default: 8787)
        #[arg(short, long, default_value_t = 8787)]
        port: u16,
        /// Chain to another local proxy (e.g. headroom): all upstreams are
        /// rewritten to forward to this URL instead of the provider directly.
        /// Example: `--chain http://127.0.0.1:8788`
        #[arg(long)]
        chain: Option<String>,
    },
    /// Stops the local daemon
    Stop,
    /// Shows the daemon status
    Status,
    /// Shows the active license (tier and expiration)
    License,
    /// Manages signed rule packs (requires Pro license)
    Pack {
        #[command(subcommand)]
        pack: PackCmd,
    },
    /// Manages the advanced TLS forward proxy (always opt-in)
    Mitm {
        #[command(subcommand)]
        mitm: MitmCmd,
    },
    /// Scans a file for secrets
    Scan {
        /// Path to the file to scan
        file: String,
    },
    /// Tests detection with inline text
    Test {
        /// Text to scan
        text: String,
    },
    /// System diagnostics
    Doctor,
}

/// `cerberus pack` subcommands (F7: signed rule packs).
#[derive(Subcommand)]
enum PackCmd {
    /// Installs a signed rule pack (verifies `CERBERUS_PACK_TRUST_ROOT`)
    Install {
        /// Path to the signed pack JSON
        file: String,
    },
    /// Lists the rule packs present in `~/.cerberus/packs`
    List,
    /// Reverts to the previous engine (last install)
    Rollback,
}

/// Explicit subcommands for forward proxy mode + local CA.
#[derive(Subcommand)]
enum MitmCmd {
    /// Shows whether the listener is enabled and the CA is ready
    Status,
    /// Generates a local CA; does NOT install or trust it automatically
    InitCa,
    /// Enables the listener only for exact DNS hosts
    Enable {
        /// Authorized host; repeat for each hardcoded endpoint
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        /// Loopback listener separate from the reverse proxy
        #[arg(long, default_value = "127.0.0.1:8788")]
        listen: String,
    },
    /// Disables the listener without deleting the CA
    Disable,
    /// Prints manual instructions; never modifies the trust store
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
        Command::Start { port, chain } => match daemon::start(port, chain).await {
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
            println!("License loaded from: {}", path.display());
            println!("{}", daemon::license_summary(&mgr));
            ExitCode::SUCCESS
        }
        Command::Pack { pack } => {
            // Reviewer v6 (P1): if the daemon is running, the CLI is a CLIENT
            // of the HTTP control plane — it does NOT open another PackManager
            // nor touch disk (the daemon's worker is the only manifest
            // writer). Only without a daemon (pid file missing/dead) is local
            // mode used.
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
            // F4: the wiring of `enable`/`disable` checks whether the daemon
            // is running. The MITM config is read ONLY at boot and there is no
            // `/api/mitm` at runtime (the control plane is another agent's):
            // if the daemon is live, the command persists the config and adds
            // the clear note "edit ~/.cerberus/mitm.json and restart".
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
