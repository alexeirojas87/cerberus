//! Cerberus Local CLI — entry point for Mode B.
//!
//! Command surface = **Appendix B** of `CERBERUS_PRODUCT_BUILD_PLAN.md`
//! (the CLI spec), wired to the control-plane Config API per §4.6: the CLI
//! and dashboard are two fronts over the same API; the daemon is the only
//! state writer. Local-only commands (init/scan/test/doctor/validate/
//! agents/config) do not require the daemon.
//!
//! Implemented in:
//! - `cli_api` — shared endpoint/token resolution + HTTP client;
//! - `cli_surface` — F6.B Appendix B commands (B.1–B.7);
//! - `cli_pack` — `pack`/`packs` install/list/rollback (v6 pattern);
//! - `daemon`, `init`, `mitm` — F4 units.

#![allow(unknown_lints)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod audit_key;
mod cli_api;
mod cli_pack;
mod cli_surface;
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
    /// Restarts the local daemon (stop + start on the same port)
    Restart {
        /// Listen port (default: the port the daemon was using)
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Shows the daemon status
    Status,
    /// Shows or changes the global operation mode (shadow = logs only)
    Mode {
        /// `shadow` or `enforce`; omit to show the current mode
        mode: Option<String>,
    },
    /// Break-glass: lets the NEXT blocked send through (audited, hash-only)
    AllowOnce {
        /// Why the bypass was needed (audited, stored hashed)
        #[arg(long)]
        reason: Option<String>,
    },
    /// Prints the version (same string as `cerberus --version`)
    Version,
    /// Checks for a newer release and prints the upgrade command
    Upgrade {
        /// Releases manifest URL (default: the official channel;
        /// overridable via `CERBERUS_RELEASES_URL` for staging)
        #[arg(long)]
        manifest_url: Option<String>,
    },
    /// Shows the active license (tier and expiration)
    License,
    /// Installs a signed Pro license and activates entitlements
    Login {
        /// Path to the signed license file
        #[arg(short, long)]
        file: String,
    },
    /// Manages signed rule packs (list/install/rollback; Pro for install)
    Pack {
        #[command(subcommand)]
        pack: PackCmd,
    },
    /// Manages signed rule packs: list, enable, disable, update (Appendix B B.3)
    Packs {
        #[command(subcommand)]
        packs: PacksCmd,
    },
    /// Lists detected agents and their config status
    Agents {
        #[command(subcommand)]
        agents: Option<AgentsCmd>,
    },
    /// Lists configured upstreams (providers)
    Providers,
    /// Registers a custom upstream and prints the local base URL to paste
    AddProvider {
        /// Provider name (used in the local route: `http://127.0.0.1:8787/<name>`)
        name: String,
        /// Upstream base URL (e.g. `https://api.nan.builders/v1`)
        #[arg(long)]
        url: String,
        /// Non-standard auth header the upstream expects (e.g. x-api-key)
        #[arg(long)]
        auth_header: Option<String>,
    },
    /// Removes an upstream
    RemoveProvider {
        /// Provider name to remove
        name: String,
    },
    /// Sets the action for a detection category (secrets|pii|...)
    Category {
        #[command(subcommand)]
        category: CategoryCmd,
    },
    /// Lists effective rules (base + overrides + custom)
    Rules {
        #[command(subcommand)]
        rules: RulesCmd,
    },
    /// Manages the false-positive allowlist (fingerprints only, R9-7)
    Allowlist {
        #[command(subcommand)]
        allowlist: AllowlistCmd,
    },
    /// Lists filterable audit events (block/redact/warn)
    Events {
        /// Filter by upstream provider (e.g. openai)
        #[arg(long)]
        provider: Option<String>,
        /// Filter by originating tool (e.g. claude-code)
        #[arg(long)]
        tool: Option<String>,
        /// Events since: epoch seconds, RFC 3339, or relative (90s/30m/2h/1d)
        #[arg(long)]
        since: Option<String>,
    },
    /// Aggregate statistics; `--by provider` gives the per-upstream breakdown
    Stats {
        /// Grouping: provider | tool | flag
        #[arg(long)]
        by: Option<String>,
    },
    /// Daemon logs (no secrets); -f follows the file
    Logs {
        /// Follow the log file until interrupted
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// Views the config file (admin token redacted)
    Config {
        #[command(subcommand)]
        config: ConfigCmd,
    },
    /// Opens the local dashboard UI
    Dashboard,
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
    /// Validates a config file before deploying (syntax, patterns, policy)
    Validate {
        /// Config file to validate
        #[arg(short = 'f', long)]
        file: String,
    },
    /// Forces a hot-reload of the on-disk config on the running daemon
    Reload,
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

/// `cerberus packs` — Appendix B B.3 surface. `list`/`install`/`rollback`
/// are compatibility aliases of `pack` (fix-plan F6.4: normalize `pack` vs
/// `packs`); `enable`/`disable`/`update` are B.3-only.
#[derive(Subcommand)]
enum PacksCmd {
    /// Lists the rule packs present in `~/.cerberus/packs`
    List,
    /// Installs a signed rule pack (alias of `pack install`)
    Install {
        /// Path to the signed pack JSON
        file: String,
    },
    /// Reverts to the previous engine (alias of `pack rollback`)
    Rollback,
    /// Enables a disabled pack (rules return to the engine, hot-reload)
    Enable {
        /// Pack name (e.g. aws)
        pack: String,
    },
    /// Disables a pack (its rules leave the engine; the pack stays installed)
    Disable {
        /// Pack name (e.g. aws)
        pack: String,
    },
    /// Re-verifies installed pack signatures and hot-reloads (registry
    /// auto-update is the F7 unit)
    Update,
}

/// `cerberus agents` subcommands (B.2); no subcommand = list.
#[derive(Subcommand)]
enum AgentsCmd {
    /// Routes an agent through Cerberus (prints the export line)
    Wire {
        /// Agent name (e.g. opencode, "Claude Code")
        agent: String,
    },
    /// Unroutes an agent (prints the restore line)
    Unwire {
        /// Agent name
        agent: String,
    },
}

/// `cerberus category set <cat> --action <a>` (B.3).
#[derive(Subcommand)]
enum CategoryCmd {
    /// Sets the action for a category
    Set {
        /// Category (`secrets`|`pii`|`internal_code`|`credentials`|...)
        category: String,
        /// Action (block|redact|warn|allow)
        #[arg(long)]
        action: String,
    },
}

/// `cerberus rules` subcommands (B.3).
#[derive(Subcommand)]
enum RulesCmd {
    /// Lists effective rules
    List,
    /// Adds a custom rule from a YAML file
    Add {
        /// Path to the rule file (single rule or a list)
        #[arg(long)]
        file: String,
    },
    /// Overrides the action of one rule
    Set {
        /// Rule flag (e.g. `secret.openai_api_key`)
        flag: String,
        /// Action (block|redact|warn|allow)
        #[arg(long)]
        action: String,
    },
}

/// `cerberus allowlist` subcommands (B.3). Raw values travel once to the
/// daemon and are persisted as HMAC fingerprints only (R9-7).
#[derive(Subcommand)]
enum AllowlistCmd {
    /// Adds a value (persisted as a fingerprint; never echoed back)
    Add {
        /// The false-positive value
        value: String,
    },
    /// Lists entries (fingerprints only — raw values are not recoverable)
    List,
    /// Removes a value (or an exact fingerprint)
    Remove {
        /// The value (or fingerprint) to remove
        value: String,
    },
}

/// `cerberus config` subcommands (B.6).
#[derive(Subcommand)]
enum ConfigCmd {
    /// Views the config file (admin token redacted)
    Show,
    /// Opens $EDITOR on the config file, then validates it
    Edit,
    /// Prints the config file location
    Path,
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
    // R9-10 (F5.1): non-blocking logging — events go through a bounded,
    // lossy, off-thread writer; a slow/blocked console can never stall the
    // request hot path. The guard is held for the whole process lifetime and
    // dropped at exit → bounded drain + final flush (no log loss on
    // graceful shutdown).
    // F6.B (B.5): `cerberus start` ALSO tees the stream to the daemon log
    // file so `cerberus logs [-f]` can read it from another process. The
    // tee must be requested BEFORE the subscriber installs its worker sink.
    if matches!(cli.command, Command::Start { .. }) && !cerberus_proxy::log::set_log_tee_file(&daemon::log_file_path())
    {
        eprintln!(
            "warning: daemon log file unavailable at {} — console-only logging",
            daemon::log_file_path().display()
        );
    }
    let _log_guard = cerberus_proxy::log::init_logging("info");
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
        Command::Restart { port } => match cli_surface::restart(port).await {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("restart failed: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Status => {
            let msg = cli_surface::status_detail().await;
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Command::Mode { mode } => print_result(cli_surface::set_mode(mode).await, "mode"),
        Command::AllowOnce { reason } => print_result(cli_surface::allow_once(reason).await, "allow-once"),
        Command::Version => {
            println!("{}", cli_surface::version());
            ExitCode::SUCCESS
        }
        Command::Upgrade { manifest_url } => print_result(cli_surface::upgrade_check(manifest_url).await, "upgrade"),
        Command::License => {
            let path = daemon::license_path();
            let mgr = daemon::load_license(Some(&path));
            println!("License loaded from: {}", path.display());
            println!("{}", daemon::license_summary(&mgr));
            ExitCode::SUCCESS
        }
        Command::Login { file } => match cli_surface::login(&file) {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("login failed: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Pack { pack } => run_pack(pack).await,
        Command::Packs { packs } => run_packs(packs).await,
        Command::Agents { agents } => match agents {
            None => {
                println!("{}", cli_surface::agents_list());
                ExitCode::SUCCESS
            }
            Some(AgentsCmd::Wire { agent }) => match cli_surface::agent_wire(&agent) {
                Ok(msg) => {
                    println!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("agents wire failed: {e}");
                    ExitCode::FAILURE
                }
            },
            Some(AgentsCmd::Unwire { agent }) => match cli_surface::agent_unwire(&agent) {
                Ok(msg) => {
                    println!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("agents unwire failed: {e}");
                    ExitCode::FAILURE
                }
            },
        },
        Command::Providers => print_result(cli_surface::providers_list().await, "providers"),
        Command::AddProvider { name, url, auth_header } => print_result(
            cli_surface::add_provider(&name, &url, auth_header).await,
            "add-provider",
        ),
        Command::RemoveProvider { name } => print_result(cli_surface::remove_provider(&name).await, "remove-provider"),
        Command::Category { category } => match category {
            CategoryCmd::Set { category, action } => {
                print_result(cli_surface::category_set(&category, &action).await, "category set")
            }
        },
        Command::Rules { rules } => match rules {
            RulesCmd::List => print_result(cli_surface::rules_list().await, "rules list"),
            RulesCmd::Add { file } => print_result(cli_surface::rules_add(&file).await, "rules add"),
            RulesCmd::Set { flag, action } => print_result(cli_surface::rules_set(&flag, &action).await, "rules set"),
        },
        Command::Allowlist { allowlist } => match allowlist {
            AllowlistCmd::Add { value } => print_result(cli_surface::allowlist_add(&value).await, "allowlist add"),
            AllowlistCmd::List => print_result(cli_surface::allowlist_list().await, "allowlist list"),
            AllowlistCmd::Remove { value } => {
                print_result(cli_surface::allowlist_remove(&value).await, "allowlist remove")
            }
        },
        Command::Events { provider, tool, since } => {
            print_result(cli_surface::events(provider, tool, since).await, "events")
        }
        Command::Stats { by } => print_result(cli_surface::stats(by).await, "stats"),
        Command::Logs { follow } => match cli_surface::logs(follow) {
            Ok(extra) => {
                if !follow && extra.is_empty() {
                    // `logs` already printed the tail; nothing else to print.
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("logs failed: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Config { config } => match config {
            ConfigCmd::Show => match cli_surface::config_show() {
                Ok(msg) => {
                    println!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("config show failed: {e}");
                    ExitCode::FAILURE
                }
            },
            ConfigCmd::Edit => match cli_surface::config_edit() {
                Ok(msg) => {
                    println!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("config edit failed: {e}");
                    ExitCode::FAILURE
                }
            },
            ConfigCmd::Path => {
                println!("{}", cli_surface::config_path());
                ExitCode::SUCCESS
            }
        },
        Command::Dashboard => {
            println!("{}", cli_surface::dashboard());
            ExitCode::SUCCESS
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
        Command::Validate { file } => match cli_surface::validate(&file) {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        Command::Reload => print_result(cli_surface::reload().await, "reload"),
        Command::Doctor => {
            let report = init::doctor();
            println!("{report}");
            ExitCode::SUCCESS
        }
    }
}

/// `cerberus pack` dispatch (v6 pattern): with a live daemon the CLI is a
/// CLIENT of the control plane; without one it runs the local path.
#[allow(clippy::too_many_lines)]
async fn run_pack(pack: PackCmd) -> ExitCode {
    if cli_pack::daemon_is_running() {
        match pack {
            PackCmd::Install { file } => print_result(cli_pack::install(&file).await, "pack install"),
            PackCmd::List => print_result(cli_pack::list().await, "pack list"),
            PackCmd::Rollback => print_result(cli_pack::rollback().await, "pack rollback"),
        }
    } else {
        match pack {
            PackCmd::Install { file } => print_result(daemon::pack_install(&file).await, "pack install"),
            PackCmd::List => print_result(daemon::pack_list(), "pack list"),
            PackCmd::Rollback => print_result(daemon::pack_rollback().await, "pack rollback"),
        }
    }
}

/// `cerberus packs` dispatch: aliases share the `pack` paths; the B.3-only
/// enable/disable/update are daemon-backed commands (they need the worker).
async fn run_packs(packs: PacksCmd) -> ExitCode {
    match packs {
        PacksCmd::Install { file } => run_pack(PackCmd::Install { file }).await,
        PacksCmd::List => run_pack(PackCmd::List).await,
        PacksCmd::Rollback => run_pack(PackCmd::Rollback).await,
        PacksCmd::Enable { pack } => print_result(cli_surface::packs_enable(&pack).await, "packs enable"),
        PacksCmd::Disable { pack } => print_result(cli_surface::packs_disable(&pack).await, "packs disable"),
        PacksCmd::Update => print_result(cli_surface::packs_update().await, "packs update"),
    }
}

/// Print an `Ok` message or an `Err` to stderr; returns the matching exit code.
fn print_result(result: Result<String, String>, what: &str) -> ExitCode {
    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{what} failed: {e}");
            ExitCode::FAILURE
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

    /// `cerberus version` parses (fix-plan F6.4: `version` in addition to
    /// `--version`).
    #[test]
    fn version_subcommand_parses() {
        let parsed = Cli::try_parse_from(["cerberus", "version"]).unwrap();
        assert!(matches!(parsed.command, Command::Version));
    }

    /// Appendix B B.1: restart / mode / allow-once parse with their flags.
    #[test]
    fn b1_lifecycle_commands_parse() {
        assert!(matches!(
            Cli::try_parse_from(["cerberus", "restart"]).unwrap().command,
            Command::Restart { port: None }
        ));
        let mode = Cli::try_parse_from(["cerberus", "mode", "shadow"]).unwrap();
        match mode.command {
            Command::Mode { mode } => assert_eq!(mode.as_deref(), Some("shadow")),
            _ => panic!("mode did not parse"),
        }
        let allow = Cli::try_parse_from(["cerberus", "allow-once", "--reason", "demo cutover"]).unwrap();
        match allow.command {
            Command::AllowOnce { reason } => assert_eq!(reason.as_deref(), Some("demo cutover")),
            _ => panic!("allow-once --reason did not parse"),
        }
        let bare = Cli::try_parse_from(["cerberus", "allow-once"]).unwrap();
        assert!(matches!(bare.command, Command::AllowOnce { reason: None }));
    }

    /// Appendix B B.2: agents/wire/unwire + provider CRUD parse.
    #[test]
    fn b2_agent_and_provider_commands_parse() {
        assert!(matches!(
            Cli::try_parse_from(["cerberus", "agents"]).unwrap().command,
            Command::Agents { agents: None }
        ));
        let wire = Cli::try_parse_from(["cerberus", "agents", "wire", "opencode"]).unwrap();
        match wire.command {
            Command::Agents {
                agents: Some(AgentsCmd::Wire { agent }),
            } => assert_eq!(agent, "opencode"),
            _ => panic!("wire did not parse"),
        }
        let add = Cli::try_parse_from([
            "cerberus",
            "add-provider",
            "nanbuilders",
            "--url",
            "https://api.nan.builders/v1",
        ])
        .unwrap();
        match add.command {
            Command::AddProvider { name, url, auth_header } => {
                assert_eq!(name, "nanbuilders");
                assert_eq!(url, "https://api.nan.builders/v1");
                assert!(auth_header.is_none());
            }
            _ => panic!("add-provider did not parse"),
        }
        let add2 = Cli::try_parse_from([
            "cerberus",
            "add-provider",
            "nanbuilders",
            "--url",
            "https://x.example/v1",
            "--auth-header",
            "x-api-key",
        ])
        .unwrap();
        match add2.command {
            Command::AddProvider { auth_header, .. } => assert_eq!(auth_header.as_deref(), Some("x-api-key")),
            _ => panic!("add-provider --auth-header did not parse"),
        }
        let rm = Cli::try_parse_from(["cerberus", "remove-provider", "nanbuilders"]).unwrap();
        match rm.command {
            Command::RemoveProvider { name } => assert_eq!(name, "nanbuilders"),
            _ => panic!("remove-provider did not parse"),
        }
    }

    /// Appendix B B.3: packs enable/disable/update, category set, rules,
    /// allowlist all parse (parity test, leg CLI).
    #[test]
    fn b3_policy_commands_parse() {
        for args in [
            vec!["cerberus", "packs", "list"],
            vec!["cerberus", "packs", "enable", "aws"],
            vec!["cerberus", "packs", "disable", "aws"],
            vec!["cerberus", "packs", "update"],
            vec!["cerberus", "packs", "install", "p.json"],
            vec!["cerberus", "packs", "rollback"],
            vec!["cerberus", "pack", "list"],
            vec!["cerberus", "category", "set", "secrets", "--action", "block"],
            vec!["cerberus", "rules", "list"],
            vec!["cerberus", "rules", "add", "--file", "rule.yaml"],
            vec!["cerberus", "rules", "set", "secret.x", "--action", "redact"],
            vec!["cerberus", "allowlist", "add", "sk-EXAMPLE"],
            vec!["cerberus", "allowlist", "list"],
            vec!["cerberus", "allowlist", "remove", "sk-EXAMPLE"],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "must parse: {args:?}");
        }
    }

    /// Appendix B B.5/B.6/B.7: events/stats/logs/config/login/dashboard/
    /// validate/reload all parse.
    #[test]
    fn b5_b6_b7_commands_parse() {
        for args in [
            vec!["cerberus", "events"],
            vec![
                "cerberus",
                "events",
                "--provider",
                "openai",
                "--tool",
                "claude-code",
                "--since",
                "30m",
            ],
            vec!["cerberus", "stats"],
            vec!["cerberus", "stats", "--by", "provider"],
            vec!["cerberus", "logs"],
            vec!["cerberus", "logs", "-f"],
            vec!["cerberus", "config", "show"],
            vec!["cerberus", "config", "edit"],
            vec!["cerberus", "config", "path"],
            vec!["cerberus", "login", "--file", "license.json"],
            vec!["cerberus", "dashboard"],
            vec!["cerberus", "validate", "-f", "cerberus.yaml"],
            vec!["cerberus", "reload"],
            vec!["cerberus", "upgrade"],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "must parse: {args:?}");
        }
    }

    /// THE PARITY TEST (CI-runnable, fix-plan F6.4 / acceptance #2): every
    /// Appendix B command that needs the daemon maps to an endpoint that
    /// EXISTS in the control-plane route table (`known_api_routes`). The
    /// full API→CLI→dashboard matrix lives in `evidence/f6/parity-matrix.md`;
    /// this test keeps the CLI↔API legs of every row honest.
    #[test]
    fn every_daemon_backed_cli_command_maps_to_a_real_api_route() {
        // (CLI label, method, endpoint) — one row per daemon-backed command.
        let daemon_backed: &[(&str, &str, &str)] = &[
            ("mode show", "GET", "/api/config"),
            ("mode set", "PUT", "/api/config"),
            ("allow-once", "POST", "/api/break-glass"),
            ("providers", "GET", "/api/upstreams"),
            ("add-provider", "POST", "/api/upstreams"),
            ("remove-provider", "DELETE", "/api/upstreams/{name}"),
            ("packs list", "GET", "/api/packs"),
            ("packs install", "POST", "/api/packs/install"),
            ("packs rollback", "POST", "/api/packs/rollback"),
            ("packs enable", "POST", "/api/packs/enable"),
            ("packs disable", "POST", "/api/packs/disable"),
            ("packs update", "POST", "/api/packs/update"),
            ("category set", "PUT", "/api/policy"),
            ("rules list", "GET", "/api/policy"),
            ("rules add", "PUT", "/api/policy"),
            ("rules set", "PUT", "/api/policy"),
            ("allowlist add", "POST", "/api/allowlist"),
            ("allowlist list", "GET", "/api/allowlist"),
            ("allowlist remove", "DELETE", "/api/allowlist"),
            ("events", "GET", "/api/events"),
            ("stats", "GET", "/api/stats"),
            ("config show (dashboard view)", "GET", "/api/config"),
            ("reload", "POST", "/api/reload"),
            ("dashboard", "GET", "/ui"),
        ];
        for (label, method, path) in daemon_backed {
            assert!(
                cerberus_proxy::api::is_known_api_route(method, path),
                "parity: CLI '{label}' maps to {method} {path}, which is NOT in the route table"
            );
        }
    }
}
