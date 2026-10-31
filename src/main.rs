#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("daemon-killer supports macOS and Windows only");

mod config;
mod controller;
mod daemon;
mod firewall;
mod health;
mod install;
mod platform;
mod policy;
mod status;
mod ui;
mod upstream;

use anyhow::{ensure, Result};
use clap::{Parser, Subcommand};
use platform::service;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Kill switch for the Clash TUN: when Clash stops, traffic stops",
    after_help = format!(
        "Get started: `daemon-killer install`, edit the config, then `daemon-killer up`.\n\
         Config: {}",
        platform::default_config_path().display()
    )
)]
struct Cli {
    /// The config always lives in the system location; this override is for tests.
    #[arg(short, long, global = true, hide = true, default_value_os_t = platform::default_config_path())]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show protection, Clash, firewall, config and service state
    Status,
    /// Turn protection on or apply a changed config; kept only once you confirm
    Up {
        #[arg(long, default_value_t = 60, hide = true)]
        confirm_secs: u64,
    },
    /// Turn protection off until the next `up`
    Down,
    /// Turn protection off for a few minutes, e.g. to log in to a captive portal
    Pause {
        #[arg(short, long, default_value_t = 5, value_name = "MIN")]
        minutes: u64,
    },
    /// Install or update the program and its background service; protection stays as it was
    Install,
    /// Turn protection off and remove the program and service; keeps the config
    Uninstall,
    /// Print the native rules the config produces (pf anchor / WFP filters); for debugging
    /// and the acceptance tests
    #[command(hide = true)]
    Rules,
    /// The enforcement loop, started by launchd / the service manager
    #[command(hide = true)]
    Run,
    /// Turns protection off unless `up` was confirmed in time
    #[command(hide = true)]
    Rollback {
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long)]
        seconds: u64,
    },
}

fn require_elevated() -> Result<()> {
    ensure!(
        platform::is_elevated(),
        if cfg!(windows) {
            "this command changes the system; run it in an administrator terminal"
        } else {
            "this command changes the system; run it with sudo"
        }
    );
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    platform::init_logging(matches!(cli.cmd, Cmd::Run | Cmd::Rollback { .. }));
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ui::error(&e);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let config = cli.config;
    match cli.cmd {
        Cmd::Status => status::status(&config),
        Cmd::Rules => status::rules(&config),
        Cmd::Up { confirm_secs } => {
            require_elevated()?;
            install::up(&config, confirm_secs)
        }
        Cmd::Down => {
            require_elevated()?;
            install::down(&config)
        }
        Cmd::Pause { minutes } => {
            require_elevated()?;
            install::pause(&config, minutes)
        }
        Cmd::Install => {
            require_elevated()?;
            install::install(&config)
        }
        Cmd::Uninstall => {
            require_elevated()?;
            install::uninstall(&config)
        }
        Cmd::Run => {
            require_elevated()?;
            service::run(move |stop| daemon::run(&config, stop))
        }
        Cmd::Rollback { ticket, seconds } => {
            require_elevated()?;
            service::run(move |_stop| install::rollback_watchdog(&config, &ticket, seconds))
        }
    }
}
