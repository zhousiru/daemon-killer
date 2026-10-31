//! Commands that change the system. `install`/`uninstall` manage the program and its service
//! and never touch the network; `up`/`down`/`pause` switch protection. `up` keeps it only
//! after the user confirms, with a rollback guard that survives the CLI being killed.

use crate::config::{Config, Egress};
use crate::daemon::{self, Mode};
use crate::firewall::Firewall;
use crate::platform::{self, service, DaemonState};
use crate::policy::Policy;
use crate::ui::{self, Mark};
use crate::{firewall, health, upstream};
use anstream::println;
use anyhow::{bail, ensure, Context, Result};
use std::io::BufRead;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn install(config_path: &Path) -> Result<()> {
    let config_dir = config_path.parent().context("config path has no parent")?;
    // Only lock down our own directory, never a user-chosen one recursively.
    if config_path == platform::default_config_path() {
        platform::secure_dir(config_dir)?;
    } else {
        std::fs::create_dir_all(config_dir)?;
    }
    let wrote_example = !config_path.exists();
    if wrote_example {
        std::fs::write(config_path, platform::EXAMPLE_CONFIG)?;
    }
    let loaded = Config::load(config_path);
    let state_dir = loaded
        .as_ref()
        .map_or_else(|_| platform::default_state_dir(), |c| c.state_dir.clone());
    platform::secure_dir(&state_dir)?;
    let upgrade = service::daemon_state() != DaemonState::NotInstalled;

    ui::heading(&format!(
        "{} daemon-killer {}",
        if upgrade { "Updating" } else { "Installing" },
        env!("CARGO_PKG_VERSION")
    ));
    // Kernel rules outlive the daemon, so stopping it leaves protection as it is.
    service::stop();
    let replaced = service::install_binary().and_then(|bin| {
        // Not canonicalize: on Windows that yields `\\?\` paths in the service arguments.
        service::register(&bin, &std::path::absolute(config_path)?)?;
        service::restart()?;
        Ok(bin)
    });
    let bin = match replaced {
        Ok(bin) => bin,
        // A stopped daemon repairs no drift and ends no pause; bring back what is in place.
        Err(e) if upgrade && service::restart().is_ok() => {
            return Err(e.context("update failed; the service runs again with the files in place"))
        }
        Err(e) => return Err(e),
    };
    ui::row("Program", Mark::Ok, &bin.display().to_string(), "");
    match service::add_to_path() {
        Ok(true) => ui::row("PATH", Mark::Ok, "added", "open a new terminal to use it"),
        Ok(false) => {}
        Err(e) => ui::row("PATH", Mark::Warn, "not changed", &format!("{e:#}")),
    }
    ui::row("Service", Mark::Ok, "running", "starts at boot");
    let shown = config_path.display().to_string();
    match &loaded {
        _ if wrote_example => ui::row("Config", Mark::Warn, "example written", &shown),
        Ok(_) => ui::row("Config", Mark::Ok, "valid", &shown),
        Err(e) => ui::row("Config", Mark::Bad, "invalid", &format!("{e:#}")),
    }

    let ready = loaded.is_ok() && !wrote_example;
    match daemon::mode(&state_dir).unwrap_or(Mode::Up) {
        Mode::Up if ready => ui::outcome(Mark::Ok, "Installed; protection stays on"),
        Mode::Up => {
            ui::outcome(
                Mark::Warn,
                "Installed; protection is on, but with the config invalid the daemon only keeps the current rules",
            );
            ui::hint("Fix it", &shown);
            ui::hint("Then apply it", "daemon-killer up");
        }
        Mode::Down => {
            ui::outcome(Mark::Ok, "Installed; protection is off");
            if !ready {
                ui::hint("Edit the config", &shown);
            }
            ui::hint("Turn protection on", "daemon-killer up");
        }
    }
    Ok(())
}

pub fn up(config_path: &Path, confirm_secs: u64) -> Result<()> {
    if service::daemon_state() == DaemonState::NotInstalled {
        bail!("daemon-killer is not installed; run `daemon-killer install` first");
    }
    let cfg = Config::load(config_path)?;
    if resume(config_path, &cfg)? {
        return Ok(());
    }

    ui::heading("Turning protection on");
    ui::row(
        "Config",
        Mark::Ok,
        "valid",
        &config_path.display().to_string(),
    );
    let h = health::check(&cfg);
    ensure!(
        h.ok(),
        "Clash is not healthy ({}); turning protection on now would cut the network",
        h.detail(&cfg)
    );
    ui::row("Clash", Mark::Ok, "healthy", &h.detail(&cfg));
    platform::secure_dir(&cfg.state_dir)?;
    let ups = upstream::refresh(&cfg, true);
    if cfg.egress == Egress::Strict {
        ensure!(
            ups.unresolved.is_empty(),
            "strict mode but these upstreams did not resolve: {}",
            ups.unresolved.join(", ")
        );
    }
    let fw = firewall::native(&cfg);
    fw.validate(&Policy::build(&cfg, &ups.nets))?;
    let nets = match cfg.egress {
        Egress::Strict => format!("{} upstream nets", ups.nets.len()),
        Egress::Core => String::new(),
    };
    ui::row("Rules", Mark::Ok, "verified", &nets);

    let bin = service::binary_path();
    // Not canonicalize: on Windows that yields `\\?\` paths in the service arguments.
    let config = std::path::absolute(config_path)?;
    let ticket = cfg
        .state_dir
        .join(format!("up-pending-{}", std::process::id()));
    std::fs::write(&ticket, "pending")?;
    let guard = service::start_guard(&bin, &config, &ticket, confirm_secs.saturating_add(20))?;
    let rollback = |why: &str| -> Result<()> {
        turn_off(&cfg)?;
        let _ = std::fs::remove_file(&ticket);
        bail!("{why}; protection is off again")
    };
    daemon::set_mode(&cfg.state_dir, Mode::Up)?;
    daemon::clear_report(&cfg.state_dir);
    // Re-register too: it picks up a config at a different path.
    let started = service::register(&bin, &config).and_then(|()| service::restart());
    if let Err(e) = started {
        let r = rollback(&format!("starting the service failed: {e:#}"));
        service::stop_guard(guard);
        return r;
    }
    if !wait_for(Duration::from_secs(15), || blocking(&fw, &cfg)) {
        let r = rollback(&format!(
            "the daemon did not start blocking within 15s (log: {})",
            service::log_path().display()
        ));
        service::stop_guard(guard);
        return r;
    }
    ui::row(
        "Firewall",
        Mark::Ok,
        "blocking",
        &format!("host traffic uses {}", cfg.tun_device),
    );

    println!();
    println!("Check that the network still works, e.g. open a website.");
    ui::prompt(&format!(
        "Keep protection on? Type yes within {confirm_secs}s, anything else turns it off:"
    ));
    let kept = wait_for_yes(Duration::from_secs(confirm_secs));
    if !kept {
        println!();
        let r = rollback("not confirmed");
        service::stop_guard(guard);
        return r;
    }
    std::fs::remove_file(&ticket)?;
    service::stop_guard(guard);
    ui::outcome(Mark::Ok, "Protection is on");
    ui::hint("Pause it for a captive portal", "daemon-killer pause");
    Ok(())
}

/// Already on with this very config: end a pause, nothing to verify or confirm again.
/// Returns whether that settled it.
fn resume(config_path: &Path, cfg: &Config) -> Result<bool> {
    if service::daemon_state() != DaemonState::Running
        || daemon::mode(&cfg.state_dir).ok() != Some(Mode::Up)
    {
        return Ok(false);
    }
    let Some(report) = daemon::read_report(&cfg.state_dir) else {
        return Ok(false);
    };
    if !report.is_fresh(cfg) || report.config != daemon::config_fingerprint(config_path) {
        return Ok(false);
    }
    let was_paused = daemon::clear_pause(&cfg.state_dir)?;
    if !was_paused {
        if report.blocking {
            ui::outcome(Mark::Ok, "Protection is already on");
            return Ok(true);
        }
        // On but not blocking: something is wrong, go through the full path.
        return Ok(false);
    }
    let fw = firewall::native(cfg);
    let wait = Duration::from_secs(cfg.check_interval_secs * 2 + 5);
    ensure!(
        wait_for(wait, || blocking(&fw, cfg)),
        "the pause is cleared, but the daemon has not blocked again yet; see `daemon-killer status`"
    );
    ui::outcome(Mark::Ok, "Resumed; protection is on");
    Ok(true)
}

/// Our rules block and the daemon says it put them there for `up`.
fn blocking(fw: &impl Firewall, cfg: &Config) -> bool {
    fw.state().is_ok_and(|s| s.active && s.blocking)
        && daemon::read_report(&cfg.state_dir)
            .is_some_and(|r| r.mode == Mode::Up && r.blocking && r.paused_secs.is_none())
}

pub fn down(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path).unwrap_or_default();
    let installed = service::daemon_state() != DaemonState::NotInstalled;
    let removed = turn_off(&cfg)?;
    if installed {
        ui::outcome(Mark::Ok, "Protection is off; traffic is not restricted");
        ui::hint("Turn it back on", "daemon-killer up");
    } else if removed {
        ui::outcome(
            Mark::Ok,
            "Removed leftover rules; traffic is not restricted",
        );
    } else {
        ui::outcome(
            Mark::Off,
            "Nothing to do: daemon-killer is not installed and no rules are loaded",
        );
    }
    Ok(())
}

/// Mode first, so the daemon does not put the rules back; then remove them here rather than
/// wait for its next tick. Without a daemon this is the emergency cleanup. Returns whether
/// any rules were loaded.
fn turn_off(cfg: &Config) -> Result<bool> {
    let fw = firewall::native(cfg);
    let state = service::daemon_state();
    let since = daemon::now_secs();
    if state != DaemonState::NotInstalled {
        daemon::set_mode(&cfg.state_dir, Mode::Down)?;
    }
    let had = !fw.state()?.is_empty();
    fw.remove()?;
    if state == DaemonState::Running {
        // A tick that read the old mode may re-apply once; outlast it.
        wait_for(Duration::from_secs(cfg.check_interval_secs * 2 + 3), || {
            daemon::read_report(&cfg.state_dir)
                .is_some_and(|r| r.mode == Mode::Down && r.updated >= since)
        });
        if !fw.state()?.is_empty() {
            fw.remove()?;
        }
    }
    Ok(had)
}

pub fn pause(config_path: &Path, minutes: u64) -> Result<()> {
    let cfg = Config::load(config_path).unwrap_or_default();
    match service::daemon_state() {
        DaemonState::NotInstalled => {
            bail!("daemon-killer is not installed, so nothing is blocked")
        }
        DaemonState::Stopped => bail!(
            "the service is not running, so nothing would end the pause; \
             run `daemon-killer install` to restart it"
        ),
        DaemonState::Running => {}
    }
    ensure!(
        daemon::mode(&cfg.state_dir)? == Mode::Up,
        "protection is off, so there is nothing to pause; `daemon-killer up` turns it on"
    );
    let granted = daemon::set_pause(&cfg.state_dir, minutes)?;
    let opened = wait_for(Duration::from_secs(cfg.check_interval_secs * 2 + 5), || {
        daemon::read_report(&cfg.state_dir).is_some_and(|r| r.paused_secs.is_some() && !r.blocking)
    });
    let limit = if granted < minutes {
        " (the maximum)"
    } else {
        ""
    };
    if opened {
        ui::outcome(
            Mark::Ok,
            &format!("Paused for {granted} min{limit}; protection comes back on by itself"),
        );
    } else {
        ui::outcome(
            Mark::Warn,
            &format!(
                "Pause of {granted} min{limit} requested, but the daemon has not opened the firewall yet"
            ),
        );
    }
    ui::hint("Resume now", "daemon-killer up");
    Ok(())
}

/// Runs as its own service/job, so it remains alive if the interactive `up` dies.
pub fn rollback_watchdog(config: &Path, ticket: &Path, seconds: u64) -> Result<()> {
    for _ in 0..seconds {
        if !ticket.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if ticket.exists() {
        log::warn!("`up` was not confirmed; turning protection off");
        turn_off(&Config::load(config).unwrap_or_default())?;
        let _ = std::fs::remove_file(ticket);
    }
    Ok(())
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_yes(timeout: Duration) -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        let _ = tx.send(line);
    });
    rx.recv_timeout(timeout)
        .is_ok_and(|l| l.trim().eq_ignore_ascii_case("yes"))
}

/// Idempotent: also cleans up after a half-finished install.
pub fn uninstall(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path).unwrap_or_default();
    let fw = firewall::native(&cfg);
    let installed = service::daemon_state() != DaemonState::NotInstalled;
    let had_rules = !fw.state()?.is_empty();
    if !installed && !had_rules && !service::binary_path().exists() {
        ui::outcome(
            Mark::Off,
            "daemon-killer is not installed; nothing to remove",
        );
        return Ok(());
    }

    ui::heading("Uninstalling daemon-killer");
    service::unregister();
    fw.remove()?;
    ui::row("Protection", Mark::Ok, "off", "rules removed");
    ui::row("Service", Mark::Ok, "removed", "");
    // Cancel every pending `up` before anything can start again.
    if let Ok(entries) = std::fs::read_dir(&cfg.state_dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("up-pending-")
            {
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    daemon::forget(&cfg.state_dir);
    let bin = service::binary_path();
    service::remove_files();
    ui::row("Program", Mark::Ok, "removed", &bin.display().to_string());
    ui::outcome(Mark::Ok, "Uninstalled");
    ui::hint(&format!("Config kept at {}", config_path.display()), "");
    Ok(())
}
