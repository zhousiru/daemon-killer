//! `status`: one screen with everything that matters and the next command to run. It also
//! validates the config and dry-runs its rules, which used to be `check`.

use crate::config::Config;
use crate::daemon::{self, Mode, Report};
use crate::firewall::{self, Firewall, FwState};
use crate::platform::{self, service, DaemonState, NativeFirewall};
use crate::policy::Policy;
use crate::ui::{self, Mark};
use crate::{health, upstream};
use anstream::println;
use anyhow::Result;
use std::path::Path;

/// The native rules the config produces (pf anchor / WFP filters), for debugging and tests.
pub fn rules(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path)?;
    let nets = upstream::refresh(&cfg, true).nets;
    print!(
        "{}",
        firewall::native(&cfg).render(&Policy::build(&cfg, &nets))
    );
    Ok(())
}

fn permission_denied(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    })
}

pub fn status(config_path: &Path) -> Result<()> {
    let elevated = platform::is_elevated();
    let svc = service::daemon_state();
    let loaded = Config::load(config_path);
    let unreadable = loaded.as_ref().err().is_some_and(permission_denied);
    let cfg = loaded.as_ref().cloned().unwrap_or_default();
    let fw = firewall::native(&cfg);
    let fw_state = elevated.then(|| fw.state());
    // Unreadable without elevation on Windows, where the state directory is admin-only.
    let mode = daemon::mode(&cfg.state_dir).ok();
    let paused = match mode {
        Some(Mode::Up) => daemon::pause_remaining(&cfg.state_dir),
        _ => None,
    };
    let report = daemon::read_report(&cfg.state_dir);
    let fresh = report.as_ref().filter(|r| r.is_fresh(&cfg));
    let shown = config_path.display().to_string();
    let mut hints: Vec<(String, String)> = Vec::new();
    let mut hint = |what: &str, cmd: &str| {
        if !hints.iter().any(|(w, _)| w == what) {
            hints.push((what.into(), cmd.into()));
        }
    };

    // Protection: what `up`/`down`/`pause` asked for, checked against the kernel.
    let leftover = matches!(&fw_state, Some(Ok(s)) if !s.is_empty());
    let enforced = match &fw_state {
        Some(Ok(s)) => Some(s.blocking),
        _ => None,
    };
    match (svc, mode) {
        (DaemonState::NotInstalled, _) if leftover => {
            ui::row(
                "Protection",
                Mark::Bad,
                "leftover rules",
                "not installed, but rules are still loaded",
            );
            hint("Remove them", "daemon-killer down");
        }
        (DaemonState::NotInstalled, _) => {
            ui::row("Protection", Mark::Off, "off", "not installed");
            hint("Install", "daemon-killer install");
        }
        (_, None) => ui::row("Protection", Mark::Unknown, "unknown", "needs elevation"),
        (_, Some(Mode::Down)) => {
            ui::row("Protection", Mark::Off, "off", "");
            if loaded.is_err() && !unreadable {
                hint("Fix the config", &shown);
            }
            hint("Turn it on", "daemon-killer up");
        }
        (_, Some(Mode::Up)) => match paused {
            Some(left) => {
                ui::row(
                    "Protection",
                    Mark::Warn,
                    "paused",
                    &format!("{} left, then back on by itself", ui::duration(left)),
                );
                hint("Resume now", "daemon-killer up");
            }
            None if enforced == Some(false) => {
                ui::row(
                    "Protection",
                    Mark::Bad,
                    "on, NOT enforced",
                    "the blocking rules are not loaded",
                );
                hint("Turn it on again", "daemon-killer up");
            }
            None => ui::row(
                "Protection",
                Mark::Ok,
                "on",
                &format!("host traffic uses {}", cfg.tun_device),
            ),
        },
    }

    // Clash
    if unreadable {
        ui::row(
            "Clash",
            Mark::Unknown,
            "unknown",
            "needs elevation to read the config",
        );
    } else if loaded.is_err() {
        ui::row("Clash", Mark::Unknown, "unknown", "needs a valid config");
    } else {
        let h = health::check(&cfg);
        if h.ok() {
            ui::row("Clash", Mark::Ok, "healthy", &h.detail(&cfg));
        } else if mode == Some(Mode::Up) && paused.is_none() {
            ui::row(
                "Clash",
                Mark::Bad,
                "down",
                &format!("{}; all other traffic is blocked", h.detail(&cfg)),
            );
        } else {
            ui::row("Clash", Mark::Bad, "down", &h.detail(&cfg));
        }
    }

    // Firewall
    firewall_row(&fw_state, fresh);

    // Config, including what `check` used to do.
    match &loaded {
        Err(_) if unreadable => ui::row(
            "Config",
            Mark::Unknown,
            "unknown",
            &format!("needs elevation to read {shown}"),
        ),
        Err(e) => {
            ui::row("Config", Mark::Bad, "invalid", &format!("{e:#}"));
            hint("Fix it", &shown);
        }
        Ok(cfg) => {
            let verified = (elevated || !NativeFirewall::VALIDATE_NEEDS_ELEVATION).then(|| {
                let nets = upstream::refresh(cfg, true).nets;
                fw.validate(&Policy::build(cfg, &nets))
            });
            let stale = svc == DaemonState::Running
                && mode == Some(Mode::Up)
                && fresh.is_some_and(|r| r.config != daemon::config_fingerprint(config_path));
            match verified {
                Some(Err(e)) => {
                    ui::row("Config", Mark::Bad, "rules rejected", &format!("{e:#}"));
                    hint("Fix it", &shown);
                }
                _ if stale => {
                    ui::row(
                        "Config",
                        Mark::Warn,
                        "changed",
                        &format!("{shown} · not applied yet"),
                    );
                    hint("Apply it", "daemon-killer up");
                }
                Some(Ok(())) => ui::row(
                    "Config",
                    Mark::Ok,
                    "valid",
                    &format!("{shown} · rules verified"),
                ),
                None => ui::row(
                    "Config",
                    Mark::Ok,
                    "valid",
                    &format!("{shown} · rules verified only when elevated"),
                ),
            }
        }
    }

    // Service
    match svc {
        DaemonState::NotInstalled => ui::row("Service", Mark::Off, "not installed", ""),
        DaemonState::Stopped => {
            ui::row(
                "Service",
                Mark::Bad,
                "stopped",
                "drift is not repaired and pauses do not end",
            );
            hint("Restart it", "daemon-killer install");
        }
        // The report is unreadable without elevation; assume it is fine then.
        DaemonState::Running if fresh.is_some() || mode.is_none() => {
            ui::row("Service", Mark::Ok, "running", "starts at boot")
        }
        DaemonState::Running => ui::row(
            "Service",
            Mark::Warn,
            "not responding",
            &format!("see {}", service::log_path().display()),
        ),
    }

    if !elevated {
        if cfg!(windows) {
            hint("Run in an administrator terminal for full details", "");
        } else {
            hint("Full details", "sudo daemon-killer status");
        }
    }
    if !hints.is_empty() {
        println!();
        for (what, cmd) in &hints {
            ui::hint(what, cmd);
        }
    }
    Ok(())
}

fn firewall_row(state: &Option<Result<FwState>>, report: Option<&Report>) {
    if let Some(err) = report.and_then(|r| r.firewall_error.as_deref()) {
        return ui::row("Firewall", Mark::Bad, "error", err);
    }
    match state {
        None => ui::row("Firewall", Mark::Unknown, "unknown", "needs elevation"),
        Some(Err(e)) => ui::row("Firewall", Mark::Bad, "error", &format!("{e:#}")),
        Some(Ok(s)) if s.is_empty() => ui::row("Firewall", Mark::Off, "no rules", ""),
        Some(Ok(s)) if s.blocking => ui::row("Firewall", Mark::Ok, "blocking", &s.summary),
        Some(Ok(s)) => ui::row("Firewall", Mark::Warn, "open", &s.summary),
    }
}
