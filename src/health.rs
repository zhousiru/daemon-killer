//! Is Clash actually up? Only drives alerts and `kill_apps`; the firewall blocks leaks regardless.

use crate::config::Config;
use crate::controller::Controller;
use crate::platform;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub tun_up: bool,
    pub mihomo_running: bool,
    /// `None` when no controller is configured.
    pub controller_ok: Option<bool>,
}

impl Health {
    pub fn ok(&self) -> bool {
        self.tun_up && self.mihomo_running && self.controller_ok != Some(false)
    }

    pub fn describe(&self) -> String {
        let yn = |b: bool| if b { "up" } else { "DOWN" };
        let ctl = match self.controller_ok {
            None => "n/a",
            Some(b) => yn(b),
        };
        format!(
            "tun {}, mihomo {}, controller {ctl}",
            yn(self.tun_up),
            yn(self.mihomo_running)
        )
    }

    /// For people: names what is checked, `tun Mihomo up · mihomo running · controller ok`.
    pub fn detail(&self, cfg: &Config) -> String {
        let controller = match self.controller_ok {
            None => "no controller set",
            Some(true) => "controller ok",
            Some(false) => "controller DOWN",
        };
        format!(
            "tun {} {} · {} {} · {controller}",
            cfg.tun_device,
            if self.tun_up { "up" } else { "DOWN" },
            cfg.mihomo_process,
            if self.mihomo_running {
                "running"
            } else {
                "NOT RUNNING"
            },
        )
    }
}

pub fn check(cfg: &Config) -> Health {
    Health {
        tun_up: platform::iface_up(&cfg.tun_device),
        mihomo_running: platform::process_running(&cfg.mihomo_process),
        controller_ok: cfg.controller.as_deref().map(|p| {
            Controller::find(p, cfg.controller_secret.as_deref()).is_some_and(|c| c.alive())
        }),
    }
}

pub fn kill_apps(names: &[String]) {
    for name in platform::kill_processes(names) {
        log::warn!("killed {name}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ok_logic() {
        let h = Health {
            tun_up: true,
            mihomo_running: true,
            controller_ok: None,
        };
        assert!(h.ok());
        assert!(!Health {
            controller_ok: Some(false),
            ..h.clone()
        }
        .ok());
        assert!(!Health { tun_up: false, ..h }.ok());
    }
}
