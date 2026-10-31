//! When to tell the logged-in user something: the rules could not be applied, so traffic may
//! leak, or they block everything because Clash stays down. Once per occurrence; recovery is
//! silent, and so is everything the user just did in a terminal.

use crate::config::Config;
use crate::health::Health;

/// Clash reloads and wakes from sleep take a few seconds; an outage this long is real.
const OUTAGE_TICKS: u32 = 3;
/// After nobody was logged in: Clash starts with the session too, so give it time.
const LOGIN_TICKS: u32 = 15;
const MAX_ERROR_CHARS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    NotEnforced(String),
    Blocked(Cause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    NotRunning,
    TunDown,
    NotResponding,
}

impl Cause {
    /// The most basic failure, when several hold.
    fn of(h: &Health) -> Option<Cause> {
        if !h.mihomo_running {
            Some(Cause::NotRunning)
        } else if !h.tun_up {
            Some(Cause::TunDown)
        } else if h.controller_ok == Some(false) {
            Some(Cause::NotResponding)
        } else {
            None
        }
    }
}

impl Notice {
    pub fn title(&self) -> &'static str {
        match self {
            Notice::NotEnforced(_) => "Kill switch not enforced",
            Notice::Blocked(_) => "Internet blocked",
        }
    }

    pub fn body(&self, cfg: &Config) -> String {
        match self {
            Notice::NotEnforced(e) => format!(
                "Traffic may bypass Clash. Firewall rules could not be applied: {}. \
                 Run \"daemon-killer status\" for details.",
                truncate(e)
            ),
            Notice::Blocked(Cause::NotRunning) => format!(
                "{} is not running, so all traffic is blocked. Start Clash, or run \
                 \"daemon-killer down\" to turn protection off.",
                cfg.mihomo_process
            ),
            Notice::Blocked(Cause::TunDown) => format!(
                "The Clash TUN ({}) is down, so all traffic is blocked. Turn on TUN mode in \
                 Clash, or run \"daemon-killer down\".",
                cfg.tun_device
            ),
            Notice::Blocked(Cause::NotResponding) => "Clash is not responding, so all traffic \
                 is blocked. Restart Clash, or run \"daemon-killer down\"."
                .into(),
        }
    }
}

fn truncate(s: &str) -> String {
    let s = s.trim().trim_end_matches('.');
    if s.chars().count() <= MAX_ERROR_CHARS {
        return s.into();
    }
    let mut out: String = s.chars().take(MAX_ERROR_CHARS - 1).collect();
    out.push('…');
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Handed to the user's session, or failed there; either way, not tried again.
    Sent,
    /// Nobody is logged in to show it to.
    NoUser,
}

#[derive(Default)]
pub struct Notifier {
    error: Option<String>,
    since_error: u32,
    outage: u32,
    healthy: u32,
    announced: bool,
    after_login: bool,
}

impl Notifier {
    /// One daemon tick. `error` is set while blocking rules failed to apply; `health` only
    /// while they are in place and blocking.
    pub fn tick(
        &mut self,
        error: Option<&str>,
        health: Option<&Health>,
        deliver: impl FnOnce(&Notice) -> Delivery,
    ) {
        if let Some(e) = error {
            self.since_error = 0;
            if self.error.as_deref() != Some(e)
                && deliver(&Notice::NotEnforced(e.into())) == Delivery::Sent
            {
                self.error = Some(e.into());
            }
            return;
        }
        self.since_error += 1;
        if self.since_error >= OUTAGE_TICKS {
            self.error = None;
        }
        match health.and_then(Cause::of) {
            Some(cause) => {
                self.healthy = 0;
                self.outage += 1;
                let needed = if self.after_login {
                    LOGIN_TICKS
                } else {
                    OUTAGE_TICKS
                };
                if !self.announced && self.outage >= needed {
                    match deliver(&Notice::Blocked(cause)) {
                        Delivery::Sent => self.announced = true,
                        Delivery::NoUser => {
                            self.outage = 0;
                            self.after_login = true;
                        }
                    }
                }
            }
            None => {
                self.outage = 0;
                self.healthy += 1;
                if self.healthy >= OUTAGE_TICKS {
                    self.announced = false;
                    self.after_login = false;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UP: Health = Health {
        tun_up: true,
        mihomo_running: true,
        controller_ok: Some(true),
    };
    const DOWN: Health = Health {
        tun_up: false,
        mihomo_running: false,
        controller_ok: None,
    };

    /// Runs ticks and returns what was delivered on each one.
    fn run(
        n: &mut Notifier,
        ticks: &[(Option<&str>, Option<&Health>, Delivery)],
    ) -> Vec<Option<Notice>> {
        ticks
            .iter()
            .map(|&(e, h, d)| {
                let mut sent = None;
                n.tick(e, h, |notice| {
                    sent = Some(notice.clone());
                    d
                });
                sent
            })
            .collect()
    }

    fn down(n: usize) -> Vec<(Option<&'static str>, Option<&'static Health>, Delivery)> {
        vec![(None, Some(&DOWN), Delivery::Sent); n]
    }

    fn up(n: usize) -> Vec<(Option<&'static str>, Option<&'static Health>, Delivery)> {
        vec![(None, Some(&UP), Delivery::Sent); n]
    }

    #[test]
    fn an_outage_is_announced_once_after_a_few_ticks() {
        let mut n = Notifier::default();
        let got = run(&mut n, &down(6));
        assert_eq!(got.iter().flatten().count(), 1);
        assert_eq!(got[2], Some(Notice::Blocked(Cause::NotRunning)));
    }

    #[test]
    fn blips_stay_silent_and_recovery_rearms() {
        let mut n = Notifier::default();
        let mut ticks = down(2);
        ticks.extend(up(1));
        ticks.extend(down(2));
        assert!(run(&mut n, &ticks).iter().all(Option::is_none));

        let mut ticks = down(3);
        ticks.extend(up(2));
        ticks.extend(down(3));
        assert_eq!(
            run(&mut n, &ticks).iter().flatten().count(),
            1,
            "flapping is one outage"
        );

        let mut ticks = up(3);
        ticks.extend(down(3));
        assert_eq!(run(&mut n, &ticks).iter().flatten().count(), 1);
    }

    #[test]
    fn pause_and_off_are_not_outages() {
        let mut n = Notifier::default();
        assert!(run(&mut n, &[(None, None, Delivery::Sent); 10])
            .iter()
            .all(Option::is_none));
    }

    #[test]
    fn nobody_logged_in_waits_for_the_session_and_clash() {
        let mut n = Notifier::default();
        let mut ticks = vec![(None, Some(&DOWN), Delivery::NoUser); 3];
        ticks.extend(down(LOGIN_TICKS as usize));
        let got = run(&mut n, &ticks);
        assert_eq!(
            got.iter().flatten().count(),
            2,
            "one try without a user, one with"
        );
        assert!(got[3 + LOGIN_TICKS as usize - 1].is_some());
    }

    #[test]
    fn errors_are_announced_at_once_and_once_each() {
        let mut n = Notifier::default();
        let e = |s| (Some(s), None, Delivery::Sent);
        let got = run(
            &mut n,
            &[e("a"), e("a"), e("b"), (None, None, Delivery::Sent), e("b")],
        );
        assert_eq!(
            got,
            vec![
                Some(Notice::NotEnforced("a".into())),
                None,
                Some(Notice::NotEnforced("b".into())),
                None,
                None,
            ]
        );
        let mut ticks = up(3);
        ticks.push(e("b"));
        assert!(
            run(&mut n, &ticks)[3].is_some(),
            "a cleared error comes back"
        );
    }

    #[test]
    fn copy_names_the_most_basic_cause() {
        let cfg = Config::default();
        assert_eq!(Cause::of(&UP), None);
        assert_eq!(Cause::of(&DOWN), Some(Cause::NotRunning));
        let tun = Health {
            mihomo_running: true,
            ..DOWN
        };
        assert_eq!(Cause::of(&tun), Some(Cause::TunDown));
        assert!(Notice::Blocked(Cause::TunDown)
            .body(&cfg)
            .contains(&format!("({})", cfg.tun_device)));
        let slow = Health {
            controller_ok: Some(false),
            ..UP
        };
        assert_eq!(Cause::of(&slow), Some(Cause::NotResponding));
    }

    #[test]
    fn long_errors_are_cut() {
        let body = Notice::NotEnforced("x".repeat(500)).body(&Config::default());
        assert!(body.contains(&format!("{}…. Run", "x".repeat(MAX_ERROR_CHARS - 1))));
        let body = Notice::NotEnforced("pfctl failed.".into()).body(&Config::default());
        assert!(body.contains("applied: pfctl failed. Run"));
    }
}
