//! The enforcement loop: keep our firewall rules as `up`/`down`/`pause` asked, watch Clash,
//! react when it goes down.

use crate::config::Config;
use crate::firewall::{self, Firewall, FwState};
use crate::policy::Policy;
use crate::{health, platform, upstream};
use anyhow::Result;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_PAUSE_MINUTES: u64 = 60;

/// What `up`/`down` asked for; it outlives reboots and reinstalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Up,
    Down,
}

/// What the daemon last did, for `status` and for `up`/`pause` to wait on.
#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub updated: u64,
    /// `config_fingerprint` of the config the daemon runs with; `up` reloads when it differs.
    pub config: String,
    pub mode: Mode,
    pub paused_secs: Option<u64>,
    pub blocking: bool,
    pub firewall_error: Option<String>,
    pub upstreams: usize,
}

impl Report {
    /// The loop is alive: it reported within a few intervals.
    pub fn is_fresh(&self, cfg: &Config) -> bool {
        now_secs() <= self.updated + cfg.check_interval_secs * 3 + 5
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Off,
    Open,
    Block,
}

/// Runs until `stop` fires or its sender goes away. Rules stay in the kernel afterwards.
pub fn run(config_path: &Path, stop: Receiver<()>) -> Result<()> {
    let cfg = loop {
        match Config::load(config_path) {
            Ok(cfg) => break cfg,
            Err(e) => {
                // Exiting would only make the service manager restart us in a loop. The kernel
                // keeps whatever rules it has, so protection that was on stays fail-closed.
                log::error!("{e:#}; rules left as they are, retrying in 30s");
                if stopped(&stop, Duration::from_secs(30)) {
                    return Ok(());
                }
            }
        }
    };
    let config = config_fingerprint(config_path);
    platform::secure_dir(&cfg.state_dir)?;
    let fw = firewall::native(&cfg);
    // Lock down first with what is already known (config + cache): DNS may not work yet.
    let upstreams = Arc::new(Mutex::new(upstream::refresh(&cfg, false).nets));
    spawn_resolver(cfg.clone(), Arc::clone(&upstreams));

    let interval = Duration::from_secs(cfg.check_interval_secs);
    let grace = Duration::from_secs(cfg.unhealthy_grace_secs);
    let mut applied: Option<Applied> = None;
    let mut last_ok: Option<bool> = None;
    let mut unhealthy_since: Option<Instant> = None;
    log::info!("started; protects through {}", cfg.tun_device);

    loop {
        // Unreadable means damaged: fail closed.
        let mode = mode(&cfg.state_dir).unwrap_or(Mode::Up);
        let paused = match mode {
            Mode::Up => pause_remaining(&cfg.state_dir),
            Mode::Down => None,
        };
        let want = match (mode, paused) {
            (Mode::Down, _) => Want::Off,
            (Mode::Up, Some(_)) => Want::Open,
            (Mode::Up, None) => Want::Block,
        };
        let nets = upstreams.lock().unwrap().clone();
        let (blocking, firewall_error) = match enforce_tick(&fw, &cfg, &nets, want, &mut applied) {
            Ok(st) => (st.blocking, None),
            Err(e) => {
                log::error!("enforcing firewall: {e:#}");
                applied = None;
                (false, Some(format!("{e:#}")))
            }
        };

        if want == Want::Block {
            let h = health::check(&cfg);
            let ok = h.ok();
            if last_ok != Some(ok) {
                if ok {
                    log::info!("clash healthy ({})", h.describe());
                    if last_ok.is_some() && cfg.notify {
                        platform::notify("Clash is back, traffic flows through the TUN again");
                    }
                } else {
                    log::warn!(
                        "clash unhealthy ({}); non-TUN traffic stays blocked",
                        h.describe()
                    );
                    if cfg.notify {
                        platform::notify(&format!(
                            "Clash down ({}): network blocked",
                            h.describe()
                        ));
                    }
                }
                last_ok = Some(ok);
            }
            if ok {
                unhealthy_since = None;
            } else if unhealthy_since.get_or_insert_with(Instant::now).elapsed() >= grace {
                // Keep killing while it lasts, so relaunched apps go down again.
                health::kill_apps(&cfg.kill_apps);
            }
        } else {
            // Nothing is blocked, so there is nothing to warn about.
            last_ok = None;
            unhealthy_since = None;
        }

        write_report(
            &cfg.state_dir,
            &Report {
                updated: now_secs(),
                config: config.clone(),
                mode,
                paused_secs: paused.map(|d| d.as_secs()),
                blocking,
                firewall_error,
                upstreams: nets.len(),
            },
        );
        if stopped(&stop, interval) {
            log::info!("stopping; firewall rules stay in place");
            return Ok(());
        }
    }
}

fn stopped(stop: &Receiver<()>, wait: Duration) -> bool {
    !matches!(stop.recv_timeout(wait), Err(RecvTimeoutError::Timeout))
}

struct Applied {
    source: String,
    fingerprint: String,
}

/// Re-apply when the wanted rules changed or someone tampered with the firewall.
fn enforce_tick(
    fw: &impl Firewall,
    cfg: &Config,
    nets: &[IpNet],
    want: Want,
    applied: &mut Option<Applied>,
) -> Result<FwState> {
    if want == Want::Off {
        *applied = None;
        let st = fw.state()?;
        if st.is_empty() {
            return Ok(st);
        }
        fw.remove()?;
        log::info!("protection off; rules removed");
        return Ok(FwState::default());
    }
    let policy = match want {
        Want::Open => Policy::open(),
        _ => Policy::build(cfg, nets),
    };
    let source = fw.render(&policy);
    let st = fw.state()?;
    let drifted = !st.active
        || st.blocking != policy.blocking
        || applied
            .as_ref()
            .is_some_and(|a| a.fingerprint != st.fingerprint);
    if applied.as_ref().map(|a| a.source.as_str()) != Some(source.as_str()) || drifted {
        if applied.is_some() && drifted {
            log::warn!("firewall drifted ({}); re-applying", st.describe());
        }
        fw.apply(&policy)?;
        log::info!(
            "firewall rules loaded ({}, {} upstream nets)",
            if want == Want::Open {
                "paused, open"
            } else {
                "blocking"
            },
            nets.len()
        );
        // Revoke only after the restrictive policy is fully installed. This also cuts
        // connections opened during pause or a firewall drift window.
        if policy.blocking {
            fw.revoke_connections()?;
        }
        let actual = fw.state()?;
        *applied = Some(Applied {
            source,
            fingerprint: actual.fingerprint.clone(),
        });
        return Ok(actual);
    }
    Ok(st)
}

fn spawn_resolver(cfg: Config, upstreams: Arc<Mutex<Vec<IpNet>>>) {
    std::thread::spawn(move || loop {
        let r = upstream::refresh(&cfg, true);
        *upstreams.lock().unwrap() = r.nets;
        std::thread::sleep(Duration::from_secs(cfg.upstream_refresh_secs));
    });
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Identifies the config file's contents (FNV-1a), stable across builds.
pub fn config_fingerprint(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    let h = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("{h:016x}")
}

fn mode_path(state_dir: &Path) -> PathBuf {
    state_dir.join("mode")
}

/// No file means protection was never turned on. Anything but `down` counts as up, so a
/// damaged file fails closed.
pub fn mode(state_dir: &Path) -> std::io::Result<Mode> {
    match std::fs::read_to_string(mode_path(state_dir)) {
        Ok(s) if s.trim() == "down" => Ok(Mode::Down),
        Ok(_) => Ok(Mode::Up),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Mode::Down),
        Err(e) => Err(e),
    }
}

/// Also ends any pause: both `up` and `down` replace it. Callers secure `state_dir`.
pub fn set_mode(state_dir: &Path, mode: Mode) -> Result<()> {
    std::fs::create_dir_all(state_dir)?;
    clear_pause(state_dir)?;
    let text = match mode {
        Mode::Up => "up\n",
        Mode::Down => "down\n",
    };
    std::fs::write(mode_path(state_dir), text)?;
    Ok(())
}

fn pause_path(state_dir: &Path) -> PathBuf {
    state_dir.join("pause")
}

/// Returns the minutes actually granted.
pub fn set_pause(state_dir: &Path, minutes: u64) -> Result<u64> {
    let minutes = minutes.clamp(1, MAX_PAUSE_MINUTES);
    platform::secure_dir(state_dir)?;
    std::fs::write(
        pause_path(state_dir),
        (now_secs() + minutes * 60).to_string(),
    )?;
    Ok(minutes)
}

/// Whether a pause was active.
pub fn clear_pause(state_dir: &Path) -> Result<bool> {
    let active = pause_remaining(state_dir).is_some();
    match std::fs::remove_file(pause_path(state_dir)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(active),
    }
}

/// Time left on an active pause. An expired or unreadable pause file counts as no pause.
pub fn pause_remaining(state_dir: &Path) -> Option<Duration> {
    let until: u64 = std::fs::read_to_string(pause_path(state_dir))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let now = now_secs();
    if until <= now {
        let _ = std::fs::remove_file(pause_path(state_dir));
        return None;
    }
    // Never honour more than the maximum, even if the file was edited by hand.
    Some(Duration::from_secs(
        (until - now).min(MAX_PAUSE_MINUTES * 60),
    ))
}

fn report_path(state_dir: &Path) -> PathBuf {
    state_dir.join("report.json")
}

fn write_report(state_dir: &Path, report: &Report) {
    if let Ok(json) = serde_json::to_string_pretty(report) {
        let _ = std::fs::write(report_path(state_dir), json);
    }
}

pub fn read_report(state_dir: &Path) -> Option<Report> {
    serde_json::from_str(&std::fs::read_to_string(report_path(state_dir)).ok()?).ok()
}

pub fn clear_report(state_dir: &Path) {
    let _ = std::fs::remove_file(report_path(state_dir));
}

/// Drop what `up`/`pause` left, so a later install starts with protection off.
pub fn forget(state_dir: &Path) {
    for p in [
        mode_path(state_dir),
        pause_path(state_dir),
        report_path(state_dir),
    ] {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dk-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn pause_roundtrip_and_expiry() {
        let dir = temp_dir("pause");
        assert!(pause_remaining(&dir).is_none());
        std::fs::write(pause_path(&dir), (now_secs() + 500 * 60).to_string()).unwrap();
        let left = pause_remaining(&dir).unwrap();
        assert!(left > Duration::from_secs(59 * 60) && left <= Duration::from_secs(60 * 60));
        std::fs::write(pause_path(&dir), (now_secs() - 1).to_string()).unwrap();
        assert!(pause_remaining(&dir).is_none());
        assert!(!pause_path(&dir).exists());
        clear_pause(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mode_defaults_off_and_fails_closed() {
        let dir = temp_dir("mode");
        assert_eq!(mode(&dir).unwrap(), Mode::Down);
        std::fs::write(mode_path(&dir), "garbage").unwrap();
        assert_eq!(mode(&dir).unwrap(), Mode::Up);
        std::fs::write(pause_path(&dir), (now_secs() + 60).to_string()).unwrap();
        set_mode(&dir, Mode::Down).unwrap();
        assert_eq!(mode(&dir).unwrap(), Mode::Down);
        assert!(!pause_path(&dir).exists(), "down ends a pause");
        forget(&dir);
        assert!(!mode_path(&dir).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fingerprint_tracks_content() {
        let dir = temp_dir("fp");
        let p = dir.join("c.toml");
        std::fs::write(&p, "a = 1").unwrap();
        let a = config_fingerprint(&p);
        assert_eq!(a, config_fingerprint(&p));
        std::fs::write(&p, "a = 2").unwrap();
        assert_ne!(a, config_fingerprint(&p));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
