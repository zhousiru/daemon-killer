//! pf backend: our rules live in the `daemon-killer` anchor, referenced first in the
//! live main ruleset.

use crate::config::Config;
use crate::firewall::pf::{
    compile, first_filter_rule, main_ruleset, without_our_anchor, ANCHOR, BLOCK_RULE,
};
use crate::firewall::{Firewall, FwState};
use crate::policy::Policy;
use anyhow::{bail, Context, Result};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const PFCTL: &str = "/sbin/pfctl";

pub struct Pf {
    state_dir: PathBuf,
}

impl Pf {
    pub fn new(cfg: &Config) -> Self {
        Pf {
            state_dir: cfg.state_dir.clone(),
        }
    }

    fn token_path(&self) -> PathBuf {
        self.state_dir.join("pf.token")
    }

    fn was_enabled_path(&self) -> PathBuf {
        self.state_dir.join("pf.was-enabled")
    }

    /// Enable pf holding a reference token, unless we already hold one on an enabled pf.
    fn ensure_enabled(&self, enabled: bool) -> Result<()> {
        if enabled && self.token_path().exists() {
            return Ok(());
        }
        if !self.was_enabled_path().exists() {
            std::fs::write(self.was_enabled_path(), if enabled { "yes" } else { "no" })?;
        }
        let out = pfctl(&["-E"], None)?;
        let token = out
            .lines()
            .find_map(|l| l.strip_prefix("Token : "))
            .map(str::trim)
            .context("pfctl -E printed no token")?;
        std::fs::write(self.token_path(), token)?;
        Ok(())
    }
}

fn pfctl(args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut child = Command::new(PFCTL)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning pfctl")?;
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        bail!("pfctl {} failed: {}", args.join(" "), stderr.trim());
    }
    // pfctl reports some results (e.g. the -E token) on stderr.
    Ok(if args.contains(&"-E") {
        stdout + &stderr
    } else {
        stdout
    })
}

/// Parse only (`pfctl -n`); changes nothing and needs no root.
fn parse_check(rules: &str) -> Result<()> {
    pfctl(&["-n", "-f", "-"], Some(rules)).map(drop)
}

/// Atomically replace our anchor's ruleset. Existing states survive.
fn load_anchor(rules: &str) -> Result<()> {
    parse_check(rules)?;
    pfctl(&["-a", ANCHOR, "-f", "-"], Some(rules)).map(drop)
}

fn pf_enabled() -> Result<bool> {
    let info = pfctl(&["-s", "info"], None)?;
    Ok(info.lines().any(|l| l.starts_with("Status: Enabled")))
}

/// Our anchor is the first filter rule of the main ruleset.
fn anchor_first() -> Result<bool> {
    let main = pfctl(&["-s", "rules"], None)?;
    Ok(first_filter_rule(&main).is_some_and(|l| l.starts_with(&format!("anchor \"{ANCHOR}\""))))
}

/// Change only the live filter/scrub rules, never rebuild from /etc/pf.conf.
fn load_main() -> Result<()> {
    let current = pfctl(&["-sr"], None)?;
    pfctl(&["-R", "-f", "-"], Some(&main_ruleset(&current))).map(drop)
}

impl Firewall for Pf {
    const VALIDATE_NEEDS_ELEVATION: bool = false;

    fn render(&self, policy: &Policy) -> String {
        compile(policy)
    }

    fn validate(&self, policy: &Policy) -> Result<()> {
        parse_check(&compile(policy))
    }

    fn state(&self) -> Result<FwState> {
        let enabled = pf_enabled()?;
        let anchor_first = anchor_first()?;
        let ours = pfctl(&["-a", ANCHOR, "-s", "rules"], None)?;
        Ok(FwState {
            active: enabled && anchor_first,
            blocking: ours.lines().any(|l| l.trim() == BLOCK_RULE),
            fingerprint: ours,
            summary: format!(
                "pf {}, anchor {}",
                if enabled { "enabled" } else { "DISABLED" },
                if anchor_first {
                    "first"
                } else {
                    "MISSING/NOT FIRST"
                },
            ),
        })
    }

    /// Bring everything up from scratch: anchor rules, main reference, pf enabled.
    fn apply(&self, policy: &Policy) -> Result<()> {
        let rules = compile(policy);
        load_anchor(&rules)?;
        let enabled = pf_enabled()?;
        if !anchor_first()? {
            load_main()?;
            // Reloading the main ruleset must not have touched our anchor, but make sure.
            load_anchor(&rules)?;
        }
        self.ensure_enabled(enabled)
    }

    /// macOS pf does not expose a safe per-UID state flush, so all states are reset.
    fn revoke_connections(&self) -> Result<()> {
        pfctl(&["-F", "states"], None).map(drop)
    }

    /// Remove our rules and release our pf reference.
    fn remove(&self) -> Result<()> {
        pfctl(&["-a", ANCHOR, "-F", "all"], None)?;
        if let Ok(token) = std::fs::read_to_string(self.token_path()) {
            if let Err(e) = pfctl(&["-X", token.trim()], None) {
                log::warn!("{e:#}");
            }
            let _ = std::fs::remove_file(self.token_path());
        }
        let current = pfctl(&["-sr"], None)?;
        pfctl(&["-R", "-f", "-"], Some(&without_our_anchor(&current)))?;
        let initial = self.was_enabled_path();
        if matches!(std::fs::read_to_string(&initial).as_deref(), Ok("yes")) && !pf_enabled()? {
            pfctl(&["-e"], None)?;
        }
        let _ = std::fs::remove_file(initial);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Egress;
    use std::path::Path;

    /// Runs the real `pfctl -n` parser; changes nothing on the host.
    #[test]
    fn rendered_rules_parse() {
        if !Path::new(PFCTL).exists() {
            return;
        }
        let c = Config {
            egress: Egress::Core,
            allow_interfaces: vec!["bridge100".into()],
            allow_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
            ..Config::default()
        };
        let ups = [
            "1.2.3.4/32".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let pf = Pf::new(&c);
        pf.validate(&Policy::build(&c, &ups)).unwrap();
        let minimal = Config {
            allow_dhcp: false,
            ..Config::default()
        };
        pf.validate(&Policy::build(&minimal, &[])).unwrap();
        parse_check(&main_ruleset(
            &std::fs::read_to_string("/etc/pf.conf").unwrap(),
        ))
        .unwrap();
    }
}
