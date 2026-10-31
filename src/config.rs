use crate::platform;
use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// What may leave through a physical interface besides the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Egress {
    /// Only the proxy upstreams and the DNS servers Clash itself uses, and only from the core.
    /// Clash rules that go DIRECT to the public internet stop working.
    Strict,
    /// Every TCP/UDP socket of the Clash core, so Clash DIRECT rules keep working.
    /// macOS identifies the core by `core_uid`, Windows by `core_program`.
    #[serde(alias = "uid")]
    Core,
}

/// The OS a config is checked against. Validation is pure so both can be tested anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // only the host's variant is constructed outside tests
pub enum Os {
    MacOs,
    Windows,
}

impl Os {
    #[cfg(target_os = "macos")]
    pub const CURRENT: Os = Os::MacOs;
    #[cfg(windows)]
    pub const CURRENT: Os = Os::Windows;
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The Clash TUN interface: `utun1500` on macOS, the adapter alias (`Mihomo`) on Windows.
    /// Pin it in Clash (`tun.device`) so the name never changes.
    pub tun_device: String,
    pub egress: Egress,
    /// macOS: owner of the Clash core process.
    #[serde(alias = "clash_uid")]
    pub core_uid: u32,
    /// Windows: full path of the Clash core executable (`mihomo.exe`).
    pub core_program: Option<PathBuf>,
    /// Windows: other executables that may reach the internet directly, even while Clash is
    /// down. Only for programs that cannot go through the TUN.
    pub allow_programs: Vec<PathBuf>,
    /// Extra proxy upstreams: IPs, CIDRs or hostnames.
    pub upstreams: Vec<String>,
    /// Running mihomo config; proxy servers, provider files and DNS servers are read from it.
    pub mihomo_config: Option<PathBuf>,
    /// Let RFC1918, link-local and multicast traffic bypass the TUN.
    pub allow_lan: bool,
    /// Extra destinations that may bypass the TUN.
    pub allow_cidrs: Vec<IpNet>,
    /// Host-internal interfaces (VM bridges, vEthernet) that are not a route to the internet.
    pub allow_interfaces: Vec<String>,
    pub allow_dhcp: bool,
    /// Windows: also install boot-time filters that block from TCP/IP start until BFE loads
    /// the persistent ones. Not yet verified on real hardware, hence off by default.
    pub boot_time_block: bool,
    /// Process name of the Clash core (`.exe` is optional on Windows).
    pub mihomo_process: String,
    /// mihomo external controller: a unix socket path (macOS), a named pipe `\\.\pipe\...`
    /// (Windows) or `tcp://127.0.0.1:9090`. One `*` in the last path component is allowed.
    #[serde(alias = "controller_socket")]
    pub controller: Option<String>,
    pub controller_secret: Option<String>,
    pub check_interval_secs: u64,
    pub upstream_refresh_secs: u64,
    /// How long Clash may stay unhealthy (e.g. during a restart) before `kill_apps` runs.
    pub unhealthy_grace_secs: u64,
    /// Processes (exact names) killed when Clash stays unhealthy.
    pub kill_apps: Vec<String>,
    pub notify: bool,
    pub state_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            tun_device: platform::DEFAULT_TUN.into(),
            egress: Egress::Strict,
            core_uid: 0,
            core_program: None,
            allow_programs: Vec::new(),
            upstreams: Vec::new(),
            mihomo_config: None,
            allow_lan: false,
            allow_cidrs: Vec::new(),
            allow_interfaces: Vec::new(),
            allow_dhcp: true,
            boot_time_block: false,
            mihomo_process: "mihomo".into(),
            controller: None,
            controller_secret: None,
            check_interval_secs: 2,
            upstream_refresh_secs: 600,
            unhealthy_grace_secs: 10,
            kill_apps: Vec::new(),
            notify: true,
            state_dir: platform::default_state_dir(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
                "no config at {}; `daemon-killer install` writes an example there to edit",
                path.display()
            ),
            r => r.with_context(|| format!("reading {}", path.display()))?,
        };
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate_for(Os::CURRENT)?;
        if Os::CURRENT == Os::Windows {
            // App IDs are derived from the file, so a missing binary cannot be filtered on.
            for p in cfg.core_program.iter().chain(&cfg.allow_programs) {
                ensure!(p.is_file(), "{} does not exist", p.display());
            }
        }
        Ok(cfg)
    }

    pub fn validate_for(&self, os: Os) -> Result<()> {
        ensure!(
            is_ifname(os, &self.tun_device),
            "bad tun_device {:?}",
            self.tun_device
        );
        for i in &self.allow_interfaces {
            ensure!(is_ifname(os, i), "bad allow_interfaces entry {i:?}");
        }
        match os {
            Os::MacOs => {
                ensure!(
                    self.core_program.is_none() && self.allow_programs.is_empty(),
                    "core_program/allow_programs need per-program filtering, which pf lacks; \
                     macOS identifies the core by core_uid"
                );
                ensure!(!self.boot_time_block, "boot_time_block is Windows-only");
            }
            Os::Windows => {
                let Some(core) = &self.core_program else {
                    bail!("core_program is required on Windows (the core runs as the same user as your apps)");
                };
                for p in std::iter::once(core).chain(&self.allow_programs) {
                    ensure!(
                        is_windows_abs(p),
                        "{} must be an absolute path",
                        p.display()
                    );
                }
            }
        }
        ensure!(!self.mihomo_process.is_empty(), "mihomo_process is empty");
        ensure!(
            self.check_interval_secs > 0,
            "check_interval_secs must be > 0"
        );
        ensure!(
            self.upstream_refresh_secs > 0,
            "upstream_refresh_secs must be > 0"
        );
        Ok(())
    }
}

/// macOS names are pasted into pf rules, so keep them strictly alphanumeric.
/// Windows aliases only go through API calls, but still reject control characters.
fn is_ifname(os: Os, s: &str) -> bool {
    match os {
        Os::MacOs => !s.is_empty() && s.len() < 16 && s.chars().all(|c| c.is_ascii_alphanumeric()),
        Os::Windows => !s.is_empty() && s.len() < 256 && !s.chars().any(char::is_control),
    }
}

/// `C:\...` or `\\server\...`, checked textually so it works on any host.
fn is_windows_abs(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let b = s.as_bytes();
    (b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || s.starts_with(r"\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn example_configs_parse() {
        let mac = parse(include_str!("../config/macos.example.toml"));
        mac.validate_for(Os::MacOs).unwrap();
        assert_eq!(mac.tun_device, "utun1500");
        assert_eq!(mac.egress, Egress::Core);

        let win = parse(include_str!("../config/windows.example.toml"));
        win.validate_for(Os::Windows).unwrap();
        assert_eq!(win.tun_device, "Mihomo");
        assert!(win.validate_for(Os::MacOs).is_err());
    }

    #[test]
    fn old_key_names_still_parse() {
        let cfg = parse("egress = \"uid\"\nclash_uid = 0\ncontroller_socket = \"/tmp/x.sock\"\n");
        assert_eq!(cfg.egress, Egress::Core);
        assert_eq!(cfg.controller.as_deref(), Some("/tmp/x.sock"));
    }

    #[test]
    fn rejects_injection_in_interface_names() {
        let cfg = parse("tun_device = \"utun1 all\\npass\"");
        assert!(cfg.validate_for(Os::MacOs).is_err());
        assert!(cfg.validate_for(Os::Windows).is_err());
    }

    #[test]
    fn windows_needs_absolute_core_program() {
        let base = "tun_device = \"Mihomo\"\n";
        assert!(parse(base).validate_for(Os::Windows).is_err());
        let rel = parse(&format!("{base}core_program = 'mihomo.exe'\n"));
        assert!(rel.validate_for(Os::Windows).is_err());
        let abs = parse(&format!("{base}core_program = 'C:\\Clash\\mihomo.exe'\n"));
        abs.validate_for(Os::Windows).unwrap();
        // Aliases may contain spaces on Windows but never on macOS.
        let spaced = parse("tun_device = \"Meta Tunnel\"\ncore_program = 'C:\\m.exe'\n");
        spaced.validate_for(Os::Windows).unwrap();
        assert!(spaced.validate_for(Os::MacOs).is_err());
    }
}
