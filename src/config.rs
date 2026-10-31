use crate::platform;
use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::path::{Path, PathBuf};

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
    /// macOS: owner of the Clash core process. Its TCP/UDP may go out directly, so proxy
    /// upstreams, DNS and Clash DIRECT rules work.
    pub core_uid: u32,
    /// Windows: full path of the Clash core executable (`mihomo.exe`), exempt likewise.
    pub core_program: Option<PathBuf>,
    /// Windows: other executables that may reach the internet directly, even while Clash is
    /// down. Only for programs that cannot go through the TUN.
    pub allow_programs: Vec<PathBuf>,
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
    /// Process name of the Clash core (`.exe` is optional on Windows); for `status`/`up`.
    pub mihomo_process: String,
    /// mihomo external controller: a unix socket path (macOS), a named pipe `\\.\pipe\...`
    /// (Windows) or `tcp://127.0.0.1:9090`. One `*` in the last path component is allowed.
    pub controller: Option<String>,
    pub controller_secret: Option<String>,
    /// Fixed next to the config, like it: not configurable.
    #[serde(skip)]
    pub state_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            tun_device: platform::DEFAULT_TUN.into(),
            core_uid: 0,
            core_program: None,
            allow_programs: Vec::new(),
            allow_lan: false,
            allow_cidrs: Vec::new(),
            allow_interfaces: Vec::new(),
            allow_dhcp: true,
            boot_time_block: false,
            mihomo_process: "mihomo".into(),
            controller: None,
            controller_secret: None,
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

        let win = parse(include_str!("../config/windows.example.toml"));
        win.validate_for(Os::Windows).unwrap();
        assert_eq!(win.tun_device, "Mihomo");
        assert!(win.validate_for(Os::MacOs).is_err());
    }

    #[test]
    fn state_dir_is_not_configurable() {
        assert!(toml::from_str::<Config>("state_dir = \"/tmp/x\"").is_err());
        assert_eq!(parse("").state_dir, platform::default_state_dir());
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
