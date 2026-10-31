//! What may pass, independent of the OS firewall. Backends compile a `Policy` into pf rules
//! or WFP filters; anything a policy does not pass is blocked.

use crate::config::{Config, Egress};
use ipnet::IpNet;
use std::path::PathBuf;

const LAN: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// How the firewall recognises the Clash core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Core {
    /// macOS: socket owner.
    pub uid: u32,
    /// Windows: executable (WFP app ID).
    pub program: Option<PathBuf>,
}

/// One pass rule. Order matters only for readability: every rule is a pass, the block is
/// implied and always loses to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// All loopback traffic.
    Loopback,
    /// All traffic in and out of an interface (the TUN, VM bridges).
    Interface(String),
    /// Outbound TCP/UDP of the Clash core; `to: None` means anywhere.
    Core { to: Option<Vec<IpNet>> },
    /// Outbound TCP/UDP of another trusted executable (Windows only).
    Program(PathBuf),
    /// Any traffic to or from these networks.
    Networks(Vec<IpNet>),
    /// DHCPv4, DHCPv6 and IPv6 neighbour discovery.
    Dhcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// False while paused: nothing is blocked and `rules` is empty.
    pub blocking: bool,
    pub core: Core,
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn open() -> Self {
        Policy {
            blocking: false,
            core: Core {
                uid: 0,
                program: None,
            },
            rules: Vec::new(),
        }
    }

    pub fn build(cfg: &Config, upstreams: &[IpNet]) -> Self {
        let mut rules = vec![Rule::Loopback, Rule::Interface(cfg.tun_device.clone())];
        rules.extend(cfg.allow_interfaces.iter().cloned().map(Rule::Interface));
        rules.push(Rule::Core {
            to: (cfg.egress == Egress::Strict).then(|| upstreams.to_vec()),
        });
        rules.extend(cfg.allow_programs.iter().cloned().map(Rule::Program));
        let mut allow = cfg.allow_cidrs.clone();
        if cfg.allow_lan {
            allow.extend(LAN.iter().map(|s| s.parse::<IpNet>().unwrap()));
        }
        if !allow.is_empty() {
            rules.push(Rule::Networks(allow));
        }
        if cfg.allow_dhcp {
            rules.push(Rule::Dhcp);
        }
        Policy {
            blocking: true,
            core: Core {
                uid: cfg.core_uid,
                program: cfg.core_program.clone(),
            },
            rules,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_mode_has_no_address_list_and_strict_has_one() {
        let ups: Vec<IpNet> = vec!["1.2.3.4/32".parse().unwrap()];
        let core = Policy::build(
            &Config {
                egress: Egress::Core,
                ..Config::default()
            },
            &ups,
        );
        assert!(core.rules.contains(&Rule::Core { to: None }));
        let strict = Policy::build(&Config::default(), &ups);
        assert!(strict.rules.contains(&Rule::Core {
            to: Some(ups.clone())
        }));
    }

    #[test]
    fn lan_and_cidrs_become_one_network_rule() {
        let cfg = Config {
            allow_lan: true,
            allow_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
            allow_dhcp: false,
            ..Config::default()
        };
        let p = Policy::build(&cfg, &[]);
        let nets = p
            .rules
            .iter()
            .find_map(|r| match r {
                Rule::Networks(n) => Some(n),
                _ => None,
            })
            .unwrap();
        assert_eq!(nets.len(), LAN.len() + 1);
        assert!(!p.rules.contains(&Rule::Dhcp));
    }

    #[test]
    fn tun_is_the_first_interface() {
        let cfg = Config {
            tun_device: "utun7".into(),
            allow_interfaces: vec!["bridge100".into()],
            ..Config::default()
        };
        let p = Policy::build(&cfg, &[]);
        let ifs: Vec<&str> = p
            .rules
            .iter()
            .filter_map(|r| match r {
                Rule::Interface(i) => Some(i.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(ifs, ["utun7", "bridge100"]);
        assert!(Policy::open().rules.is_empty());
    }
}
