//! Policy -> Windows Filtering Platform filters. Pure; the Fwpm* calls live in
//! `platform::windows::wfp`.
//!
//! All filters go into one sublayer of maximum weight. Inside it the highest weight match
//! wins, so every permit outweighs the final block. Across sublayers a block always beats a
//! permit, so permits added elsewhere (Defender rules, other software) cannot reopen a path
//! we block, while their blocks still apply to traffic we pass.
//!
//! Only the ALE connect/accept layers: the scope is sockets of this host. Traffic the host
//! forwards for guests (WSL, VMs, ICS) is out of scope.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::policy::{Policy, Rule};
use ipnet::IpNet;
use std::fmt::Write as _;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    ConnectV4,
    ConnectV6,
    AcceptV4,
    AcceptV6,
}

impl Layer {
    pub const ALL: [Layer; 4] = [
        Layer::ConnectV4,
        Layer::ConnectV6,
        Layer::AcceptV4,
        Layer::AcceptV6,
    ];
    const CONNECT: [Layer; 2] = [Layer::ConnectV4, Layer::ConnectV6];

    pub fn v6(self) -> bool {
        matches!(self, Layer::ConnectV6 | Layer::AcceptV6)
    }

    pub fn name(self) -> &'static str {
        match self {
            Layer::ConnectV4 => "connect-v4",
            Layer::ConnectV6 => "connect-v6",
            Layer::AcceptV4 => "accept-v4",
            Layer::AcceptV6 => "accept-v6",
        }
    }
}

/// One match condition. Conditions on the same field are OR'ed, different fields AND'ed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    Loopback,
    /// Interface LUID.
    LocalInterface(u64),
    /// Executable; WFP matches its app ID (NT device path).
    App(PathBuf),
    Protocol(u8),
    /// For ICMP this field holds the ICMP type.
    LocalPort(u16),
    RemotePort(u16),
    Remote(IpNet),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

impl Action {
    pub fn weight(self) -> u8 {
        match self {
            Action::Permit => 10,
            Action::Block => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub name: &'static str,
    pub layer: Layer,
    pub action: Action,
    pub conds: Vec<Cond>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Persistent filters: enforced from BFE start until removed, daemon or not.
    pub filters: Vec<Filter>,
    /// Enforced from TCP/IP start until BFE loads `filters`.
    pub boot: Vec<Filter>,
    /// Interfaces that do not exist right now; their traffic stays blocked.
    pub missing: Vec<String>,
}

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMPV6: u8 = 58;
const NDP_TYPES: std::ops::RangeInclusive<u16> = 133..=136;

pub fn compile(p: &Policy, luid: &dyn Fn(&str) -> Option<u64>, boot: bool) -> Plan {
    let mut plan = Plan::default();
    if !p.blocking {
        return plan;
    }
    let f = &mut plan.filters;
    let push = |f: &mut Vec<Filter>, name, layer, action, conds| {
        f.push(Filter {
            name,
            layer,
            action,
            conds,
        })
    };
    let family = |nets: &[IpNet], layer: Layer, wrap: fn(IpNet) -> Cond| -> Vec<Cond> {
        nets.iter()
            .filter(|n| matches!(n, IpNet::V6(_)) == layer.v6())
            .map(|n| wrap(*n))
            .collect()
    };

    for rule in &p.rules {
        match rule {
            Rule::Loopback => {
                for l in Layer::ALL {
                    push(f, "loopback", l, Action::Permit, vec![Cond::Loopback]);
                }
            }
            Rule::Interface(name) => match luid(name) {
                Some(id) => {
                    for l in Layer::ALL {
                        push(
                            f,
                            "interface",
                            l,
                            Action::Permit,
                            vec![Cond::LocalInterface(id)],
                        );
                    }
                }
                None => plan.missing.push(name.clone()),
            },
            Rule::Core { to } => {
                // Config validation guarantees a program on Windows.
                let Some(app) = &p.core.program else { continue };
                for l in Layer::CONNECT {
                    let mut conds = vec![
                        Cond::App(app.clone()),
                        Cond::Protocol(TCP),
                        Cond::Protocol(UDP),
                    ];
                    if let Some(nets) = to {
                        let remote = family(nets, l, Cond::Remote);
                        if remote.is_empty() {
                            continue;
                        }
                        conds.extend(remote);
                    }
                    push(f, "clash core", l, Action::Permit, conds);
                }
            }
            Rule::Program(path) => {
                for l in Layer::CONNECT {
                    let conds = vec![
                        Cond::App(path.clone()),
                        Cond::Protocol(TCP),
                        Cond::Protocol(UDP),
                    ];
                    push(f, "allowed program", l, Action::Permit, conds);
                }
            }
            Rule::Networks(nets) => {
                for l in Layer::ALL {
                    let remote = family(nets, l, Cond::Remote);
                    if !remote.is_empty() {
                        push(f, "allowed networks", l, Action::Permit, remote);
                    }
                }
            }
            Rule::Dhcp => dhcp(f),
        }
    }
    for l in Layer::ALL {
        push(f, "block everything else", l, Action::Block, Vec::new());
    }

    if boot {
        let b = &mut plan.boot;
        for l in Layer::ALL {
            push(b, "boot: loopback", l, Action::Permit, vec![Cond::Loopback]);
        }
        if p.rules.contains(&Rule::Dhcp) {
            dhcp(b);
        }
        for l in Layer::ALL {
            push(b, "boot: block everything", l, Action::Block, Vec::new());
        }
    }
    plan
}

fn dhcp(f: &mut Vec<Filter>) {
    let udp = |local, remote| {
        vec![
            Cond::Protocol(UDP),
            Cond::LocalPort(local),
            Cond::RemotePort(remote),
        ]
    };
    for (layers, local, remote) in [
        ([Layer::ConnectV4, Layer::AcceptV4], 68, 67),
        ([Layer::ConnectV6, Layer::AcceptV6], 546, 547),
    ] {
        for layer in layers {
            f.push(Filter {
                name: "dhcp",
                layer,
                action: Action::Permit,
                conds: udp(local, remote),
            });
        }
    }
    for layer in [Layer::ConnectV6, Layer::AcceptV6] {
        let mut conds = vec![Cond::Protocol(ICMPV6)];
        conds.extend(NDP_TYPES.map(Cond::LocalPort));
        f.push(Filter {
            name: "ndp",
            layer,
            action: Action::Permit,
            conds,
        });
    }
}

fn describe_cond(c: &Cond) -> String {
    match c {
        Cond::Loopback => "loopback".into(),
        Cond::LocalInterface(id) => format!("if {id:#x}"),
        Cond::App(p) => format!("app {:?}", p.display().to_string()),
        Cond::Protocol(n) => format!("proto {n}"),
        Cond::LocalPort(n) => format!("lport {n}"),
        Cond::RemotePort(n) => format!("rport {n}"),
        Cond::Remote(n) => format!("remote {n}"),
    }
}

pub fn describe(plan: &Plan) -> String {
    let mut r = String::from("# Generated by daemon-killer: WFP filters in our sublayer.\n");
    for name in &plan.missing {
        let _ = writeln!(
            r,
            "# interface {name:?} not present: its traffic stays blocked"
        );
    }
    for (tag, list) in [("", &plan.filters), ("boot ", &plan.boot)] {
        for f in list {
            let conds: Vec<String> = f.conds.iter().map(describe_cond).collect();
            let _ = writeln!(
                r,
                "{tag}{:<10} {:<6} w{:<2} [{}]  # {}",
                f.layer.name(),
                match f.action {
                    Action::Permit => "permit",
                    Action::Block => "block",
                },
                f.action.weight(),
                conds.join(", "),
                f.name
            );
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Egress};

    fn cfg() -> Config {
        Config {
            tun_device: "Mihomo".into(),
            core_program: Some(r"C:\Clash\mihomo.exe".into()),
            allow_dhcp: false,
            ..Config::default()
        }
    }

    fn tun_only(name: &str) -> Option<u64> {
        (name == "Mihomo").then_some(0x42)
    }

    #[test]
    fn every_layer_ends_in_a_block() {
        let plan = compile(&Policy::build(&cfg(), &[]), &tun_only, false);
        for l in Layer::ALL {
            let blocks: Vec<_> = plan
                .filters
                .iter()
                .filter(|f| f.layer == l && f.action == Action::Block)
                .collect();
            assert_eq!(blocks.len(), 1, "{l:?}");
            assert!(blocks[0].conds.is_empty());
        }
        assert!(plan.boot.is_empty());
    }

    #[test]
    fn strict_core_only_reaches_upstreams_per_family() {
        let ups = ["1.2.3.4/32".parse().unwrap()];
        let plan = compile(&Policy::build(&cfg(), &ups), &tun_only, false);
        let core: Vec<_> = plan
            .filters
            .iter()
            .filter(|f| f.name == "clash core")
            .collect();
        // No IPv6 upstream, so the core gets no IPv6 permit at all.
        assert_eq!(core.len(), 1);
        assert_eq!(core[0].layer, Layer::ConnectV4);
        assert!(core[0].conds.contains(&Cond::Remote(ups[0])));
        assert!(core[0]
            .conds
            .contains(&Cond::App(r"C:\Clash\mihomo.exe".into())));
    }

    #[test]
    fn core_mode_permits_the_core_anywhere() {
        let c = Config {
            egress: Egress::Core,
            ..cfg()
        };
        let plan = compile(&Policy::build(&c, &[]), &tun_only, false);
        let core: Vec<_> = plan
            .filters
            .iter()
            .filter(|f| f.name == "clash core")
            .collect();
        assert_eq!(core.len(), 2);
        assert!(core
            .iter()
            .all(|f| !f.conds.iter().any(|c| matches!(c, Cond::Remote(_)))));
    }

    #[test]
    fn missing_tun_fails_closed() {
        let plan = compile(&Policy::build(&cfg(), &[]), &|_| None, false);
        assert_eq!(plan.missing, ["Mihomo"]);
        assert!(!plan.filters.iter().any(|f| f.name == "interface"));
        assert!(describe(&plan).contains("not present"));
    }

    #[test]
    fn dhcp_and_boot_filters() {
        let c = Config {
            allow_dhcp: true,
            ..cfg()
        };
        let plan = compile(&Policy::build(&c, &[]), &tun_only, true);
        assert_eq!(plan.filters.iter().filter(|f| f.name == "dhcp").count(), 4);
        let ndp = plan.filters.iter().find(|f| f.name == "ndp").unwrap();
        assert!(ndp.layer.v6());
        assert_eq!(ndp.conds.len(), 1 + 4);
        assert!(plan.boot.iter().any(|f| f.name == "dhcp"));
        assert_eq!(
            plan.boot
                .iter()
                .filter(|f| f.action == Action::Block)
                .count(),
            Layer::ALL.len()
        );
    }

    #[test]
    fn open_policy_has_no_filters() {
        assert_eq!(compile(&Policy::open(), &tun_only, true), Plan::default());
    }
}
