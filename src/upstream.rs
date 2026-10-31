//! Which addresses Clash itself must reach over the physical interface: proxy servers
//! and the DNS servers it uses to resolve them.

use crate::config::Config;
use crate::controller::Controller;
use anyhow::{Context, Result};
use ipnet::IpNet;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

const DNS_KEYS: &[&str] = &[
    "default-nameserver",
    "nameserver",
    "fallback",
    "proxy-server-nameserver",
    "direct-nameserver",
];

/// Hostnames, IPs and CIDRs from the config and the mihomo config it points at.
pub fn collect_hosts(cfg: &Config) -> BTreeSet<String> {
    let mut hosts: BTreeSet<String> = cfg.upstreams.iter().map(|s| s.trim().to_string()).collect();
    if let Some(path) = &cfg.mihomo_config {
        match read_yaml(path) {
            Ok(doc) => {
                servers_of(&doc, &mut hosts);
                dns_hosts(&doc, &mut hosts);
                let base = path.parent().unwrap_or(Path::new("."));
                for file in provider_files(&doc, base) {
                    match read_yaml(&file) {
                        Ok(d) => servers_of(&d, &mut hosts),
                        Err(e) => log::warn!("{e:#}"),
                    }
                }
            }
            Err(e) => log::warn!("{e:#}"),
        }
    }
    hosts.retain(|h| !h.is_empty());
    hosts
}

fn read_yaml(path: &Path) -> Result<Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn provider_files(doc: &Value, base: &Path) -> Vec<PathBuf> {
    let Some(Value::Mapping(providers)) = doc.get("proxy-providers") else {
        return Vec::new();
    };
    providers
        .values()
        .filter_map(|p| p.get("path")?.as_str())
        .map(|rel| base.join(rel))
        .collect()
}

fn servers_of(doc: &Value, hosts: &mut BTreeSet<String>) {
    let Some(Value::Sequence(proxies)) = doc.get("proxies") else {
        return;
    };
    for p in proxies {
        if let Some(s) = p.get("server").and_then(Value::as_str) {
            hosts.insert(strip_brackets(s.trim()).to_string());
        }
    }
}

fn dns_hosts(doc: &Value, hosts: &mut BTreeSet<String>) {
    let Some(dns) = doc.get("dns") else { return };
    let mut add = |v: &Value| {
        let list = match v {
            Value::Sequence(l) => l.iter().collect(),
            other => vec![other],
        };
        for s in list.into_iter().filter_map(Value::as_str) {
            if let Some(h) = nameserver_host(s) {
                hosts.insert(h);
            }
        }
    };
    for key in DNS_KEYS {
        if let Some(v) = dns.get(*key) {
            add(v);
        }
    }
    if let Some(Value::Mapping(policy)) = dns.get("nameserver-policy") {
        policy.values().for_each(&mut add);
    }
}

/// `https://dns.alidns.com/dns-query#PROXY` -> `dns.alidns.com`, `tls://223.5.5.5:853` -> `223.5.5.5`.
pub fn nameserver_host(s: &str) -> Option<String> {
    let s = s.split('#').next()?.trim();
    if s.is_empty() || s == "system" || s.starts_with("dhcp://") || s.starts_with("rcode://") {
        return None;
    }
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let authority = rest.split('/').next()?;
    Some(strip_port(authority).to_string()).filter(|h| !h.is_empty())
}

fn strip_port(a: &str) -> &str {
    if let Some(r) = a.strip_prefix('[') {
        return r.split(']').next().unwrap_or(r);
    }
    if a.parse::<IpAddr>().is_ok() {
        return a;
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => h,
        _ => a,
    }
}

fn strip_brackets(s: &str) -> &str {
    s.strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(s)
}

/// Clash fake-ip range. An answer here came from Clash's own DNS and is useless as a firewall target.
fn is_fake(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 18)
}

pub type Cache = BTreeMap<String, Vec<IpAddr>>;
type Lookup = dyn Fn(&str) -> Option<Vec<IpAddr>>;

pub struct Resolved {
    pub nets: Vec<IpNet>,
    pub unresolved: Vec<String>,
}

/// Resolve hostnames with `lookup` (None = cache only). Failed lookups fall back to the last
/// good answer in `cache`, so a restart while Clash is down keeps the previous upstream set.
pub fn resolve(hosts: &BTreeSet<String>, cache: &mut Cache, lookup: Option<&Lookup>) -> Resolved {
    let mut nets = BTreeSet::new();
    let mut unresolved = Vec::new();
    for h in hosts {
        if let Ok(n) = h.parse::<IpNet>() {
            nets.insert(n.trunc());
            continue;
        }
        if let Ok(ip) = h.parse::<IpAddr>() {
            nets.insert(IpNet::from(ip));
            continue;
        }
        let fresh = lookup
            .and_then(|f| f(h))
            .map(clean)
            .filter(|ips| !ips.is_empty());
        if let Some(ips) = fresh {
            cache.insert(h.clone(), ips);
        }
        match cache.get(h) {
            Some(ips) => nets.extend(ips.iter().copied().map(IpNet::from)),
            None => unresolved.push(h.clone()),
        }
    }
    cache.retain(|h, _| hosts.contains(h));
    Resolved {
        nets: nets.into_iter().collect(),
        unresolved,
    }
}

fn clean(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.retain(|ip| !is_fake(ip) && !ip.is_loopback() && !ip.is_unspecified());
    ips.sort();
    ips.dedup();
    ips
}

/// The system resolver goes through Clash's DNS hijack and mostly returns fake-ip answers,
/// so prefer asking mihomo's resolver through the controller.
fn lookup_fn(cfg: &Config) -> Box<Lookup> {
    let ctl = cfg
        .controller
        .as_deref()
        .and_then(|p| Controller::find(p, cfg.controller_secret.as_deref()));
    match ctl {
        Some(c) => Box::new(move |h| match c.resolve(h) {
            Ok(ips) => Some(ips),
            Err(e) => {
                log::debug!("controller lookup {h}: {e:#}");
                None
            }
        }),
        None => Box::new(|h| Some((h, 0).to_socket_addrs().ok()?.map(|a| a.ip()).collect())),
    }
}

fn cache_path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("upstreams.cache")
}

pub fn load_cache(cfg: &Config) -> Cache {
    let Ok(text) = std::fs::read_to_string(cache_path(cfg)) else {
        return Cache::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let host = parts.next()?.to_string();
            let ips: Vec<IpAddr> = parts.filter_map(|p| p.parse().ok()).collect();
            (!ips.is_empty()).then_some((host, ips))
        })
        .collect()
}

pub fn save_cache(cfg: &Config, cache: &Cache) {
    let text: String = cache
        .iter()
        .map(|(h, ips)| {
            let ips: Vec<String> = ips.iter().map(ToString::to_string).collect();
            format!("{h} {}\n", ips.join(" "))
        })
        .collect();
    if let Err(e) = std::fs::write(cache_path(cfg), text) {
        log::debug!("not saving upstream cache: {e}");
    }
}

/// Collect, resolve and persist the upstream set.
pub fn refresh(cfg: &Config, lookup: bool) -> Resolved {
    // Core policy has no address whitelist and needs no DNS bootstrap.
    if cfg.egress == crate::config::Egress::Core {
        return Resolved {
            nets: Vec::new(),
            unresolved: Vec::new(),
        };
    }
    let hosts = collect_hosts(cfg);
    let mut cache = load_cache(cfg);
    let f = lookup.then(|| lookup_fn(cfg));
    let r = resolve(&hosts, &mut cache, f.as_deref());
    if lookup {
        save_cache(cfg, &cache);
    }
    if !r.unresolved.is_empty() {
        log::warn!(
            "unresolved upstreams (blocked until resolvable): {}",
            r.unresolved.join(", ")
        );
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameserver_hosts() {
        let cases = [
            ("https://dns.alidns.com/dns-query", Some("dns.alidns.com")),
            ("https://8.8.8.8/dns-query#PROXY", Some("8.8.8.8")),
            ("tls://223.5.5.5", Some("223.5.5.5")),
            ("tls://1.1.1.1:853", Some("1.1.1.1")),
            ("10.75.128.1", Some("10.75.128.1")),
            ("udp://[2001:db8::1]:53", Some("2001:db8::1")),
            ("2001:db8::1", Some("2001:db8::1")),
            ("system", None),
            ("dhcp://en0", None),
        ];
        for (input, want) in cases {
            assert_eq!(nameserver_host(input).as_deref(), want, "{input}");
        }
    }

    #[test]
    fn collects_servers_dns_and_providers() {
        let dir = std::env::temp_dir().join(format!("dk-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("pp")).unwrap();
        std::fs::write(
            dir.join("config.yaml"),
            r#"
proxies:
  - {name: a, server: 1.2.3.4, port: 443}
proxy-providers:
  p: {type: http, path: ./pp/p.yaml}
dns:
  default-nameserver: [tls://223.5.5.5]
  proxy-server-nameserver: [https://doh.pub/dns-query]
  nameserver-policy:
    +.corp: 10.0.0.53
    geosite:cn: [https://dns.alidns.com/dns-query]
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("pp/p.yaml"),
            "proxies:\n  - {name: b, server: proxy.example}\n",
        )
        .unwrap();
        let cfg = Config {
            mihomo_config: Some(dir.join("config.yaml")),
            ..Config::default()
        };
        let hosts = collect_hosts(&cfg);
        std::fs::remove_dir_all(&dir).unwrap();
        let want = [
            "1.2.3.4",
            "10.0.0.53",
            "223.5.5.5",
            "dns.alidns.com",
            "doh.pub",
            "proxy.example",
        ];
        assert_eq!(hosts.into_iter().collect::<Vec<_>>(), want);
    }

    #[test]
    fn resolve_uses_cache_and_skips_fake_ips() {
        let hosts: BTreeSet<String> = ["9.9.9.9", "10.0.0.0/8", "gone.example"]
            .map(String::from)
            .into();
        let mut cache = Cache::from([("gone.example".into(), vec!["5.6.7.8".parse().unwrap()])]);
        let r = resolve(&hosts, &mut cache, None);
        let fake = |_: &str| Some(vec!["198.18.0.9".parse().unwrap()]);
        let mut empty = Cache::new();
        let only_fake = resolve(&["x.example".to_string()].into(), &mut empty, Some(&fake));
        assert_eq!(only_fake.unresolved, ["x.example"]);
        let nets: Vec<String> = r.nets.iter().map(ToString::to_string).collect();
        assert_eq!(nets, ["5.6.7.8/32", "9.9.9.9/32", "10.0.0.0/8"]);
        assert!(r.unresolved.is_empty());
        assert!(is_fake(&"198.18.0.5".parse().unwrap()));
        assert!(is_fake(&"198.19.255.1".parse().unwrap()));
        assert!(!is_fake(&"198.20.0.1".parse().unwrap()));
    }
}
