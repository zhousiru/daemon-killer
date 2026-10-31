//! Minimal HTTP/1.0 client for the mihomo external controller over a unix socket (macOS),
//! a named pipe (Windows) or TCP.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(3);
const PIPE_DIR: &str = r"\\.\pipe\";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    Tcp(String),
    /// Unix socket or named pipe.
    Local(PathBuf),
}

pub struct Controller {
    endpoint: Endpoint,
    secret: Option<String>,
}

impl Controller {
    /// `tcp://host:port`, or a socket/pipe path with at most one `*` in its last component;
    /// the newest match wins.
    pub fn find(spec: &str, secret: Option<&str>) -> Option<Self> {
        let endpoint = match spec.strip_prefix("tcp://") {
            Some(addr) => Endpoint::Tcp(addr.to_string()),
            None => Endpoint::Local(expand(spec)?),
        };
        Some(Controller {
            endpoint,
            secret: secret.map(String::from),
        })
    }

    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut resp = Vec::new();
        match &self.endpoint {
            Endpoint::Tcp(addr) => {
                let sa = addr
                    .to_socket_addrs()?
                    .next()
                    .with_context(|| format!("resolving {addr}"))?;
                let mut s = TcpStream::connect_timeout(&sa, TIMEOUT)?;
                s.set_read_timeout(Some(TIMEOUT))?;
                s.set_write_timeout(Some(TIMEOUT))?;
                s.write_all(request)?;
                s.read_to_end(&mut resp)?;
            }
            Endpoint::Local(path) => resp = local_exchange(path, request)?,
        }
        Ok(resp)
    }

    pub fn get(&self, path: &str) -> Result<String> {
        let auth = self
            .secret
            .as_ref()
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n{auth}\r\n");
        let resp = self.exchange(req.as_bytes())?;
        let resp = String::from_utf8_lossy(&resp);
        let (head, body) = resp
            .split_once("\r\n\r\n")
            .context("malformed HTTP response")?;
        let status = head.split_whitespace().nth(1).unwrap_or("");
        if status != "200" {
            bail!("GET {path}: HTTP {status}");
        }
        Ok(body.to_string())
    }

    pub fn alive(&self) -> bool {
        self.get("/version").is_ok()
    }

    /// Resolve through mihomo's real resolver. Unlike the system resolver this never
    /// hands back fake-ip answers.
    pub fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
        {
            bail!("refusing to query odd hostname {host:?}");
        }
        let mut ips = Vec::new();
        for qtype in ["A", "AAAA"] {
            let body = self.get(&format!("/dns/query?name={host}&type={qtype}"))?;
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let answers = v
                .get("Answer")
                .and_then(|a| a.as_array())
                .into_iter()
                .flatten();
            ips.extend(
                answers
                    .filter(|a| matches!(a.get("type").and_then(|t| t.as_u64()), Some(1 | 28)))
                    .filter_map(|a| a.get("data")?.as_str()?.parse::<IpAddr>().ok()),
            );
        }
        Ok(ips)
    }
}

#[cfg(unix)]
fn local_exchange(path: &Path, request: &[u8]) -> Result<Vec<u8>> {
    let mut s = std::os::unix::net::UnixStream::connect(path)
        .with_context(|| format!("connecting {}", path.display()))?;
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    s.write_all(request)?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp)?;
    Ok(resp)
}

/// Pipe handles opened as files have no timeouts, so a hung core costs one parked thread
/// instead of the enforcement loop.
#[cfg(windows)]
fn local_exchange(path: &Path, request: &[u8]) -> Result<Vec<u8>> {
    let (path, request) = (path.to_path_buf(), request.to_vec());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = (|| -> Result<Vec<u8>> {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .with_context(|| format!("connecting {}", path.display()))?;
            f.write_all(&request)?;
            let mut resp = Vec::new();
            // The server closing its end reads as EOF.
            f.read_to_end(&mut resp)?;
            Ok(resp)
        })();
        let _ = tx.send(r);
    });
    rx.recv_timeout(TIMEOUT)
        .map_err(|_| anyhow::anyhow!("controller pipe timed out"))?
}

fn glob_match(name: &str, prefix: &str, suffix: &str) -> bool {
    name.len() >= prefix.len() + suffix.len() && name.starts_with(prefix) && name.ends_with(suffix)
}

fn expand(pattern: &str) -> Option<PathBuf> {
    if !pattern.contains('*') {
        return Some(pattern.into());
    }
    // Pipe names are flat and may contain `\` (`MihomoParty\mihomo-admin-...`).
    let pipe = pattern
        .get(..PIPE_DIR.len())
        .filter(|p| p.eq_ignore_ascii_case(PIPE_DIR))
        .map(|_| &pattern[PIPE_DIR.len()..]);
    let (dir, file) = match pipe {
        Some(name) => (Path::new(PIPE_DIR), name),
        None => {
            let path = Path::new(pattern);
            (path.parent()?, path.file_name()?.to_str()?)
        }
    };
    let (prefix, suffix) = file.split_once('*')?;
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| glob_match(&e.file_name().to_string_lossy(), prefix, suffix))
        .max_by_key(|e| (e.metadata().and_then(|m| m.modified()).ok(), e.file_name()))
        .map(|e| dir.join(e.file_name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let c = Controller::find("tcp://127.0.0.1:9090", None).unwrap();
        assert_eq!(c.endpoint, Endpoint::Tcp("127.0.0.1:9090".into()));
        let c = Controller::find(r"\\.\pipe\verge-mihomo", None).unwrap();
        assert_eq!(c.endpoint, Endpoint::Local(r"\\.\pipe\verge-mihomo".into()));
        assert!(glob_match(
            r"MihomoParty\mihomo-admin-alice-28488",
            r"MihomoParty\mihomo-",
            ""
        ));
        assert!(!glob_match("mihomo-", "mihomo-", "-"));
    }

    /// Talks to the local mihomo controller (read-only DNS query): `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn live_resolve() {
        let spec = if cfg!(windows) {
            r"\\.\pipe\MihomoParty\mihomo-*"
        } else {
            "/tmp/mihomo-party-*.sock"
        };
        let c = Controller::find(spec, None).unwrap();
        println!("{:?} {:?}", c.endpoint, c.resolve("doh.pub"));
    }
}
