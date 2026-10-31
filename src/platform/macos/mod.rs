//! macOS: pf for enforcement, launchd for the daemon.

pub mod launchd;
mod pf;

pub use launchd as service;
pub use pf::Pf as NativeFirewall;

use anyhow::Result;
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const DEFAULT_TUN: &str = "utun1500";
pub const EXAMPLE_CONFIG: &str = include_str!("../../../config/macos.example.toml");

pub fn default_config_path() -> PathBuf {
    "/etc/daemon-killer/config.toml".into()
}

pub fn default_state_dir() -> PathBuf {
    "/var/db/daemon-killer".into()
}

pub fn is_elevated() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// launchd already sends stdout/stderr to the log file. Commands only show warnings, next to
/// their own output.
pub fn init_logging(daemon: bool) {
    let level = if daemon { "info" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();
}

/// Root-owned directories under /etc and /var/db need nothing extra.
pub fn secure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

pub fn iface_up(name: &str) -> bool {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we walk read-only and free once.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return false;
        }
        let mut up = false;
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if CStr::from_ptr(ifa.ifa_name).to_bytes() == name.as_bytes()
                && ifa.ifa_flags & libc::IFF_UP as u32 != 0
            {
                up = true;
                break;
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
        up
    }
}

pub fn process_running(name: &str) -> bool {
    Command::new("/usr/bin/pgrep")
        .args(["-x", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Names of the processes that were killed.
pub fn kill_processes(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            Command::new("/usr/bin/pkill")
                .args(["-x", name])
                .status()
                .is_ok_and(|s| s.success())
        })
        .cloned()
        .collect()
}

/// Best-effort desktop notification for the console user.
pub fn notify(msg: &str) {
    use std::os::unix::fs::MetadataExt;
    let Ok(uid) = std::fs::metadata("/dev/console").map(|m| m.uid()) else {
        return;
    };
    if uid == 0 {
        return;
    }
    let script = format!("display notification {msg:?} with title \"daemon-killer\"");
    let _ = Command::new("/bin/launchctl")
        .args([
            "asuser",
            &uid.to_string(),
            "/usr/bin/osascript",
            "-e",
            &script,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_is_up_and_bogus_is_not() {
        assert!(super::iface_up("lo0"));
        assert!(!super::iface_up("utun9999"));
    }
}
