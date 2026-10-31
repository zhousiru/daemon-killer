//! macOS: pf for enforcement, launchd for the daemon.

pub mod launchd;
mod pf;

pub use launchd as service;
pub use pf::Pf as NativeFirewall;

use crate::notify::Delivery;
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

/// The user at the console; root owns it at the login window.
fn console_uid() -> Option<libc::uid_t> {
    // SAFETY: stat fills a zeroed struct for a NUL-terminated path.
    let uid = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::stat(c"/dev/console".as_ptr(), &mut st) == 0).then_some(st.st_uid)
    };
    uid.filter(|&u| u != 0)
}

/// A LaunchDaemon has no GUI session; run osascript in the console user's, as that user.
/// The text goes in as arguments, never into the script. Notifications show as from
/// Script Editor and leave nothing of ours behind.
pub fn notify(title: &str, body: &str) -> Delivery {
    let Some(uid) = console_uid() else {
        return Delivery::NoUser;
    };
    let child = Command::new("/bin/launchctl")
        .args(["asuser", &uid.to_string(), "/usr/bin/sudo", "-u"])
        .arg(format!("#{uid}"))
        .args([
            "/usr/bin/osascript",
            "-e",
            "on run argv",
            "-e",
            "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e",
            "end run",
            title,
            body,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(mut c) => {
            std::thread::spawn(move || c.wait());
        }
        Err(e) => log::warn!("notifying: {e}"),
    }
    Delivery::Sent
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_is_up_and_bogus_is_not() {
        assert!(super::iface_up("lo0"));
        assert!(!super::iface_up("utun9999"));
    }
}
