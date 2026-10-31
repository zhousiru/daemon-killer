//! Everything OS-specific. Each platform module exports the same set of items:
//!
//! - `NativeFirewall`: the `firewall::Firewall` backend
//! - `service`: install/run/query the daemon and the install rollback guard
//! - `DEFAULT_TUN`, `EXAMPLE_CONFIG`, `default_config_path`, `default_state_dir`
//! - `is_elevated`, `iface_up`, `process_running`, `kill_processes`, `notify`,
//!   `secure_dir`, `init_logging`
//!
//! Process names match exactly on macOS and case-insensitively, `.exe` optional, on Windows.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;

/// Whether the daemon is registered with launchd / the service manager, and running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    NotInstalled,
    Stopped,
    Running,
}
