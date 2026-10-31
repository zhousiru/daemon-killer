//! LaunchDaemon for the enforcement loop and a one-shot launchd job that turns protection off
//! when `up` is not confirmed.

use crate::platform::DaemonState;
use anyhow::{ensure, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;

const LABEL: &str = "com.daemonkiller";
const PLIST: &str = "/Library/LaunchDaemons/com.daemonkiller.plist";
const BIN: &str = "/usr/local/bin/daemon-killer";
const LOG: &str = "/var/log/daemon-killer.log";

pub fn log_path() -> PathBuf {
    LOG.into()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn plist(config: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{BIN}</string>
    <string>--config</string>
    <string>{}</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{LOG}</string>
  <key>StandardErrorPath</key><string>{LOG}</string>
</dict>
</plist>
"#,
        esc(&config.display().to_string())
    )
}

/// Output is captured so it never mixes into ours; it is part of the error instead.
fn launchctl(args: &[&str]) -> Result<()> {
    let out = Command::new("/bin/launchctl").args(args).output()?;
    ensure!(
        out.status.success(),
        "launchctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

pub fn binary_path() -> PathBuf {
    BIN.into()
}

pub fn install_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    if exe != Path::new(BIN) {
        let tmp = format!("{BIN}.new");
        std::fs::create_dir_all("/usr/local/bin")?;
        std::fs::copy(&exe, &tmp)?;
        std::fs::rename(&tmp, BIN)?;
    }
    Ok(BIN.into())
}

/// /usr/local/bin is on PATH already.
pub fn add_to_path() -> Result<bool> {
    Ok(false)
}

/// Write the LaunchDaemon without loading it.
pub fn register(_bin: &Path, config: &Path) -> Result<()> {
    std::fs::write(PLIST, plist(config))?;
    Ok(())
}

/// (Re)load, so launchd and the daemon read the plist and config again.
pub fn restart() -> Result<()> {
    stop();
    // bootout returns before the job is fully gone; bootstrap fails until it is.
    let mut last = Ok(());
    for _ in 0..10 {
        last = launchctl(&["bootstrap", "system", PLIST]);
        if last.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    last
}

pub fn daemon_state() -> DaemonState {
    if !Path::new(PLIST).exists() {
        return DaemonState::NotInstalled;
    }
    match Command::new("/bin/launchctl")
        .args(["print", &format!("system/{LABEL}")])
        .output()
    {
        Ok(o)
            if o.status.success()
                && String::from_utf8_lossy(&o.stdout).contains("state = running") =>
        {
            DaemonState::Running
        }
        _ => DaemonState::Stopped,
    }
}

/// pf rules stay in the kernel; only the loop stops.
pub fn stop() {
    let _ = launchctl(&["bootout", &format!("system/{LABEL}")]);
}

/// `remove_files` deletes the plist.
pub fn unregister() {
    stop();
}

pub fn remove_files() {
    for f in [PLIST, BIN] {
        if let Err(e) = std::fs::remove_file(f) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("removing {f}: {e}");
            }
        }
    }
}

pub struct Guard {
    label: String,
    plist: PathBuf,
}

/// Independent launchd job: keeps running if the interactive `up` dies.
pub fn start_guard(bin: &Path, config: &Path, ticket: &Path, seconds: u64) -> Result<Guard> {
    let dir = ticket.parent().unwrap_or(Path::new("/"));
    let label = format!("{LABEL}.rollback-{}", std::process::id());
    let plist = dir.join(format!("rollback-{}.plist", std::process::id()));
    std::fs::write(
        &plist,
        format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
         <key>Label</key><string>{label}</string>\
         <key>ProgramArguments</key><array><string>{}</string>\
         <string>-c</string><string>{}</string><string>rollback</string>\
         <string>--ticket</string><string>{}</string>\
         <string>--seconds</string><string>{seconds}</string></array>\
         <key>RunAtLoad</key><true/></dict></plist>",
            esc(&bin.display().to_string()),
            esc(&config.display().to_string()),
            esc(&ticket.display().to_string()),
        ),
    )?;
    launchctl(&["bootstrap", "system", &plist.to_string_lossy()])?;
    Ok(Guard { label, plist })
}

pub fn stop_guard(g: Guard) {
    let _ = launchctl(&["bootout", &format!("system/{}", g.label)]);
    let _ = std::fs::remove_file(&g.plist);
}

/// launchd runs us as a plain process and stops us with SIGTERM.
pub fn run(body: impl FnOnce(mpsc::Receiver<()>) -> Result<()>) -> Result<()> {
    let (_keep, stop) = mpsc::channel();
    body(stop)
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_escapes_and_lints() {
        let p = super::plist(std::path::Path::new("/etc/a&b/config.toml"));
        assert!(p.contains("/etc/a&amp;b/config.toml"));
        let tmp = std::env::temp_dir().join(format!("dk-{}.plist", std::process::id()));
        std::fs::write(&tmp, p).unwrap();
        let ok = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&tmp)
            .status();
        std::fs::remove_file(&tmp).unwrap();
        if let Ok(st) = ok {
            assert!(st.success());
        }
    }
}
