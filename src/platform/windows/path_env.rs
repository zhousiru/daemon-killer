//! The machine PATH (`HKLM\...\Session Manager\Environment\Path`), edited in place like an
//! installer does: keep the value type (usually REG_EXPAND_SZ), never truncate (unlike
//! `setx`), and tell running programs so new terminals see the change.

use super::wide;
use anyhow::{bail, Result};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};

const KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

fn same_dir(entry: &str, dir: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('\\').to_ascii_lowercase();
    !entry.trim().is_empty() && norm(entry) == norm(dir)
}

/// `None` when `dir` is already present.
fn with_dir(path: &str, dir: &str) -> Option<String> {
    if path.split(';').any(|e| same_dir(e, dir)) {
        return None;
    }
    let base = path.trim_end_matches(';');
    Some(if base.is_empty() {
        dir.to_string()
    } else {
        format!("{base};{dir}")
    })
}

/// `None` when `dir` is absent.
fn without_dir(path: &str, dir: &str) -> Option<String> {
    let kept: Vec<&str> = path.split(';').filter(|e| !same_dir(e, dir)).collect();
    (kept.len() != path.split(';').count()).then(|| kept.join(";"))
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: opened by RegOpenKeyExW, closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn open() -> Result<Key> {
    let name = wide(KEY);
    let mut h = null_mut();
    // SAFETY: valid NUL-terminated subkey and out pointer.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &mut h,
        )
    };
    if rc != NO_ERROR {
        bail!("opening HKLM\\{KEY}: error {rc}");
    }
    Ok(Key(h))
}

fn read(key: &Key) -> Result<(String, REG_VALUE_TYPE)> {
    let name = wide("Path");
    let (mut kind, mut size) = (0, 0u32);
    // SAFETY: size query with a null buffer, then a read into a buffer of that size.
    unsafe {
        let rc = RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            null_mut(),
            &mut size,
        );
        if rc != NO_ERROR {
            bail!("reading PATH: error {rc}");
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2)];
        let rc = RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            buf.as_mut_ptr().cast(),
            &mut size,
        );
        if rc != NO_ERROR {
            bail!("reading PATH: error {rc}");
        }
        if kind != REG_EXPAND_SZ && kind != REG_SZ {
            bail!("PATH has unexpected registry type {kind}");
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Ok((String::from_utf16_lossy(&buf[..len]), kind))
    }
}

fn write(key: &Key, value: &str, kind: REG_VALUE_TYPE) -> Result<()> {
    let name = wide("Path");
    let data = wide(value);
    // SAFETY: `data` is NUL-terminated and its byte length is passed.
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            kind,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    if rc != NO_ERROR {
        bail!("writing PATH: error {rc}");
    }
    let env = wide("Environment");
    let mut result = 0;
    // SAFETY: broadcast with a NUL-terminated string; hung windows are skipped.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            env.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        )
    };
    Ok(())
}

/// Returns whether PATH changed.
pub fn add(dir: &Path) -> Result<bool> {
    let key = open()?;
    let (path, kind) = read(&key)?;
    match with_dir(&path, &dir.to_string_lossy()) {
        Some(new) => write(&key, &new, kind).map(|()| true),
        None => Ok(false),
    }
}

/// Returns whether PATH changed.
pub fn remove(dir: &Path) -> Result<bool> {
    let key = open()?;
    let (path, kind) = read(&key)?;
    match without_dir(&path, &dir.to_string_lossy()) {
        Some(new) => write(&key, &new, kind).map(|()| true),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = r"C:\Program Files\daemon-killer";

    #[test]
    fn add_is_idempotent_and_case_insensitive() {
        assert_eq!(
            with_dir(r"%SystemRoot%\system32;C:\Tools;", DIR).unwrap(),
            r"%SystemRoot%\system32;C:\Tools;C:\Program Files\daemon-killer"
        );
        assert_eq!(with_dir("", DIR).unwrap(), DIR);
        assert!(with_dir(r"C:\A;c:\program files\DAEMON-KILLER\;C:\B", DIR).is_none());
    }

    #[test]
    fn remove_keeps_everything_else() {
        assert_eq!(
            without_dir(r"C:\A;C:\Program Files\daemon-killer\;C:\B", DIR).unwrap(),
            r"C:\A;C:\B"
        );
        assert!(without_dir(r"C:\A;C:\B", DIR).is_none());
        // An empty entry is not ours, so it survives untouched.
        assert_eq!(
            without_dir(r"C:\A;;C:\Program Files\daemon-killer", DIR).unwrap(),
            r"C:\A;"
        );
    }
}
