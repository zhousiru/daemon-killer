//! Toasts. The service runs in session 0, which has no desktop, so it starts this binary as
//! the user at the console (`daemon-killer notify`) to show them under our AppUserModelId.
//! The id is registered machine-wide by `install`; `uninstall` removes it along with what
//! Windows keeps for it per user.

use super::{wide, Handle};
use crate::notify::Delivery;
use anyhow::{bail, Context, Result};
use std::ptr::{null, null_mut};
use windows::core::HSTRING;
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE, LUID,
    WIN32_ERROR,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Environment::{
    CreateEnvironmentBlock, DestroyEnvironmentBlock, ExpandEnvironmentStringsW,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegEnumKeyExW, RegLoadKeyW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW, RegUnLoadKeyW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS,
    KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows_sys::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

const AUMID: &str = "daemon-killer";
const AUMID_KEY: &str = r"SOFTWARE\Classes\AppUserModelId\daemon-killer";
/// Created by Windows in each user's hive once a toast from us was shown.
const SETTINGS_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\daemon-killer";
const PROFILES_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
/// Where an offline user's hive is mounted while we clean it.
const MOUNT: &str = "daemon-killer-cleanup";

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: opened by RegOpenKeyExW/RegCreateKeyExW, closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn check(rc: WIN32_ERROR, what: &str) -> Result<()> {
    if rc != ERROR_SUCCESS {
        bail!("{what}: {}", std::io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

fn open(root: HKEY, path: &str, access: u32) -> Option<Key> {
    let name = wide(path);
    let mut h = null_mut();
    // SAFETY: NUL-terminated subkey and a valid out pointer.
    let rc = unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, access, &mut h) };
    (rc == ERROR_SUCCESS).then(|| Key(h))
}

/// Missing is fine.
fn delete_tree(root: HKEY, path: &str) -> Result<()> {
    let name = wide(path);
    // SAFETY: NUL-terminated subkey; this removes the key itself as well.
    let rc = unsafe { RegDeleteTreeW(root, name.as_ptr()) };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check(rc, &format!("deleting {path}"))
}

fn subkeys(key: &Key) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0.. {
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` characters; the other outputs are optional.
        let rc = unsafe {
            RegEnumKeyExW(
                key.0,
                i,
                buf.as_mut_ptr(),
                &mut len,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc == ERROR_SUCCESS {
            out.push(String::from_utf16_lossy(&buf[..len as usize]));
        }
    }
    out
}

fn string_value(key: &Key, name: &str) -> Option<String> {
    let name = wide(name);
    let mut buf = [0u16; 1024];
    let mut size = std::mem::size_of_val(&buf) as u32;
    // SAFETY: `buf` holds `size` bytes.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let raw = wide(String::from_utf16_lossy(&buf[..len]));
    let mut out = [0u16; 1024];
    // SAFETY: both buffers are NUL-terminated and sized; ProfileImagePath uses %vars%.
    let n = unsafe { ExpandEnvironmentStringsW(raw.as_ptr(), out.as_mut_ptr(), out.len() as u32) };
    (n > 0 && (n as usize) <= out.len()).then(|| String::from_utf16_lossy(&out[..n as usize - 1]))
}

/// Lets Windows show our toasts with a name.
pub fn register() -> Result<()> {
    let path = wide(AUMID_KEY);
    let mut h = null_mut();
    // SAFETY: NUL-terminated subkey and a valid out pointer.
    check(
        unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                null(),
                &mut h,
                null_mut(),
            )
        },
        &format!("creating HKLM\\{AUMID_KEY}"),
    )?;
    let key = Key(h);
    let (name, data) = (wide("DisplayName"), wide("daemon-killer"));
    // SAFETY: `data` is NUL-terminated and its byte length is passed.
    check(
        unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        },
        "setting the notification display name",
    )
}

/// Our toasts in the calling user's notification center, every user's notification setting
/// for us, then the registration.
pub fn unregister() {
    if let Err(e) =
        ToastNotificationManager::History().and_then(|h| h.ClearWithId(&HSTRING::from(AUMID)))
    {
        log::warn!("clearing notifications: {e}");
    }
    if let Err(e) = clean_user_hives() {
        log::warn!("removing notification settings: {e:#}");
    }
    if let Err(e) = delete_tree(HKEY_LOCAL_MACHINE, AUMID_KEY) {
        log::warn!("{e:#}");
    }
}

fn clean_user_hives() -> Result<()> {
    let users = open(HKEY_USERS, "", KEY_ENUMERATE_SUB_KEYS).context("opening HKEY_USERS")?;
    let loaded = subkeys(&users);
    for sid in loaded.iter().filter(|s| !s.ends_with("_Classes")) {
        delete_tree(HKEY_USERS, &format!(r"{sid}\{SETTINGS_KEY}"))?;
    }
    drop(users);
    // Users who are not logged in: mount their hive for a moment.
    let profiles = open(HKEY_LOCAL_MACHINE, PROFILES_KEY, KEY_ENUMERATE_SUB_KEYS)
        .context("opening the profile list")?;
    let offline: Vec<String> = subkeys(&profiles)
        .into_iter()
        .filter(|sid| !loaded.contains(sid))
        .filter_map(|sid| {
            let key = open(profiles.0, &sid, KEY_QUERY_VALUE)?;
            string_value(&key, "ProfileImagePath")
        })
        .map(|dir| format!(r"{dir}\NTUSER.DAT"))
        .filter(|hive| std::path::Path::new(hive).exists())
        .collect();
    drop(profiles);
    if offline.is_empty() {
        return Ok(());
    }
    enable_privileges(&["SeBackupPrivilege", "SeRestorePrivilege"])?;
    for hive in offline {
        let (mount, file) = (wide(MOUNT), wide(&hive));
        // SAFETY: NUL-terminated mount name and file path.
        if unsafe { RegLoadKeyW(HKEY_USERS, mount.as_ptr(), file.as_ptr()) } != ERROR_SUCCESS {
            continue;
        }
        let deleted = delete_tree(HKEY_USERS, &format!(r"{MOUNT}\{SETTINGS_KEY}"));
        // SAFETY: the hive was mounted above and no handle into it is open any more.
        let rc = unsafe { RegUnLoadKeyW(HKEY_USERS, mount.as_ptr()) };
        check(rc, &format!("unloading {hive}"))?;
        deleted?;
    }
    Ok(())
}

fn enable_privileges(names: &[&'static str]) -> Result<()> {
    // SAFETY: our own process token; TOKEN_PRIVILEGES holds one entry per call.
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return Err(std::io::Error::last_os_error()).context("opening the process token");
        }
        let token = Handle(token);
        for name in names {
            let wname = wide(name);
            let mut luid = LUID::default();
            if LookupPrivilegeValueW(null(), wname.as_ptr(), &mut luid) == 0 {
                return Err(std::io::Error::last_os_error()).context(*name);
            }
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            if AdjustTokenPrivileges(token.0, 0, &tp, 0, null_mut(), null_mut()) == 0 {
                return Err(std::io::Error::last_os_error()).context(*name);
            }
        }
    }
    Ok(())
}

/// From the service: start `daemon-killer notify` in the console session, as its user.
pub fn notify(title: &str, body: &str) -> Delivery {
    match spawn_helper(title, body) {
        Ok(true) => Delivery::Sent,
        Ok(false) => Delivery::NoUser,
        Err(e) => {
            log::warn!("notifying: {e:#}");
            Delivery::Sent
        }
    }
}

fn spawn_helper(title: &str, body: &str) -> Result<bool> {
    let exe = std::env::current_exe()?;
    let mut cmd = wide(command_line(&[
        &exe.to_string_lossy(),
        "notify",
        "--title",
        title,
        "--body",
        body,
    ]));
    let app = wide(&exe);
    let mut desktop = wide(r"winsta0\default");
    // SAFETY: the token and environment block are released here; every string passed is
    // NUL-terminated and the command line buffer is writable, as CreateProcess requires.
    unsafe {
        let session = WTSGetActiveConsoleSessionId();
        let mut token: HANDLE = null_mut();
        // Fails when nobody is logged in, or when not running as a service.
        if session == u32::MAX || WTSQueryUserToken(session, &mut token) == 0 {
            return Ok(false);
        }
        let token = Handle(token);
        let mut env = null_mut();
        if CreateEnvironmentBlock(&mut env, token.0, 0) == 0 {
            return Err(std::io::Error::last_os_error()).context("building the user environment");
        }
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desktop.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessAsUserW(
            token.0,
            app.as_ptr(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            env,
            null(),
            &si,
            &mut pi,
        );
        let err = std::io::Error::last_os_error();
        DestroyEnvironmentBlock(env);
        if ok == 0 {
            return Err(err).context("starting the notification helper");
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(true)
}

/// Quote each argument the way the C runtime splits a command line.
fn command_line(args: &[&str]) -> String {
    let mut out = String::new();
    for arg in args {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push('"');
        let mut slashes = 0;
        for c in arg.chars() {
            match c {
                '\\' => slashes += 1,
                '"' => {
                    out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                    out.push('"');
                    slashes = 0;
                }
                _ => {
                    out.extend(std::iter::repeat_n('\\', slashes));
                    out.push(c);
                    slashes = 0;
                }
            }
        }
        out.extend(std::iter::repeat_n('\\', slashes * 2));
        out.push('"');
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// In the user's session: show the toast. Windows keeps it once handed over.
pub fn show(title: &str, body: &str) -> Result<()> {
    let xml = XmlDocument::new()?;
    xml.LoadXml(&HSTRING::from(format!(
        "<toast><visual><binding template=\"ToastGeneric\">\
         <text>{}</text><text>{}</text></binding></visual></toast>",
        xml_escape(title),
        xml_escape(body)
    )))?;
    let toast = ToastNotification::CreateToastNotification(&xml)?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))?.Show(&toast)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_survive_the_command_line() {
        assert_eq!(command_line(&["a b", ""]), r#""a b" """#);
        assert_eq!(command_line(&[r#"say "hi""#]), r#""say \"hi\"""#);
        assert_eq!(command_line(&[r"C:\dir\"]), r#""C:\dir\\""#);
        assert_eq!(command_line(&[r#"a\"b"#]), r#""a\\\"b""#);
        assert_eq!(command_line(&[r"a\b"]), r#""a\b""#);
    }
}
