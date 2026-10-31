//! Windows: WFP for enforcement, the service control manager for the daemon.

mod path_env;
pub mod service;
mod wfp;

pub use wfp::Wfp as NativeFirewall;

use anyhow::{ensure, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, GetIfEntry2, MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, TokenElevation,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSGetActiveConsoleSessionId, WTSSendMessageW, WTS_CURRENT_SERVER_HANDLE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, TerminateProcess, PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK};

pub const DEFAULT_TUN: &str = "Mihomo";
pub const EXAMPLE_CONFIG: &str = include_str!("../../../config/windows.example.toml");

fn program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| r"C:\ProgramData".into())
        .join("daemon-killer")
}

pub fn default_config_path() -> PathBuf {
    program_data().join("config.toml")
}

pub fn default_state_dir() -> PathBuf {
    program_data().join("state")
}

pub(crate) fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: callers pass NUL-terminated strings owned by the OS.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

pub fn is_elevated() -> bool {
    // SAFETY: plain token query on our own process; buffers are sized for TOKEN_ELEVATION.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = Handle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0;
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        ) != 0
            && elevation.TokenIsElevated != 0
    }
}

/// A service has no console; the daemon and the rollback guard log to a file. Commands only
/// show warnings, next to their own output.
pub fn init_logging(daemon: bool) {
    let level = if daemon { "info" } else { "warn" };
    let mut b = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level));
    if daemon {
        let path = service::log_path();
        let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            b.target(env_logger::Target::Pipe(Box::new(f)));
        }
    }
    b.init();
}

/// ProgramData lets every user create files, so a non-admin could pre-create the directory
/// (and own it) or drop a `pause` file. Make it SYSTEM/Administrators-only, owned by
/// Administrators, recursively.
pub fn secure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    secure_path(path)
}

fn secure_path(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing to change permissions through a reparse point: {}",
        path.display()
    );
    // Replace the DACL in one operation: recursive icacls grants with inheritance
    // flags can strip all access from existing files. Files need plain ACEs.
    let sddl = wide(if meta.is_dir() {
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    } else {
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
    });
    let name = wide(path);
    // SAFETY: the descriptor is allocated by Windows; its owner/DACL pointers stay
    // valid until LocalFree, after SetNamedSecurityInfoW has copied them.
    unsafe {
        let mut descriptor = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("creating directory permissions");
        }
        let (mut owner, mut dacl) = (null_mut(), null_mut());
        let (mut present, mut defaulted) = (0, 0);
        let result = if GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) == 0
            || GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            // Owners retain WRITE_DAC even if an earlier install left an empty
            // DACL. Restore access before requesting WRITE_OWNER as well.
            let mut rc = SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            );
            if rc == NO_ERROR {
                rc = SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    owner,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                );
            }
            if rc == NO_ERROR {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(rc as i32))
            }
        };
        LocalFree(descriptor);
        result.with_context(|| format!("securing {}", path.display()))?;
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            secure_path(&entry?.path())?;
        }
    }
    Ok(())
}

pub(crate) fn interface_luid(alias: &str) -> Option<u64> {
    let name = wide(alias);
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: `name` is NUL-terminated and `luid` is a valid out pointer.
    let rc = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
    // SAFETY: every bit pattern is a valid u64.
    (rc == NO_ERROR).then_some(unsafe { luid.Value })
}

pub fn iface_up(alias: &str) -> bool {
    let Some(luid) = interface_luid(alias) else {
        return false;
    };
    // SAFETY: MIB_IF_ROW2 is plain data; GetIfEntry2 reads InterfaceLuid and fills the rest.
    unsafe {
        let mut row: MIB_IF_ROW2 = std::mem::zeroed();
        row.InterfaceLuid.Value = luid;
        GetIfEntry2(&mut row) == NO_ERROR && row.OperStatus == IfOperStatusUp
    }
}

fn processes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    // SAFETY: standard Toolhelp walk; dwSize is set before the first call.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let snap = Handle(snap);
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap.0, &mut e);
        while ok != 0 {
            out.push((e.th32ProcessID, from_wide(e.szExeFile.as_ptr())));
            ok = Process32NextW(snap.0, &mut e);
        }
    }
    out
}

/// Case-insensitive; `.exe` is optional on either side.
fn same_process_name(running: &str, wanted: &str) -> bool {
    let strip = |s: &str| {
        let s = s.trim();
        match s.len().checked_sub(4) {
            Some(i) if s.is_char_boundary(i) && s[i..].eq_ignore_ascii_case(".exe") => &s[..i],
            _ => s,
        }
        .to_string()
    };
    strip(running).eq_ignore_ascii_case(&strip(wanted))
}

pub fn process_running(name: &str) -> bool {
    processes()
        .iter()
        .any(|(_, exe)| same_process_name(exe, name))
}

pub fn kill_processes(names: &[String]) -> Vec<String> {
    let mut killed = Vec::new();
    for (pid, exe) in processes() {
        if !names.iter().any(|n| same_process_name(&exe, n)) {
            continue;
        }
        // SAFETY: the handle is checked and closed; TerminateProcess only needs PROCESS_TERMINATE.
        let ok = unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            !h.is_null() && {
                let h = Handle(h);
                TerminateProcess(h.0, 1) != 0
            }
        };
        if ok {
            killed.push(format!("{exe} ({pid})"));
        }
    }
    killed
}

/// Services run in session 0 and cannot show toasts; a non-blocking message box in the
/// console session is the closest thing.
pub fn notify(msg: &str) {
    let title: Vec<u16> = "daemon-killer".encode_utf16().collect();
    let body: Vec<u16> = msg.encode_utf16().collect();
    let mut response = 0;
    // SAFETY: buffers outlive the call; lengths are in bytes as the API requires.
    unsafe {
        WTSSendMessageW(
            WTS_CURRENT_SERVER_HANDLE,
            WTSGetActiveConsoleSessionId(),
            title.as_ptr(),
            (title.len() * 2) as u32,
            body.as_ptr(),
            (body.len() * 2) as u32,
            MB_OK | MB_ICONWARNING,
            30,
            &mut response,
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_suffix_is_optional() {
        assert!(same_process_name("mihomo.exe", "mihomo"));
        assert!(same_process_name("Mihomo.EXE", "mihomo.exe"));
        assert!(!same_process_name("mihomo-alpha.exe", "mihomo"));
    }

    /// Read-only lookups; nothing on the host changes.
    #[test]
    fn interfaces_and_processes() {
        assert!(iface_up("Loopback Pseudo-Interface 1"));
        assert!(!iface_up("daemon-killer-no-such-adapter"));
        assert!(process_running("System") || process_running("svchost"));
        assert!(!process_running("daemon-killer-no-such-process"));
    }

    #[test]
    #[ignore = "requires an administrator terminal to set the directory owner"]
    fn secure_dir_preserves_access_on_repeated_calls() {
        let dir = std::env::temp_dir().join(format!("dk-acl-{}", std::process::id()));
        secure_dir(&dir).unwrap();
        let file = dir.join("config.toml");
        std::fs::write(&file, "test").unwrap();
        secure_dir(&dir).unwrap();
        secure_dir(&dir).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "test");
        std::fs::write(&file, "updated").unwrap();
        // Reproduce an empty, protected DACL left by the old recursive icacls call.
        let empty = windows_sys::Win32::Security::ACL {
            AclRevision: windows_sys::Win32::Security::ACL_REVISION as u8,
            AclSize: std::mem::size_of::<windows_sys::Win32::Security::ACL>() as u16,
            ..Default::default()
        };
        let name = wide(&file);
        // SAFETY: empty is a valid ACL header, and name is NUL-terminated.
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &empty,
                    null_mut(),
                )
            },
            NO_ERROR
        );
        secure_dir(&dir).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "updated");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
