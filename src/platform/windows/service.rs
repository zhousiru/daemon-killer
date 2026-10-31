//! Windows services: `daemon-killer` runs the enforcement loop, `daemon-killer-rollback-<pid>`
//! is the one-shot guard that turns protection off when `up` is not confirmed. Both run this binary; `run` hands the body to the
//! service control dispatcher, or runs it in the console when not started by the SCM.

use crate::platform::DaemonState;
use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceDependency, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_MARKED_FOR_DELETE,
};
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

pub(super) const SERVICE: &str = "daemon-killer";
const GUARD_PREFIX: &str = "daemon-killer-rollback-";

fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| r"C:\Program Files".into())
        .join("daemon-killer")
}

pub fn log_path() -> PathBuf {
    super::program_data().join("daemon-killer.log")
}

/// Connect-only access works without elevation, enough to query status.
pub fn daemon_state() -> DaemonState {
    let svc = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service(SERVICE, ServiceAccess::QUERY_STATUS));
    let Ok(svc) = svc else {
        return DaemonState::NotInstalled;
    };
    match svc.query_status().map(|s| s.current_state) {
        Ok(ServiceState::Running | ServiceState::StartPending) => DaemonState::Running,
        _ => DaemonState::Stopped,
    }
}

fn manager() -> Result<ServiceManager> {
    ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the service control manager")
}

const ACCESS: ServiceAccess = ServiceAccess::QUERY_STATUS
    .union(ServiceAccess::START)
    .union(ServiceAccess::STOP)
    .union(ServiceAccess::DELETE)
    .union(ServiceAccess::CHANGE_CONFIG);

fn info(name: &str, start: ServiceStartType, bin: &Path, args: Vec<OsString>) -> ServiceInfo {
    ServiceInfo {
        name: name.into(),
        display_name: format!("daemon-killer ({name})").into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: start,
        error_control: ServiceErrorControl::Normal,
        executable_path: bin.into(),
        launch_arguments: args,
        // WFP lives in the Base Filtering Engine.
        dependencies: vec![ServiceDependency::Service("BFE".into())],
        account_name: None,
        account_password: None,
    }
}

/// Stop and wait until stopped (up to 15s). Not running is fine.
fn stop_and_wait(svc: &windows_service::service::Service) {
    let _ = svc.stop();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match svc.query_status() {
            Ok(s) if s.current_state != ServiceState::Stopped => {
                std::thread::sleep(Duration::from_millis(200))
            }
            _ => break,
        }
    }
}

/// Stop, then delete. Missing services are fine.
fn stop_and_delete(name: &str) {
    let Ok(m) = manager() else { return };
    let Ok(svc) = m.open_service(name, ACCESS) else {
        return;
    };
    stop_and_wait(&svc);
    if let Err(e) = svc.delete() {
        // A rollback service also deletes itself when it exits.
        if !matches!(&e, windows_service::Error::Winapi(io)
            if io.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32))
        {
            log::warn!("deleting service {name}: {e}");
        }
    }
}

pub fn binary_path() -> PathBuf {
    install_dir().join("daemon-killer.exe")
}

/// Copy the running binary into place. The service must be stopped first: Windows cannot
/// replace a running image.
pub fn install_binary() -> Result<PathBuf> {
    let dir = install_dir();
    std::fs::create_dir_all(&dir)?;
    let bin = binary_path();
    let exe = std::fs::canonicalize(std::env::current_exe()?)?;
    if std::fs::canonicalize(&bin).ok() != Some(exe.clone()) {
        let tmp = dir.join("daemon-killer.exe.new");
        std::fs::copy(&exe, &tmp)?;
        // SCM can report Stopped just before the service process releases its image.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match std::fs::rename(&tmp, &bin) {
                Ok(()) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::PermissionDenied
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e).with_context(|| format!("replacing {}", bin.display())),
            }
        }
    }
    Ok(bin)
}

/// Whether PATH changed; new terminals pick it up.
pub fn add_to_path() -> Result<bool> {
    super::path_env::add(&install_dir())
}

/// Create or update the autostart service without starting it.
pub fn register(bin: &Path, config: &Path) -> Result<()> {
    let m = manager()?;
    let info = info(
        SERVICE,
        ServiceStartType::AutoStart,
        bin,
        vec!["--config".into(), config.into(), "run".into()],
    );
    let svc = match m.open_service(SERVICE, ACCESS) {
        Ok(svc) => {
            svc.change_config(&info)?;
            svc
        }
        Err(_) => m.create_service(&info, ACCESS)?,
    };
    // The SCM repeats the last action for every further failure, so this restarts forever,
    // like launchd KeepAlive; exits with an error (not only crashes) count too.
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(2),
        }]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

/// WFP filters are persistent; only the loop stops.
pub fn stop() {
    if let Ok(svc) = manager().and_then(|m| Ok(m.open_service(SERVICE, ACCESS)?)) {
        stop_and_wait(&svc);
    }
}

/// (Re)start, so the daemon reads the config again.
pub fn restart() -> Result<()> {
    let svc = manager()?
        .open_service(SERVICE, ACCESS)
        .context("opening the daemon-killer service")?;
    stop_and_wait(&svc);
    svc.start(&[] as &[&OsStr])
        .context("starting the daemon-killer service")
}

pub fn unregister() {
    stop_and_delete(SERVICE);
}

/// A running image cannot be deleted but can be renamed. When uninstall runs from the
/// installed binary, move it out of the way and delete it at reboot.
fn park_running_binary(dir: &Path) {
    let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize) else {
        return;
    };
    if !std::fs::canonicalize(dir).is_ok_and(|d| exe.starts_with(d)) {
        return;
    }
    let parked = std::env::temp_dir().join(format!("daemon-killer-{}.exe", std::process::id()));
    let target = match std::fs::rename(&exe, &parked) {
        Ok(()) => parked,
        Err(e) => {
            log::warn!("moving {}: {e}", exe.display());
            exe
        }
    };
    let name = super::wide(&target);
    // SAFETY: `name` is NUL-terminated; a null destination means delete.
    if unsafe { MoveFileExW(name.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) } == 0 {
        log::warn!("{} stays until deleted by hand", target.display());
    }
}

pub fn remove_files() {
    let dir = install_dir();
    if let Err(e) = super::path_env::remove(&dir) {
        log::warn!("removing {} from PATH: {e:#}", dir.display());
    }
    park_running_binary(&dir);
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("removing {}: {e}", dir.display());
        }
    }
}

pub struct Guard {
    name: String,
}

/// A separate service: it survives the interactive `up` being killed.
pub fn start_guard(bin: &Path, config: &Path, ticket: &Path, seconds: u64) -> Result<Guard> {
    let name = format!("{GUARD_PREFIX}{}", std::process::id());
    let info = info(
        &name,
        ServiceStartType::OnDemand,
        bin,
        vec![
            "--config".into(),
            config.into(),
            "rollback".into(),
            "--ticket".into(),
            ticket.into(),
            "--seconds".into(),
            seconds.to_string().into(),
        ],
    );
    let svc = manager()?.create_service(&info, ACCESS)?;
    svc.start(&[] as &[&OsStr])
        .context("starting the rollback guard service")?;
    Ok(Guard { name })
}

pub fn stop_guard(g: Guard) {
    stop_and_delete(&g.name);
}

type Body = Box<dyn FnOnce(mpsc::Receiver<()>) -> Result<()> + Send>;
static BODY: Mutex<Option<Body>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

pub fn run(body: impl FnOnce(mpsc::Receiver<()>) -> Result<()> + Send + 'static) -> Result<()> {
    *BODY.lock().unwrap() = Some(Box::new(body));
    // The name is ignored for own-process services; the real one arrives in service_main.
    match service_dispatcher::start(SERVICE, ffi_service_main) {
        Ok(()) => Ok(()),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) =>
        {
            let body = BODY
                .lock()
                .unwrap()
                .take()
                .context("service body missing")?;
            let (_keep, stop) = mpsc::channel();
            body(stop)
        }
        Err(e) => Err(e).context("starting the service dispatcher"),
    }
}

fn service_main(args: Vec<OsString>) {
    let name = args
        .first()
        .and_then(|n| n.to_str())
        .unwrap_or(SERVICE)
        .to_string();
    if let Err(e) = serve(&name) {
        log::error!("service {name}: {e:#}");
    }
}

fn serve(name: &str) -> Result<()> {
    let body = BODY
        .lock()
        .unwrap()
        .take()
        .context("service body missing")?;
    let (tx, stop) = mpsc::channel();
    let status = service_control_handler::register(name, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let report = |state, accept, exit_code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::NO_ERROR,
    )?;
    let result = body(stop);
    if let Err(e) = &result {
        log::error!("{e:#}");
    }
    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        // Non-zero so the failure actions restart the daemon.
        match result {
            Ok(()) => ServiceExitCode::NO_ERROR,
            Err(_) => ServiceExitCode::ServiceSpecific(1),
        },
    )?;
    // A guard whose installer died must not linger in the service list.
    if name.starts_with(GUARD_PREFIX) {
        if let Ok(svc) = manager().and_then(|m| Ok(m.open_service(name, ServiceAccess::DELETE)?)) {
            let _ = svc.delete();
        }
    }
    Ok(())
}
