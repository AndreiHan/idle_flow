#![cfg(windows)]
use std::{sync::atomic::AtomicBool, thread::JoinHandle};

use anyhow::Result;
use tracing::{error, info, trace, warn};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_EVENT, WAIT_OBJECT_0},
        System::{
            Registry::{
                HKEY, HKEY_CURRENT_USER, KEY_NOTIFY, RegCloseKey, RegNotifyChangeKeyValue,
                RegOpenKeyExW,
            },
            Threading::{CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects},
        },
    },
    core::PCWSTR,
};

const REG_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const VALUE_NAME: &str = "IdleFlow";

static CURRENT_STATUS: AtomicBool = AtomicBool::new(false);
static UPDATE_NEEDED: AtomicBool = AtomicBool::new(true);

pub fn is_key_set() -> bool {
    if UPDATE_NEEDED.load(std::sync::atomic::Ordering::Relaxed) {
        info!("Registry key status check needed, checking...");
        let is_set = inner_is_key_set();
        CURRENT_STATUS.store(is_set, std::sync::atomic::Ordering::Relaxed);
        UPDATE_NEEDED.store(false, std::sync::atomic::Ordering::Relaxed);
        info!("Registry key status updated: {is_set}");
        return is_set;
    }
    let status = CURRENT_STATUS.load(std::sync::atomic::Ordering::Relaxed);
    info!("Returning cached registry key status: {status}");
    status
}

fn inner_is_key_set() -> bool {
    let Ok(key) = windows_registry::CURRENT_USER
        .options()
        .read()
        .open(REG_PATH)
        .inspect_err(|e| error!("Failed to open registry key: {REG_PATH}, error: {e:?}"))
    else {
        warn!("Failed to open registry key: {REG_PATH}");
        return false;
    };
    info!("Opened registry key: {key:?}");

    let Ok(res) = key
        .get_string(VALUE_NAME)
        .inspect_err(|e| info!("Failed to read registry value: {VALUE_NAME}, error: {e:?}"))
    else {
        return false;
    };
    info!("Read registry value: {res:?}");
    true
}

fn get_current_exe_path() -> Result<String> {
    let exe_path = std::env::current_exe()?;
    let exe_str = exe_path.to_string_lossy().to_string();
    Ok(exe_str)
}

/// Sets the registry key to start the application with Windows.
///
/// # Errors
///
/// Returns an error if the registry key cannot be set.
pub fn set_key() -> Result<()> {
    let exe_str = get_current_exe_path()?;
    let formatted_exe_str = format!("\"{exe_str}\"");
    let key = windows_registry::CURRENT_USER
        .options()
        .write()
        .create()
        .open(REG_PATH)?;
    key.set_string(VALUE_NAME, &formatted_exe_str)?;
    info!("Set registry value: {VALUE_NAME} to {exe_str}");
    Ok(())
}

/// Unsets the registry key to stop the application from starting with Windows.
///
/// # Errors
///
/// Returns an error if the registry key cannot be removed.
pub fn unset_key() -> Result<()> {
    let key = windows_registry::CURRENT_USER
        .options()
        .write()
        .open(REG_PATH)?;
    key.remove_value(VALUE_NAME)?;
    info!("Removed registry value: {VALUE_NAME}");
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SafeHandle(HANDLE);

unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

pub struct RegistryWatcher {
    handle: JoinHandle<()>,
    event: SafeHandle,
}

impl RegistryWatcher {
    /// Starts a new registry watcher thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the watcher cannot be started.
    pub fn build() -> Result<Self> {
        start_watcher()
    }
}

impl mitigations::Closeable for RegistryWatcher {
    fn init_close(&self) {
        info!("Initiating close of registry watcher");
        let res = unsafe { SetEvent(self.event.0) };
        if res.is_err() {
            error!("Failed to set event to stop registry watcher: {res:?}");
        }
        let res = unsafe { CloseHandle(self.event.0) };
        info!("Close event handle result: {res:?}");
        info!("Set event to stop registry watcher: {res:?}");
    }

    fn wait_close(self) {
        info!("Waiting for registry watcher to close");
        mitigations::join_timeout(self.handle, std::time::Duration::from_secs(5))
            .unwrap_or_else(|e| error!("Failed to join registry watcher thread: {e}"));
        info!("Registry watcher closed");
    }
}

fn start_watcher() -> Result<RegistryWatcher> {
    let event = unsafe { CreateEventW(None, true, false, None) }?;
    let safe_handle = SafeHandle(event);

    let handle = std::thread::spawn(move || {
        mitigations::hide_current_thread_from_debuggers();
        mitigations::set_priority(mitigations::Priority::Lowest);
        watch_loop(&safe_handle);
    });
    Ok(RegistryWatcher {
        handle,
        event: SafeHandle(event),
    })
}

fn watch_loop(close_event: &SafeHandle) {
    let mut key: HKEY = HKEY::default();
    let path = REG_PATH
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let pcwstr = PCWSTR(path.as_ptr());

    let res = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, pcwstr, None, KEY_NOTIFY, &raw mut key) };

    if res.is_err() {
        error!("Failed to open registry key for watching: {REG_PATH}, error: {res:?}");
        return;
    }

    let Ok(event) = (unsafe { CreateEventW(None, true, false, None) }) else {
        error!("Failed to create event for registry watcher");
        info!("Closing registry key");
        let res = unsafe { RegCloseKey(key) };
        trace!("Closed registry key, result: {res:?}");
        return;
    };

    loop {
        let res = unsafe {
            RegNotifyChangeKeyValue(
                key,
                true,
                windows::Win32::System::Registry::REG_NOTIFY_CHANGE_LAST_SET,
                Some(event),
                true,
            )
        };

        if res.is_err() {
            error!("Failed to set up registry change notification, error: {res:?}");
            info!("Closing registry key");
            let res = unsafe { RegCloseKey(key) };
            trace!("Closed registry key, result: {res:?}");
            return;
        }

        info!("Waiting for registry change or close event...");
        let close_event = close_event.0;
        let res = unsafe { WaitForMultipleObjects(&[close_event, event], false, INFINITE) };
        info!("Wait completed");
        match res {
            WAIT_OBJECT_0 => {
                info!("Received close event, stopping registry watcher");
                break;
            }
            WAIT_EVENT(1) => {
                info!("Registry change detected");
                UPDATE_NEEDED.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            other => {
                info!("Abandoning registry watcher, unexpected wait result: {other:?}");
                break;
            }
        }
        let res = unsafe { ResetEvent(event) };
        if res.is_err() {
            error!("Failed to reset registry change event, error: {res:?}");
            break;
        }
        info!("Reset registry change event");
    }
    info!("Closing registry key and event handles");
    let res = unsafe { RegCloseKey(key) };
    trace!("Closed registry key, result: {res:?}");
    let res = unsafe { CloseHandle(event) };
    trace!("Closed event handle, result: {res:?}");
    trace!("Registry watcher thread exiting");
}
