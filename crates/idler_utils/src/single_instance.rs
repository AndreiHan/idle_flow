use anyhow::Result;
use tracing::{error, info};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, WAIT_OBJECT_0},
        System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
    },
    core::PCWSTR,
};
const MUTEX_NAME: &str = "idle_flow";

pub struct SingleInstanceGuard {
    mutex_handle: HANDLE,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        unsafe {
            let res = ReleaseMutex(self.mutex_handle);
            info!("Released mutex: {res:?}");
            let res = CloseHandle(self.mutex_handle);
            info!("Closed mutex handle: {res:?}");
        }
    }
}

/// Attempts to create a named mutex to ensure a single instance of the application.
///
/// # Errors
///
/// Returns an error if another instance is already running or if mutex creation fails.
pub fn get_single_instance_guard() -> Result<SingleInstanceGuard> {
    let name = MUTEX_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let pcwstr = PCWSTR(name.as_ptr());

    let mutex_handle = unsafe { CreateMutexW(None, false, pcwstr) };
    let last_err = unsafe { GetLastError() };

    let Ok(mutex) = mutex_handle else {
        error!("Failed to create mutex: {last_err:?}");
        anyhow::bail!("Failed to create mutex: {last_err:?}");
    };

    if last_err == ERROR_ALREADY_EXISTS {
        error!("Another instance is already running.");
        let res = unsafe { CloseHandle(mutex) };
        info!("Closed mutex handle: {res:?}");
        anyhow::bail!("Another instance is already running.");
    }

    let event = unsafe { WaitForSingleObject(mutex, 0) };

    if event != WAIT_OBJECT_0 {
        error!("Another instance is already running (WaitForSingleObject).");
        let res = unsafe { CloseHandle(mutex) };
        info!("Closed mutex handle: {res:?}");
        anyhow::bail!("Another instance is already running (WaitForSingleObject).");
    }

    info!("Created mutex with name: {MUTEX_NAME}");

    Ok(SingleInstanceGuard {
        mutex_handle: mutex,
    })
}
