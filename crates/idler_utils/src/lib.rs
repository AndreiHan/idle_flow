#![cfg(windows)]
use std::sync::{Arc, Condvar, Mutex};

use anyhow::Result;
use rand::{Rng, rng};
use tracing::{debug, error, info, warn};
use windows::Win32::UI::WindowsAndMessaging::{WM_ENDSESSION, WM_QUERYENDSESSION};
use windows::{
    Win32::{
        Foundation::{GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            Power::{
                ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED, ES_USER_PRESENT,
                SetThreadExecutionState,
            },
            Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy},
        },
        UI::WindowsAndMessaging::{
            CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow,
            DispatchMessageW, GetMessageW, HWND_MESSAGE, IDC_ARROW, LoadCursorW, MSG, PostMessageW,
            PostQuitMessage, RegisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_DESTROY,
            WNDCLASSW,
        },
    },
    core::w,
};

mod input_utils;
pub mod registry;

/// Default maximum idle time in seconds
#[cfg(debug_assertions)]
const DEFAULT_MAX_IDLE: u64 = 10;
#[cfg(not(debug_assertions))]
const DEFAULT_MAX_IDLE: u64 = 60;

#[non_exhaustive]
pub struct ExecState;

impl ExecState {
    #[inline]
    pub fn start() {
        unsafe {
            let state =
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
            info!("SetThreadExecutionState result: {state:?} - ENABLE");
        }
    }
    #[inline]
    pub fn stop() {
        unsafe {
            let state = SetThreadExecutionState(ES_CONTINUOUS);
            info!("SetThreadExecutionState result: {state:?} - DISABLE");
        }
    }

    #[inline]
    pub fn user_present() {
        unsafe {
            let state = SetThreadExecutionState(ES_USER_PRESENT);
            info!("SetThreadExecutionState result: {state:?} - USER_PRESENT");
        }
    }
}

#[derive(Debug)]
pub struct ExitCondition {
    condvar: Condvar,
    mutex: Mutex<bool>,
}

impl Default for ExitCondition {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitCondition {
    #[must_use]
    const fn new() -> Self {
        Self {
            condvar: Condvar::new(),
            mutex: Mutex::new(false),
        }
    }

    #[inline]
    fn start_exit(&self) {
        info!("Exit condition triggered");
        let mut guard = self.mutex.lock().unwrap();
        *guard = true;
        self.condvar.notify_all();
    }

    #[inline]
    fn is_exit(&self) -> bool {
        *self.mutex.lock().unwrap()
    }

    #[inline]
    fn wait_for_exit(&self, dur: core::time::Duration) -> bool {
        let Ok(res) = self
            .condvar
            .wait_timeout_while(self.mutex.lock().unwrap(), dur, |exit| !*exit)
            .map_err(|e| anyhow::anyhow!("Condvar wait failed: {e:?}"))
        else {
            return true;
        };

        if res.1.timed_out() {
            info!("Wait timed out after {:?}", dur);
            return false;
        }
        info!("Exit condition met");
        true
    }
}

/// Spawns a new window and reports the handle through the provided sender.
///
/// # Errors
///
/// This function will return an error if the window creation fails for any reason,
/// such as if the window class could not be registered, or if the window could not be created.
#[allow(clippy::missing_safety_doc)]
pub fn spawn_window(handle_sender: &crossbeam::channel::Sender<Option<isize>>) -> Result<()> {
    let instance: HINSTANCE = unsafe { GetModuleHandleW(None) }?.into();

    let window_class = w!("window");

    let wc = WNDCLASSW {
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }?,
        hInstance: instance,
        lpszClassName: window_class,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wndproc),
        ..Default::default()
    };

    let atom = unsafe { RegisterClassW(&raw const wc) };
    debug_assert!(atom != 0);

    let window_handle: HWND;
    unsafe {
        match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            window_class,
            w!("LsWindow"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance),
            None,
        ) {
            Ok(hnd) => {
                info!("Window created");
                if handle_sender.send(Some(hnd.0 as isize)).is_err() {
                    warn!("Window handle receiver dropped before initialization");
                }
                window_handle = hnd;
            }
            Err(err) => {
                error!("Failed to create window: {:?}", err);
                let _ = handle_sender.send(None);
                return Err(err.into());
            }
        }
    };

    let original_reason = w!("Preventing system shutdown while idling");
    let res = unsafe { ShutdownBlockReasonCreate(window_handle, original_reason) };
    info!("ShutdownBlockReasonCreate result: {res:?}");

    let mut message = MSG::default();
    loop {
        let status = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
        match status.0 {
            -1 => {
                error!("GetMessageW failed: {:?}", unsafe { GetLastError() });
                break;
            }
            0 => {
                info!("Window message loop exit requested");
                break;
            }
            _ => unsafe {
                DispatchMessageW(&raw const message);
            },
        }
    }
    let res = unsafe { ShutdownBlockReasonDestroy(window_handle) };
    info!("ShutdownBlockReasonDestroy result: {res:?}");
    info!("Window thread exiting");

    Ok(())
}

unsafe extern "system" fn wndproc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_QUERYENDSESSION => {
            info!("Received WM_QUERYENDSESSION for idle window, disallowing session end");
            LRESULT(0)
        }
        WM_ENDSESSION => {
            info!("Received WM_ENDSESSION for idle window");
            LRESULT(0)
        }
        WM_CLOSE => {
            info!("Received WM_CLOSE for idle window");
            if let Err(err) = unsafe { DestroyWindow(window) } {
                error!("DestroyWindow failed: {err:?}");
                unsafe { PostQuitMessage(0) };
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            info!("Received WM_DESTROY for idle window");
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => {
            #[cfg(debug_assertions)]
            debug!(
                "msg-only message: {} - {:?} - {:?}",
                message, wparam, lparam
            );
            unsafe { DefWindowProcW(window, message, wparam, lparam) }
        }
    }
}

#[inline]
fn idle_loop(max_idle: u64, exit_condvar: &Arc<ExitCondition>) -> Result<()> {
    debug!("Start idle time thread");
    let mut rng = rng();
    let sleep_base =
        u64::try_from(core::time::Duration::from_secs(max_idle * 94 / 100).as_millis())?;
    loop {
        if exit_condvar.is_exit() {
            info!("Idle loop shutdown requested (condvar), 1");
            break;
        }

        let idle_time = input_utils::get_last_input().unwrap_or(0);
        if idle_time >= (max_idle * 94 / 100) {
            ExecState::user_present();
            match input_utils::send_random_input() {
                Ok(()) => info!("Simulated input after {idle_time}s idle"),
                Err(e) => error!("Failed to send input: {e:?}"),
            }
            let sleep_secs = rng.random_range(5..=15);

            if exit_condvar.wait_for_exit(core::time::Duration::from_secs(sleep_secs)) {
                info!("Idle loop shutdown requested (condvar), 2");
                break;
            }
        } else {
            info!("Idle time: {idle_time}s, waiting for input");
            let sleep_ms = rng.random_range(sleep_base / 2..=sleep_base);

            if exit_condvar.wait_for_exit(core::time::Duration::from_millis(sleep_ms)) {
                info!("Idle loop shutdown requested (condvar), 3");
                break;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct IdleController {
    exit_condition: Arc<ExitCondition>,
    thread_handle: std::thread::JoinHandle<()>,
    window_thread: Option<std::thread::JoinHandle<()>>,
    window_handle: Option<HWND>,
}

impl mitigations::Closeable for IdleController {
    fn init_close(&self) {
        info!("Initiating close of idle controller");
        self.exit_condition.start_exit();
        if let Some(hwnd) = self.window_handle {
            info!("Posting WM_CLOSE to idle window");
            unsafe {
                if let Err(err) = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) {
                    error!("Failed to post WM_CLOSE: {err:?}");
                }
            }
        } else {
            warn!("Idle window handle unavailable, skipping WM_CLOSE");
        }
    }

    fn wait_close(self) {
        let timeout = core::time::Duration::from_secs(5);
        if let Some(window_thread_handle) = self.window_thread {
            if let Err(e) = mitigations::join_timeout(window_thread_handle, timeout) {
                error!("Idle window thread join failed: {e:?}");
            } else {
                info!("Idle window thread stopped successfully");
            }
        }

        if let Err(e) = mitigations::join_timeout(self.thread_handle, timeout) {
            error!("Idle thread join failed: {e:?}");
        } else {
            info!("Idle thread stopped successfully");
        }
        info!("Idle controller closed");
    }
}

#[must_use]
#[inline]
pub fn spawn_idle_thread(max_idle: Option<u64>) -> IdleController {
    let idle = max_idle.unwrap_or(DEFAULT_MAX_IDLE);
    let exit_condition = Arc::new(ExitCondition::new());

    let (window_tx, window_rx) = crossbeam::channel::bounded(1);
    let window_thread = std::thread::spawn(move || {
        mitigations::set_priority(mitigations::Priority::Lowest);
        mitigations::hide_current_thread_from_debuggers();
        if let Err(e) = spawn_window(&window_tx) {
            error!("Window thread exited with error: {e:?}");
        }
    });

    let exit_condition_clone = Arc::clone(&exit_condition);
    let thread_handle = std::thread::spawn(move || {
        mitigations::set_priority(mitigations::Priority::Lowest);
        mitigations::hide_current_thread_from_debuggers();
        info!("Starting idle thread after {idle} seconds delay");

        if exit_condition_clone.wait_for_exit(core::time::Duration::from_secs(idle)) {
            info!("Idle loop shutdown requested (condvar), 0");
            return;
        }

        let status = idle_loop(idle, &exit_condition_clone);
        if let Err(e) = status {
            error!("Idle loop exited with error: {e:?}");
        }
    });

    let window_handle = match window_rx.recv_timeout(core::time::Duration::from_secs(5)) {
        Ok(Some(handle)) => {
            info!("Received idle window handle");
            Some(HWND(handle as *mut core::ffi::c_void))
        }
        Ok(None) => {
            error!("Window thread reported creation failure");
            None
        }
        Err(err) => {
            error!("Timed out waiting for idle window handle: {err:?}");
            None
        }
    };

    IdleController {
        exit_condition,
        thread_handle,
        window_thread: Some(window_thread),
        window_handle,
    }
}
