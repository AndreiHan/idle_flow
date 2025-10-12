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
            SystemInformation::GetTickCount64,
        },
        UI::{
            Input::KeyboardAndMouse::{
                GetLastInputInfo, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS,
                KEYBDINPUT, KEYEVENTF_KEYUP, LASTINPUTINFO, MOUSEEVENTF_MOVE, MOUSEINPUT,
                SendInput, VIRTUAL_KEY, VK_CONTROL, VK_MENU, VK_SHIFT,
            },
            WindowsAndMessaging::{
                CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow,
                DispatchMessageW, GetMessageW, HWND_MESSAGE, IDC_ARROW, LoadCursorW, MSG,
                PostMessageW, PostQuitMessage, RegisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE,
                WM_CLOSE, WM_DESTROY, WNDCLASSW,
            },
        },
    },
    core::{BOOL, w},
};

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
const SIZE_OF_INPUT: i32 = std::mem::size_of::<INPUT>() as i32;
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
const SIZE_OF_LASTINPUTINFO: u32 = std::mem::size_of::<LASTINPUTINFO>() as u32;

/// Default maximum idle time in seconds
#[cfg(debug_assertions)]
const DEFAULT_MAX_IDLE: u64 = 10;
#[cfg(not(debug_assertions))]
const DEFAULT_MAX_IDLE: u64 = 60;

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

#[inline]
const fn mouse_move_input() -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: 0,
                dwFlags: MOUSEEVENTF_MOVE,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Enum for safe, non-disruptive keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeKey {
    Shift,
    Control,
    Alt,
}

impl SafeKey {
    #[must_use]
    #[inline]
    pub const fn to_virtual_key(self) -> VIRTUAL_KEY {
        match self {
            Self::Shift => VK_SHIFT,
            Self::Control => VK_CONTROL,
            Self::Alt => VK_MENU,
        }
    }

    /// Returns all safe keys
    #[must_use]
    #[inline]
    pub fn all() -> &'static [Self] {
        static SAFE_KEYS: [SafeKey; 3] = [SafeKey::Shift, SafeKey::Control, SafeKey::Alt];
        &SAFE_KEYS
    }
}

/// Generates a key press/release INPUT pair for a given `SafeKey`.
#[must_use]
#[inline]
pub const fn make_key_input(key: SafeKey) -> [INPUT; 2] {
    let vk = key.to_virtual_key();
    [
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        },
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        },
    ]
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum InputType {
    Mouse,
    Keyboard,
}

#[non_exhaustive]
pub struct ExecState;

impl ExecState {
    #[inline]
    pub fn start() {
        unsafe {
            let state =
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
            info!("{state:?} - ENABLE");
        }
    }
    #[inline]
    pub fn stop() {
        unsafe {
            let state = SetThreadExecutionState(ES_CONTINUOUS);
            info!("{state:?} - DISABLE");
        }
    }

    #[inline]
    pub fn user_present() {
        unsafe {
            let state = SetThreadExecutionState(ES_USER_PRESENT);
            info!("{state:?} - USER_PRESENT");
        }
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

/// Sends a random safe key input from the provided list of virtual key codes.
#[inline]
fn send_key_input() -> Result<()> {
    let mut rng = rng();
    let safe_keys = SafeKey::all();
    let key = safe_keys[rng.random_range(0..safe_keys.len())];
    let key_pair = make_key_input(key);
    for item in key_pair {
        let value = unsafe { SendInput(&[item], SIZE_OF_INPUT) };
        if value == 1 {
            info!("Sent KeyboardInput: {key:?}");
        } else {
            let err = unsafe { GetLastError() };
            error!("Failed to send KeyboardInput {key:?}, last err {err:?}");
            return Err(anyhow::anyhow!("{err:?}"));
        }
    }
    Ok(())
}

#[inline]
fn send_mouse_input() -> Result<()> {
    let input = mouse_move_input();
    if unsafe { SendInput(&[input], SIZE_OF_INPUT) } == 1 {
        info!("Sent MouseInput");
        Ok(())
    } else {
        let err = unsafe { GetLastError() };
        error!("Failed to send MouseInput, last err {err:?}");
        Err(anyhow::anyhow!("{err:?}"))
    }
}

/// Sends either a mouse or random safe key input.
#[inline]
fn send_random_input() -> Result<()> {
    let mut rng = rng();
    if rng.random_bool(0.5) {
        send_mouse_input()
    } else {
        send_key_input()
    }
}

#[inline]
fn get_last_input() -> Option<u64> {
    let mut last_input = LASTINPUTINFO {
        cbSize: SIZE_OF_LASTINPUTINFO,
        ..Default::default()
    };
    let total_ticks;
    unsafe {
        if GetLastInputInfo(core::ptr::from_mut(&mut last_input)) != BOOL(1) {
            error!("Failed to get last input info, {:?}", GetLastError());
            return None;
        }
        total_ticks = GetTickCount64();
    }
    Some(core::time::Duration::from_millis(total_ticks - u64::from(last_input.dwTime)).as_secs())
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

        let idle_time = get_last_input().unwrap_or(0);
        if idle_time >= (max_idle * 94 / 100) {
            ExecState::user_present();
            match send_random_input() {
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

impl IdleController {
    /// # Errors
    /// Returns an error if any of the join operations fail or time out.
    #[inline]
    pub fn stop(self, timeout: core::time::Duration) -> Result<()> {
        let IdleController {
            exit_condition,
            thread_handle,
            window_thread,
            window_handle,
        } = self;

        exit_condition.start_exit();
        info!("Stop signal sent to idle thread");

        if let Some(hwnd) = window_handle {
            info!("Posting WM_CLOSE to idle window");
            unsafe {
                if let Err(err) = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) {
                    error!("Failed to post WM_CLOSE: {err:?}");
                }
            }
        } else {
            warn!("Idle window handle unavailable, skipping WM_CLOSE");
        }

        let mut first_error: Option<anyhow::Error> = None;

        if let Some(window_thread_handle) = window_thread {
            if let Err(e) = mitigations::join_timeout(window_thread_handle, timeout) {
                error!("Idle window thread join failed: {e:?}");
                first_error
                    .get_or_insert_with(|| anyhow::anyhow!("Idle window thread join failed"));
            } else {
                info!("Idle window thread stopped successfully");
            }
        }

        if let Err(e) = mitigations::join_timeout(thread_handle, timeout) {
            error!("Idle thread join failed: {e:?}");
            first_error.get_or_insert_with(|| anyhow::anyhow!("Idle thread join failed"));
        } else {
            info!("Idle thread stopped successfully");
        }

        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(())
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

const REG_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const VALUE_NAME: &str = "IdleFlow";

pub fn is_key_set() -> bool {
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
