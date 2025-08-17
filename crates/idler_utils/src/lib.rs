#![cfg(windows)]
use anyhow::Result;
use crossbeam::channel::{Receiver, Sender, bounded};
use rand::{Rng, rng};
use tracing::{debug, error, info};
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::{
            Power::{
                ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED, ES_USER_PRESENT,
                SetThreadExecutionState,
            },
            SystemInformation::GetTickCount64,
        },
        UI::Input::KeyboardAndMouse::{
            GetLastInputInfo, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS,
            KEYBDINPUT, KEYEVENTF_KEYUP, LASTINPUTINFO, MOUSEEVENTF_MOVE, MOUSEINPUT, SendInput,
            VIRTUAL_KEY, VK_CONTROL, VK_MENU, VK_SHIFT,
        },
    },
    core::BOOL,
};

/// Default maximum idle time in seconds
#[cfg(debug_assertions)]
const DEFAULT_MAX_IDLE: u64 = 5;
#[cfg(not(debug_assertions))]
const DEFAULT_MAX_IDLE: u64 = 60;

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
    pub const fn to_virtual_key(self) -> VIRTUAL_KEY {
        match self {
            Self::Shift => VK_SHIFT,
            Self::Control => VK_CONTROL,
            Self::Alt => VK_MENU,
        }
    }

    /// Returns all safe keys
    #[must_use]
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
            info!("{:?} - ENABLE", state);
        }
    }
    #[inline]
    pub fn stop() {
        unsafe {
            let state = SetThreadExecutionState(ES_CONTINUOUS);
            info!("{:?} - DISABLE", state);
        }
    }

    pub fn user_present() {
        unsafe {
            let state = SetThreadExecutionState(ES_USER_PRESENT);
            info!("{:?} - USER_PRESENT", state);
        }
    }
}

/// Sends a random safe key input from the provided list of virtual key codes.
fn send_key_input() -> Result<()> {
    let mut rng = rng();
    let safe_keys = SafeKey::all();
    let key = safe_keys[rng.random_range(0..safe_keys.len())];
    let key_pair = make_key_input(key);
    let size = i32::try_from(core::mem::size_of::<INPUT>())?;
    for item in key_pair {
        let value = unsafe { SendInput(&[item], size) };
        if value == 1 {
            info!("Sent KeyboardInput: {:?}", key);
        } else {
            let err = unsafe { GetLastError() };
            error!("Failed to send KeyboardInput {:?}, last err {:?}", key, err);
            return Err(anyhow::anyhow!("{:?}", err));
        }
    }
    Ok(())
}

fn send_mouse_input() -> Result<()> {
    let input = mouse_move_input();
    let size = i32::try_from(core::mem::size_of::<INPUT>())?;
    if unsafe { SendInput(&[input], size) } == 1 {
        info!("Sent MouseInput");
        Ok(())
    } else {
        let err = unsafe { GetLastError() };
        error!("Failed to send MouseInput, last err {:?}", err);
        Err(anyhow::anyhow!("{:?}", err))
    }
}

/// Sends either a mouse or random safe key input.
fn send_random_input() -> Result<()> {
    let mut rng = rng();
    if rng.random_bool(0.5) {
        send_mouse_input()
    } else {
        send_key_input()
    }
}

fn get_last_input() -> Option<u64> {
    let mut last_input = LASTINPUTINFO {
        cbSize: u32::try_from(core::mem::size_of::<LASTINPUTINFO>())
            .inspect_err(|e| error!("Failed to get size of LASTINPUTINFO: {:?}", e))
            .ok()?,
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

fn idle_loop(max_idle: u64, stop_rx: &Receiver<()>) -> Result<()> {
    debug!("Start idle time thread");
    let mut rng = rng();
    let sleep_base = core::time::Duration::from_secs(max_idle * 94 / 100);
    loop {
        if stop_rx.try_recv().is_ok() {
            info!("Idle loop shutdown requested (channel), 1");
            break;
        }
        let idle_time = get_last_input().unwrap_or(0);
        if idle_time >= (max_idle * 94 / 100) {
            ExecState::user_present();
            match send_random_input() {
                Ok(()) => info!("Simulated input after {}s idle", idle_time),
                Err(e) => error!("Failed to send input: {e:?}"),
            }
            let sleep_secs = rng.random_range(5..=15);
            if stop_rx
                .recv_timeout(core::time::Duration::from_secs(sleep_secs))
                .is_ok()
            {
                info!("Idle loop shutdown requested (channel), 2");
                break;
            }
        } else {
            info!("Idle time: {}s, waiting for input", idle_time);
            let sleep_ms = rng.random_range(
                u64::try_from(sleep_base.as_millis() / 2)?..=u64::try_from(sleep_base.as_millis())?,
            );
            if stop_rx
                .recv_timeout(core::time::Duration::from_millis(sleep_ms))
                .is_ok()
            {
                info!("Idle loop shutdown requested (channel), 3");
                break;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct IdleController {
    stop_tx: Sender<()>,
    thread_handle: std::thread::JoinHandle<()>,
}

impl IdleController {
    /// # Errors
    /// Returns an error if the stop signal fails to send.
    pub fn stop(self, timeout: core::time::Duration) -> Result<()> {
        let status = self.stop_tx.send(());
        info!("Stop signal sent to idle thread: {:?}", status);
        drop(self.stop_tx);
        info!("Stop signal sent to idle thread, waiting for it to finish");
        if let Err(e) = mitigations::join_timeout(self.thread_handle, timeout) {
            error!("Idle thread join failed: {:?}", e);
            return Err(anyhow::anyhow!("Idle thread join failed"));
        }
        info!("Thread join successful");
        info!("Idle thread stopped successfully");
        Ok(())
    }
}

#[must_use]
#[inline]
pub fn spawn_idle_thread(max_idle: Option<u64>) -> IdleController {
    let idle = max_idle.unwrap_or(DEFAULT_MAX_IDLE);
    let (stop_tx, stop_rx) = bounded::<()>(1);
    let thread_handle = std::thread::spawn(move || {
        mitigations::set_priority(mitigations::Priority::Lowest);
        mitigations::hide_current_thread_from_debuggers();
        info!("Starting idle thread after {idle} seconds delay");
        if stop_rx
            .recv_timeout(core::time::Duration::from_secs(idle))
            .is_ok()
        {
            info!("Idle loop shutdown requested (channel)");
            return;
        }

        let status = idle_loop(idle, &stop_rx);
        if let Err(e) = status {
            error!("Idle loop exited with error: {e:?}");
        }
    });
    IdleController {
        stop_tx,
        thread_handle,
    }
}
