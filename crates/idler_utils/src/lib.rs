use anyhow::{Result, anyhow};
use tracing::{debug, error, info, trace};
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
            KEYBDINPUT, KEYEVENTF_KEYUP, LASTINPUTINFO, MOUSEEVENTF_WHEEL, MOUSEINPUT, SendInput,
            VK_ESCAPE,
        },
    },
    core::BOOL,
};

const MAX_IDLE: u64 = 10; // Maximum idle time in seconds

const MOUSE_INPUT: INPUT = INPUT {
    r#type: INPUT_MOUSE,
    Anonymous: INPUT_0 {
        mi: MOUSEINPUT {
            dx: 0,
            dy: 0,
            mouseData: 1,
            dwFlags: MOUSEEVENTF_WHEEL,
            time: 0,
            dwExtraInfo: 0,
        },
    },
};

const KEYBOARD_INPUT: [INPUT; 2] = [
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VK_ESCAPE,
                wScan: 1,
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
                wVk: VK_ESCAPE,
                wScan: 1,
                dwFlags: KEYEVENTF_KEYUP,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    },
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum InputType {
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

fn send_key_input() -> Result<()> {
    for item in KEYBOARD_INPUT {
        let value = unsafe { SendInput(&[item], size_of_val(&[item]).try_into()?) };
        if value == 1 {
            info!("Sent KeyboardInput");
        } else {
            let err = unsafe { GetLastError() };
            error!("Failed to send KeyboardInput, last err {:?}", err);
            return Err(anyhow!("{:?}", err));
        }
    }
    Ok(())
}

fn send_mouse_input() -> Result<()> {
    if unsafe { SendInput(&[MOUSE_INPUT], size_of_val(&[MOUSE_INPUT]).try_into()?) } == 1 {
        info!("Sent MouseInput");
        Ok(())
    } else {
        let err = unsafe { GetLastError() };
        error!("Failed to send MouseInput, last err {:?}", err);
        Err(anyhow!("{:?}", err))
    }
}

fn send_mixed_input(input_type: InputType) {
    if input_type == InputType::Mouse {
        let _ = send_mouse_input();
    } else {
        let _ = send_key_input();
    }
}

fn get_last_input() -> Option<u64> {
    let mut last_input = LASTINPUTINFO::default();

    last_input.cbSize = if let Ok(val) = size_of_val(&last_input).try_into() {
        val
    } else {
        error!("Failed to get size of last input");
        return None;
    };
    let total_ticks;
    unsafe {
        if GetLastInputInfo(std::ptr::from_mut(&mut last_input)) != BOOL(1) {
            error!("Failed to get last input info, {:?}", GetLastError());
            return None;
        }
        total_ticks = GetTickCount64();
    }
    Some(std::time::Duration::from_millis(total_ticks - u64::from(last_input.dwTime)).as_secs())
}

/// The main idle loop.
///
/// # Errors
///
/// This function will return an error if there is a problem with the registry operations or
/// sending inputs to the system.
#[allow(clippy::missing_panics_doc)]
pub fn idle_loop() -> Result<()> {
    debug!("Start idle time thread");
    let mut max_idle = MAX_IDLE;

    if cfg!(debug_assertions) && max_idle < 60 {
        info!("Force interval is less than 60 seconds, setting to 60 seconds");
        max_idle = 60;
    }

    loop {
        let idle_time = get_last_input().unwrap_or(0);
        if idle_time >= (max_idle * 94 / 100) {
            ExecState::user_present();
            send_mixed_input(InputType::Mouse);
            if get_last_input() >= Some(idle_time) {
                send_mixed_input(InputType::Keyboard);
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
            if get_last_input() >= Some(idle_time) {
                error!("Failed to reset idle time, skipping");
            }
            continue;
        }
        std::thread::sleep(std::time::Duration::from_secs(max_idle * 94 / 100));
    }
}

pub fn spawn_idle_threads() {
    std::thread::spawn(move || {
        mitigations::hide_current_thread_from_debuggers();
        trace!("Starting idle thread after {MAX_IDLE} seconds delay");
        std::thread::sleep(std::time::Duration::from_secs(MAX_IDLE));
        loop {
            let status = idle_loop();
            if status.is_err() {
                error!("Failed to run idle loop with err: {:?}", status);
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });
}
