#![cfg(windows)]
use anyhow::Result;
use rand::{Rng, rng};
use tracing::{error, info};
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::SystemInformation::GetTickCount64,
        UI::Input::KeyboardAndMouse::{
            GetLastInputInfo, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS,
            KEYBDINPUT, KEYEVENTF_KEYUP, LASTINPUTINFO, MOUSEEVENTF_MOVE, MOUSEINPUT, SendInput,
            VIRTUAL_KEY, VK_CONTROL, VK_MENU, VK_SHIFT,
        },
    },
    core::BOOL,
};

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
const SIZE_OF_INPUT: i32 = std::mem::size_of::<INPUT>() as i32;
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
const SIZE_OF_LASTINPUTINFO: u32 = std::mem::size_of::<LASTINPUTINFO>() as u32;

#[inline]
pub const fn mouse_move_input() -> INPUT {
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
    pub(crate) const fn to_virtual_key(self) -> VIRTUAL_KEY {
        match self {
            Self::Shift => VK_SHIFT,
            Self::Control => VK_CONTROL,
            Self::Alt => VK_MENU,
        }
    }

    /// Returns all safe keys
    #[must_use]
    #[inline]
    pub(crate) fn all() -> &'static [Self] {
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

/// Sends a random safe key input from the provided list of virtual key codes.
#[inline]
pub fn send_key_input() -> Result<()> {
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
pub fn send_mouse_input() -> Result<()> {
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
pub fn send_random_input() -> Result<()> {
    let mut rng = rng();
    if rng.random_bool(0.5) {
        send_mouse_input()
    } else {
        send_key_input()
    }
}

#[inline]
pub fn get_last_input() -> Option<u64> {
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
