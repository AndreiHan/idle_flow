#![cfg(windows)]
use tracing::{error, info, trace, warn};
use windows::{
    Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger},
    Win32::{
        Foundation::GetLastError,
        System::{
            Memory::{GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc},
            Threading::{
                CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, GetCurrentThread,
                InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_INFORMATION, STARTUPINFOEXW,
                STARTUPINFOW, STARTUPINFOW_FLAGS, SetThreadPriority, THREAD_PRIORITY,
                THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_BELOW_NORMAL,
                THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_NORMAL,
                THREAD_PRIORITY_TIME_CRITICAL, UpdateProcThreadAttribute,
            },
        },
    },
    core::{Owned, PCWSTR, PWSTR},
};

const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 =
    0x0000_0001_u64 << 44;

pub fn clean_env() {
    // Clear the environment variables
    let env = std::env::vars().collect::<Vec<_>>();
    for (key, val) in env {
        trace!("Clearing environment variable: {key}={val}");
        unsafe { std::env::remove_var(key) };
    }
    info!("Environment variables cleared, checking");
    let env = std::env::vars().collect::<Vec<_>>();
    if env.is_empty() {
        info!("No environment variables found");
    } else {
        warn!("Remaining environment variables:");
        for (key, val) in env {
            info!("{key}={val}");
        }
    }
}

#[inline]
fn reset_current_dir() {
    let binding = std::env::current_exe().expect("Failed to get current exe path");
    let parent_dir = binding.parent().expect("Failed to get parent directory");
    std::env::set_current_dir(parent_dir).expect("Failed to set current directory");
    info!("Current directory reset to: {}", parent_dir.display());
}

#[inline]
unsafe fn get_dll_attributes() -> anyhow::Result<Owned<LPPROC_THREAD_ATTRIBUTE_LIST>> {
    let mut attribute_size = usize::default();

    unsafe {
        // The first call returns an error, this is intentional
        let _ = InitializeProcThreadAttributeList(None, 1, None, &raw mut attribute_size);

        let attributes = Owned::new(LPPROC_THREAD_ATTRIBUTE_LIST(HeapAlloc(
            GetProcessHeap()?,
            HEAP_ZERO_MEMORY,
            attribute_size,
        )));

        match InitializeProcThreadAttributeList(Some(*attributes), 1, None, &raw mut attribute_size)
        {
            Ok(()) => {
                info!("Initialized attribute list");
            }
            Err(err) => {
                error!("Failed to initialize attribute list: {err:?}");
                return Err(anyhow::anyhow!(
                    "Failed to initialize attribute list, {err:?}"
                ));
            }
        }

        let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

        match UpdateProcThreadAttribute(
            *attributes,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(std::ptr::from_ref(&policy).cast::<std::ffi::c_void>()),
            std::mem::size_of::<u64>(),
            None,
            None,
        ) {
            Ok(()) => {
                info!("Updated attribute list");
            }
            Err(err) => {
                error!("Failed to update attribute list: {err:?}");
                return Err(anyhow::anyhow!("Failed to update attribute list, {err:?}"));
            }
        }
        Ok(attributes)
    }
}

/// Restarts the current process with the `--restart` argument.
///
/// # Errors
/// Returns an error if the process restart fails.
#[inline]
pub fn restart_self() -> Result<(), anyhow::Error> {
    let current_path = std::env::current_exe()?;
    let Some(current_path) = current_path.to_str() else {
        return Err(anyhow::anyhow!("Failed to convert path to string"));
    };
    let cmdline = format!("\"{current_path}\" --restart");

    info!("Cmdline: {cmdline:?}");
    let mut wide_path = cmdline
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    unsafe {
        let attributes = get_dll_attributes()?;
        let startup_info = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())?,
                dwFlags: STARTUPINFOW_FLAGS(EXTENDED_STARTUPINFO_PRESENT.0),
                ..Default::default()
            },
            lpAttributeList: *attributes,
        };

        let mut process_info = PROCESS_INFORMATION::default();

        match CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR::from_raw(wide_path.as_mut_ptr())),
            None,
            None,
            true,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            std::ptr::from_ref(&startup_info.StartupInfo),
            std::ptr::from_mut(&mut process_info),
        ) {
            Ok(()) => {
                info!("Created process: {current_path:?}");
                Ok(())
            }
            Err(err) => {
                error!("Failed to create process: {err} - | {:?}", GetLastError());
                Err(anyhow::anyhow!("Failed to create process"))
            }
        }
    }
}

/// Joins a thread with a timeout.
///
/// # Errors
/// Returns an error if the thread join fails or times out.
#[inline]
pub fn join_timeout(
    thread_handle: std::thread::JoinHandle<()>,
    timeout: std::time::Duration,
) -> Result<(), anyhow::Error> {
    let timeout = std::time::Instant::now() + timeout;
    trace!("Waiting for thread to finish with timeout: {timeout:?}");
    loop {
        if thread_handle.is_finished() {
            info!("Thread finished");
            return thread_handle.join().map_err(|e| {
                info!("Thread join failed: {e:?}");
                anyhow::anyhow!("Thread join failed")
            });
        }
        if timeout < std::time::Instant::now() {
            info!("Thread join timed out");
            return Err(anyhow::anyhow!("Thread join timed out"));
        }
    }
}

#[inline]
#[allow(clippy::missing_panics_doc)]
pub fn enable_mitigations() {
    hide_current_thread_from_debuggers();
    clean_env();
    reset_current_dir();
    set_policy_mitigation();
    info!("Mitigations enabled");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Lowest,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    TimeCritical,
}

impl Priority {
    fn to_thread_priority(self) -> THREAD_PRIORITY {
        match self {
            Priority::Lowest => THREAD_PRIORITY_LOWEST,
            Priority::BelowNormal => THREAD_PRIORITY_BELOW_NORMAL,
            Priority::Normal => THREAD_PRIORITY_NORMAL,
            Priority::AboveNormal => THREAD_PRIORITY_ABOVE_NORMAL,
            Priority::High => THREAD_PRIORITY_HIGHEST,
            Priority::TimeCritical => THREAD_PRIORITY_TIME_CRITICAL,
        }
    }
}

#[inline]
pub fn set_priority(priority: Priority) {
    unsafe {
        let status = SetThreadPriority(GetCurrentThread(), priority.to_thread_priority());
        trace!("Set thread priority to {priority:?}: {status:?}");
    }
}

#[inline]
pub fn hide_current_thread_from_debuggers() {
    if cfg!(debug_assertions) {
        info!("[DEBUG-MODE] NOT SETTING anti debug status");
        return;
    }
    let status = unsafe {
        NtSetInformationThread(
            GetCurrentThread(),
            ThreadHideFromDebugger,
            std::ptr::null(),
            0,
        )
    };
    info!("Set anti debug status: {status:?}");
}

#[inline]
fn set_policy_mitigation() {
    if std::env::args().any(|arg| arg == "--restart") {
        info!("Found --restart argument, setting child process policy");
        win_mitigations::child_process::ChildProcessPolicy::default()
            .set_no_child_process_creation(true)
            .build()
            .inspect(|()| trace!("Child process policy set"))
            .expect("Failed to set child process policy");
    } else {
        info!("No --restart argument found, not setting child process policy");
    }

    win_mitigations::binary_signature::BinarySignaturePolicy::default()
        .set_microsoft_signed_only(true)
        .build()
        .inspect(|()| trace!("Binary signature policy set"))
        .expect("Failed to set binary signature policy");

    win_mitigations::font_disable::FontDisablePolicy::default()
        .set_disable_non_system_fonts(true)
        .build()
        .inspect(|()| trace!("Font disable policy set"))
        .expect("Failed to set font disable policy");

    win_mitigations::extension_point::ExtensionPointPolicy::default()
        .set_disable_extension_points(true)
        .build()
        .inspect(|()| trace!("Extension point policy set"))
        .expect("Failed to set extension point policy");

    win_mitigations::aslr::AslrPolicy::default()
        .set_enable_bottom_up_randomization(true)
        .set_enable_force_relocate_images(true)
        .build()
        .inspect(|()| trace!("ASLR policy set"))
        .expect("Failed to set ASLR policy");

    win_mitigations::extension_point::ExtensionPointPolicy::default()
        .set_disable_extension_points(true)
        .build()
        .inspect(|()| trace!("Extension point policy set"))
        .expect("Failed to set extension point policy");

    win_mitigations::aslr::AslrPolicy::default()
        .set_enable_bottom_up_randomization(true)
        .set_enable_force_relocate_images(true)
        .set_enable_high_entropy(true)
        .build()
        .inspect(|()| trace!("ASLR policy set"))
        .expect("Failed to set ASLR policy");

    win_mitigations::image_load::ImageLoadPolicy::default()
        .set_prefer_system32_images(true)
        .set_no_remote_images(true)
        .build()
        .inspect(|()| trace!("Image load policy set"))
        .expect("Failed to set image load policy");

    #[cfg(debug_assertions)]
    win_mitigations::strict_handle::StrictHandlePolicy::default()
        .set_raise_exception_on_invalid_handle_reference(true)
        .set_handle_exceptions_permanently_enabled(true)
        .build()
        .inspect(|()| trace!("Strict handle policy set"))
        .expect("Failed to set strict handle policy");

    win_mitigations::dynamic_code::DynamicCodePolicy::default()
        .set_prohibit_dynamic_code(true)
        .build()
        .inspect(|()| trace!("Dynamic code policy set"))
        .expect("Failed to set dynamic code policy");
}
