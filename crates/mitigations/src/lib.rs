#![cfg(windows)]
#![allow(clippy::missing_panics_doc)]

use std::sync::{LazyLock, atomic::AtomicBool};

use parking_lot::Mutex;
use tracing::{error, info, trace};
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::{
            Console::FreeConsole,
            ErrorReporting::WerAddExcludedApplication,
            Memory::{
                GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapEnableTerminationOnCorruption,
                HeapOptimizeResources, HeapSetInformation,
            },
            SystemServices::HEAP_OPTIMIZE_RESOURCES_INFORMATION,
            Threading::{
                BELOW_NORMAL_PRIORITY_CLASS, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT,
                GetCurrentProcess, GetCurrentThread, InitializeProcThreadAttributeList,
                LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW, STARTUPINFOW_FLAGS,
                SetPriorityClass, SetThreadPriority, THREAD_PRIORITY, THREAD_PRIORITY_ABOVE_NORMAL,
                THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_LOWEST,
                THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_TIME_CRITICAL, UpdateProcThreadAttribute,
            },
        },
    },
    core::{HSTRING, Owned, PCWSTR, PWSTR},
};

mod thread;

pub use thread::hide_current_thread_from_debuggers;

const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 =
    0x0000_0001_u64 << 44;

static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static ENV_CLEANED: AtomicBool = AtomicBool::new(false);

pub trait Closeable {
    fn init_close(&self);
    fn wait_close(self);
}

#[inline]
pub fn clean_env() {
    // Clear the environment variables
    if ENV_CLEANED.load(std::sync::atomic::Ordering::Relaxed) {
        trace!("Environment already cleaned, skipping");
        return;
    }
    ENV_CLEANED.store(true, std::sync::atomic::Ordering::Relaxed);
    let _lock = ENV_MUTEX.lock();
    let env = std::env::vars().collect::<Vec<_>>();
    for (key, _val) in env {
        unsafe {
            std::env::set_var(&key, "");
            std::env::remove_var(&key);
        };
    }

    #[cfg(debug_assertions)]
    {
        info!("Environment variables cleared, checking");
        let env = std::env::vars().collect::<Vec<_>>();
        if env.is_empty() {
            info!("No environment variables found");
        } else {
            error!("Remaining environment variables:");
            for (key, val) in env {
                error!("{key}={val}");
            }
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
            GetProcessHeap().map_err(|err| {
                error!("Failed to get process heap: {err:?}");
                anyhow::anyhow!("Failed to get process heap, {err:?}")
            })?,
            HEAP_ZERO_MEMORY,
            attribute_size,
        )));

        if let Err(err) =
            InitializeProcThreadAttributeList(Some(*attributes), 1, None, &raw mut attribute_size)
        {
            error!("Failed to initialize attribute list: {err:?}");
            return Err(anyhow::anyhow!(
                "Failed to initialize attribute list, {err:?}"
            ));
        }
        trace!("Initialized attribute list, attribute size: {attribute_size}");

        let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

        if let Err(err) = UpdateProcThreadAttribute(
            *attributes,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(std::ptr::from_ref(&policy).cast::<std::ffi::c_void>()),
            std::mem::size_of::<u64>(),
            None,
            None,
        ) {
            error!("Failed to update attribute list: {err:?}");
            return Err(anyhow::anyhow!("Failed to update attribute list, {err:?}"));
        }
        trace!("Updated attribute list with mitigation policy: {policy:#x}");

        Ok(attributes)
    }
}

/// Restarts the current process with the `--clean` argument.
///
/// # Errors
/// Returns an error if the process restart fails.
#[inline]
pub fn restart_self() -> Result<(), anyhow::Error> {
    let current_path = std::env::current_exe()?;
    let Some(current_path) = current_path.to_str() else {
        return Err(anyhow::anyhow!("Failed to convert path to string"));
    };
    let cmdline = format!("\"{current_path}\" --clean");

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

        if let Err(err) = CreateProcessW(
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
            error!("Failed to create process: {err} - | {:?}", GetLastError());
            return Err(anyhow::anyhow!("Failed to create process"));
        }
        trace!("Process created successfully, exiting current process");
        free_console();
        Ok(())
    }
}

pub fn free_console() {
    unsafe {
        let res = FreeConsole();
        info!("FreeConsole result: {res:?}");
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
    trace!(
        "Joining threadID: {:?} with timeout: {timeout:?}",
        thread_handle.thread().id()
    );
    let start = std::time::Instant::now();
    while !thread_handle.is_finished() {
        if start.elapsed() > timeout {
            error!("Thread join timed out after {timeout:?}");
            return Err(anyhow::anyhow!("Thread join timed out"));
        }
        std::thread::park_timeout(std::time::Duration::from_millis(5));
    }
    trace!(
        "ThreadID: {:?} finished, joining",
        thread_handle.thread().id()
    );
    thread_handle.join().map_err(|err| {
        error!("Failed to join thread: {err:?}");
        anyhow::anyhow!("Failed to join thread")
    })?;
    Ok(())
}

#[inline]
#[allow(clippy::missing_panics_doc)]
pub fn enable_mitigations() {
    info!("Enabling mitigations");
    thread::hide_current_thread_from_debuggers();
    heap_protection();
    exclude_wefault();
    clean_env();
    reset_current_dir();
    set_policy_mitigation();
    info!("Mitigations enabled");
}

fn heap_protection() {
    info!("Enabling heap protections");
    let res = unsafe { HeapSetInformation(None, HeapEnableTerminationOnCorruption, None, 0) };
    info!("HeapSetInformation - HeapEnableTerminationOnCorruption result: {res:?}");

    let heap_info = HEAP_OPTIMIZE_RESOURCES_INFORMATION {
        Version: 1,
        ..Default::default()
    };

    let res = unsafe {
        HeapSetInformation(
            None,
            HeapOptimizeResources,
            Some((&raw const heap_info).cast::<std::ffi::c_void>()),
            std::mem::size_of::<HEAP_OPTIMIZE_RESOURCES_INFORMATION>(),
        )
    };
    info!("HeapSetInformation - HeapOptimizeResources result: {res:?}");
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
    #[inline]
    const fn to_thread_priority(self) -> THREAD_PRIORITY {
        match self {
            Self::Lowest => THREAD_PRIORITY_LOWEST,
            Self::BelowNormal => THREAD_PRIORITY_BELOW_NORMAL,
            Self::Normal => THREAD_PRIORITY_NORMAL,
            Self::AboveNormal => THREAD_PRIORITY_ABOVE_NORMAL,
            Self::High => THREAD_PRIORITY_HIGHEST,
            Self::TimeCritical => THREAD_PRIORITY_TIME_CRITICAL,
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
pub fn set_process_priority() {
    unsafe {
        let status = SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
        trace!("Set process priority to BelowNormal: {status:?}");
    }
}

#[inline]
fn exclude_wefault() {
    let Ok(current_exe) = std::env::current_exe() else {
        error!("Failed to get current exe path");
        return;
    };

    let Some(exe_name) = current_exe.file_name() else {
        error!("Failed to get current exe name");
        return;
    };

    trace!("Current exe name: {exe_name:?}");
    trace!("Excluding {exe_name:?} from Windows Error Reporting");

    let exe_name = HSTRING::from(exe_name.to_string_lossy().as_ref());

    let status = unsafe { WerAddExcludedApplication(&exe_name, false) };
    info!("Set wefault exclusion status: {status:?}");
}

#[inline]
fn set_policy_mitigation() {
    if std::env::args().any(|arg| arg == "--clean") {
        info!("Found --clean argument, setting child process policy");
        win_mitigations::child_process::ChildProcessPolicy::default()
            .set_no_child_process_creation(true)
            .build()
            .inspect(|()| trace!("Child process policy set"))
            .expect("Failed to set child process policy");
    } else {
        info!("No --clean argument found, not setting child process policy");
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
