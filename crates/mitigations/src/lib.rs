#![cfg(windows)]
use std::thread::JoinHandle;
use tracing::{info, trace};
use windows::{
    Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger},
    Win32::System::Threading::GetCurrentThread,
};

/// Joins a thread with a timeout.
///
/// # Errors
/// Returns an error if the thread join fails or times out.
#[inline]
pub fn join_timeout(
    thread_handle: JoinHandle<()>,
    timeout: std::time::Duration,
) -> Result<(), anyhow::Error> {
    let timeout = std::time::Instant::now() + timeout;
    trace!("Waiting for thread to finish with timeout: {:?}", timeout);
    loop {
        if thread_handle.is_finished() {
            info!("Thread finished");
            return thread_handle.join().map_err(|e| {
                info!("Thread join failed: {:?}", e);
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
    info!("Set anti debug status: {:?}", status);
}

#[inline]
#[allow(clippy::missing_panics_doc)]
pub fn enable_mitigations() {
    win_mitigations::binary_signature::BinarySignaturePolicy::default()
        .build()
        .expect("Failed to set binary signature policy");

    win_mitigations::font_disable::FontDisablePolicy::default()
        .set_disable_non_system_fonts(true)
        .build()
        .expect("Failed to set font disable policy");

    win_mitigations::child_process::ChildProcessPolicy::default()
        .set_no_child_process_creation(true)
        .build()
        .expect("Failed to set child process policy");

    win_mitigations::extension_point::ExtensionPointPolicy::default()
        .set_disable_extension_points(true)
        .build()
        .expect("Failed to set extension point policy");

    win_mitigations::aslr::AslrPolicy::default()
        .set_enable_bottom_up_randomization(true)
        .set_enable_force_relocate_images(true)
        .set_enable_high_entropy(true)
        .build()
        .expect("Failed to set ASLR policy");

    win_mitigations::image_load::ImageLoadPolicy::default()
        .set_prefer_system32_images(true)
        .set_no_remote_images(true)
        .build()
        .expect("Failed to set image load policy");

    #[cfg(debug_assertions)]
    win_mitigations::strict_handle::StrictHandlePolicy::default()
        .set_raise_exception_on_invalid_handle_reference(true)
        .set_handle_exceptions_permanently_enabled(true)
        .build()
        .expect("Failed to set strict handle policy");

    win_mitigations::dynamic_code::DynamicCodePolicy::default()
        .set_prohibit_dynamic_code(true)
        .build()
        .expect("Failed to set dynamic code policy");

    info!("Mitigations enabled");
}
