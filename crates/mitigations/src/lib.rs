#![cfg(windows)]
use std::{ffi::c_void, thread::JoinHandle};
use tracing::{info, trace};
use windows::{
    Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger},
    Win32::System::{
        SystemServices::{
            PROCESS_MITIGATION_ASLR_POLICY, PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
            PROCESS_MITIGATION_FONT_DISABLE_POLICY,
        },
        Threading::{
            GetCurrentThread, ProcessASLRPolicy, ProcessChildProcessPolicy,
            ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessFontDisablePolicy,
            ProcessSignaturePolicy, SetProcessMitigationPolicy,
        },
    },
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
pub fn enable_mitigations() {
    info!("Enabling mitigations...");
    hide_current_thread_from_debuggers();
    prevent_third_party_dll_loading();
    enable_arbitrary_code_guard();
    prevent_font_policy();
    prevent_child_process_creation();
    prevent_extension_points();
    enable_aslr();
    info!("Mitigations enabled");
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
pub fn prevent_third_party_dll_loading() {
    info!("Preventing third party dll loading");
    let mut policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    unsafe { policy.Anonymous.Flags |= 1 << 0 };

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set process mitigation policy status: {:?}", status);
}

#[inline]
pub fn prevent_font_policy() {
    info!("Preventing font loading");
    let mut policy = PROCESS_MITIGATION_FONT_DISABLE_POLICY::default();
    unsafe { policy.Anonymous.Flags |= 1 << 0 };

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessFontDisablePolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set font disable policy status: {:?}", status);
}

#[inline]
pub fn prevent_child_process_creation() {
    info!("Preventing child process creation");
    let mut policy = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
    unsafe { policy.Anonymous.Flags |= 1 << 0 };

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessChildProcessPolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set child process mitigation policy status: {:?}", status);
}

#[inline]
pub fn prevent_extension_points() {
    info!("Preventing extension points");
    let mut policy = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
    unsafe { policy.Anonymous.Flags |= 1 << 0 };

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessExtensionPointDisablePolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set extension point disable policy status: {:?}", status);
}

#[inline]
pub fn enable_aslr() {
    info!("Enabling ASLR");
    let mut policy = PROCESS_MITIGATION_ASLR_POLICY::default();
    unsafe {
        policy.Anonymous.Flags |= 1 << 0; // BottomUpRandomization
        policy.Anonymous.Flags |= 1 << 1; // ForceRelocateImages
        policy.Anonymous.Flags |= 1 << 2; // Enable high entropy ASLR
    };

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessASLRPolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set ASLR policy status: {:?}", status);
}

#[inline]
pub fn enable_arbitrary_code_guard() {
    if cfg!(debug_assertions) {
        info!("[DEBUG-MODE] NOT PREVENTING third party dll loading");
        return;
    }
    let mut policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    unsafe { policy.Anonymous.Flags |= 1 << 0 };

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set acg mitigation policy status: {:?}", status);
}
