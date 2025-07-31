#![cfg(windows)]
use std::{ffi::c_void, thread::JoinHandle};
use tracing::{info, trace};
use windows::{
    Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger},
    Win32::System::{
        SystemServices::{
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
            SE_SIGNING_LEVEL_DYNAMIC_CODEGEN, SE_SIGNING_LEVEL_MICROSOFT,
        },
        Threading::{
            GetCurrentThread, ProcessDynamicCodePolicy, ProcessSignaturePolicy,
            SetProcessMitigationPolicy,
        },
    },
};

/// Joins a thread with a timeout.
///
/// # Errors
/// Returns an error if the thread join fails or times out.
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
    info!("Mitigations enabled");
}

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

pub fn prevent_third_party_dll_loading() {
    info!("Preventing third party dll loading");
    let mut policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    policy.Anonymous.Flags = SE_SIGNING_LEVEL_MICROSOFT;
    policy.Anonymous.Anonymous._bitfield = 1;

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set process mitigation policy status: {:?}", status);
}

pub fn enable_arbitrary_code_guard() {
    if cfg!(debug_assertions) {
        info!("[DEBUG-MODE] NOT PREVENTING third party dll loading");
        return;
    }
    let mut policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    policy.Anonymous.Flags = SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
    policy.Anonymous.Anonymous._bitfield = 1;

    let status = unsafe {
        SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            std::ptr::from_mut(&mut policy).cast::<c_void>(),
            std::mem::size_of_val(&policy),
        )
    };
    info!("Set process mitigation policy status: {:?}", status);
}
