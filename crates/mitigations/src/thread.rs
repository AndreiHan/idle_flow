use tracing::{error, info, trace};
use windows::{
    Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger},
    Win32::Foundation::HANDLE,
    Win32::{
        System::Diagnostics::Debug::CONTEXT_FLAGS,
        System::{
            Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext},
            Threading::{
                GetCurrentThread, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
                THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
            },
        },
    },
    core::Owned,
};

fn clear_hardware_breakpoints_on_thread(
    thread_handle: windows::Win32::Foundation::HANDLE,
) -> Result<(), windows::core::Error> {
    info!("Clearing hardware breakpoints on thread handle: {thread_handle:?}");

    let suspend_count = unsafe { SuspendThread(thread_handle) };
    if suspend_count == u32::MAX {
        let last_err = std::io::Error::last_os_error();
        error!("Failed to suspend thread for debug register clearing: {last_err:?}");
        return Err(last_err.into());
    }
    trace!(
        "Thread suspended (previous count: {suspend_count}){}",
        if suspend_count > 0 {
            ", was already suspended"
        } else {
            ""
        }
    );

    let res = clear_context(thread_handle)
        .inspect_err(|e| error!("Failed to clear debug registers: {e:?}"));

    info!("Resuming thread after debug register clearing");
    let resume_count = unsafe { ResumeThread(thread_handle) };
    if resume_count == u32::MAX {
        let last_err = std::io::Error::last_os_error();
        error!("Failed to resume thread after debug register clearing: {last_err:?}");
        return Err(last_err.into());
    }
    trace!(
        "Thread resumed (new count: {})",
        resume_count.saturating_sub(1)
    );

    res
}

fn clear_context(thread_handle: HANDLE) -> Result<(), windows::core::Error> {
    let mut ctx = AlignedContext {
        ctx: CONTEXT {
            ContextFlags: CONTEXT_DEBUG_REGISTERS,
            ..Default::default()
        },
    };

    (unsafe { GetThreadContext(thread_handle, &raw mut ctx.ctx) })?;

    if ctx.has_breakpoints() {
        ctx.log_registers();
    } else {
        trace!("No hardware breakpoints detected");
    }

    ctx.clear();

    unsafe { SetThreadContext(thread_handle, &raw const ctx.ctx) }?;
    info!("Debug registers cleared successfully");
    Ok(())
}

fn clear_hardware_breakpoints_current_thread() {
    let current_tid = unsafe { GetCurrentThreadId() };
    trace!("Clearing hardware breakpoints on current thread (TID: {current_tid})");

    trace!("Spawning helper thread to clear hardware breakpoints");
    let handle = std::thread::spawn(move || {
        inner_hide_current_thread_from_debuggers();
        let thread_handle = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                false,
                current_tid,
            )
        }
        .inspect_err(|e| error!("Failed to open thread handle for TID {current_tid}: {e:?}"))
        .map(|handle| unsafe { Owned::new(handle) });

        let Ok(thread_handle) = thread_handle else {
            return;
        };
        let result = clear_hardware_breakpoints_on_thread(*thread_handle);

        if let Err(e) = result {
            error!("Failed to clear hardware breakpoints on thread TID {current_tid}: {e:?}");
        } else {
            info!("Successfully cleared hardware breakpoints on thread TID {current_tid}");
        }
    });

    // Wait for helper thread (we'll be suspended briefly during this)
    trace!("Waiting for helper thread to complete");
    if let Err(e) = handle.join() {
        error!("Helper thread panicked: {e:?}");
    }
}

/// Checks if a debugger is attached using the standard API.
#[inline]
fn is_debugger_present() -> bool {
    use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    unsafe { IsDebuggerPresent().as_bool() }
}

#[inline]
pub fn hide_current_thread_from_debuggers() {
    if cfg!(debug_assertions) {
        info!("[DEBUG-MODE] NOT SETTING anti debug status");
        return;
    }

    if is_debugger_present() {
        error!("Debugger detected via IsDebuggerPresent API");
    }

    inner_hide_current_thread_from_debuggers();
    clear_hardware_breakpoints_current_thread();
}

fn inner_hide_current_thread_from_debuggers() {
    if cfg!(debug_assertions) {
        info!("[DEBUG-MODE] NOT SETTING anti debug status");
        return;
    }

    info!("Hiding current thread from debugger, NtSetInformationThread(ThreadHideFromDebugger)");
    let status = unsafe {
        NtSetInformationThread(
            GetCurrentThread(),
            ThreadHideFromDebugger,
            std::ptr::null(),
            0,
        )
    };

    if status.is_ok() {
        info!("Thread hidden from debugger successfully");
    } else {
        error!("Failed to hide thread from debugger: {status:?}");
    }
}

/// Architecture-specific context flag for debug registers.
#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG_REGISTERS: CONTEXT_FLAGS = {
    use windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
    CONTEXT_DEBUG_REGISTERS_AMD64
};

#[cfg(target_arch = "aarch64")]
const CONTEXT_DEBUG_REGISTERS: CONTEXT_FLAGS = {
    use windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_ARM64;
    CONTEXT_DEBUG_REGISTERS_ARM64
};

/// Aligned wrapper for CONTEXT structure.
/// `x86_64`/`ARM64` require 16-byte alignment for XMM/NEON registers.
/// Using an unaligned CONTEXT with `GetThreadContext`/`SetThreadContext` causes
/// `ERROR_NOACCESS` (0x800703E6 - "Invalid access to memory location").
#[repr(C, align(16))]
struct AlignedContext {
    ctx: CONTEXT,
}

impl Default for AlignedContext {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl std::ops::Deref for AlignedContext {
    type Target = CONTEXT;
    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl std::ops::DerefMut for AlignedContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}

/// Trait for architecture-specific debug register operations.
/// Abstracts the differences between x64 and ARM64 debug registers.
trait DebugRegisters {
    /// Returns true if any hardware breakpoints are set.
    fn has_breakpoints(&self) -> bool;
    /// Clears all debug registers.
    fn clear(&mut self);
    /// Logs the current debug register values.
    fn log_registers(&self);
}

#[cfg(target_arch = "x86_64")]
impl DebugRegisters for CONTEXT {
    fn has_breakpoints(&self) -> bool {
        self.Dr0 != 0 || self.Dr1 != 0 || self.Dr2 != 0 || self.Dr3 != 0 || (self.Dr7 & 0xFF) != 0
    }

    fn clear(&mut self) {
        self.Dr0 = 0;
        self.Dr1 = 0;
        self.Dr2 = 0;
        self.Dr3 = 0;
        self.Dr6 = 0;
        self.Dr7 = 0;
    }

    fn log_registers(&self) {
        info!(
            "Hardware breakpoints detected - DR0:{:#x} DR1:{:#x} DR2:{:#x} DR3:{:#x} DR6:{:#x} DR7:{:#x}",
            self.Dr0, self.Dr1, self.Dr2, self.Dr3, self.Dr6, self.Dr7
        );
    }
}

#[cfg(target_arch = "aarch64")]
impl DebugRegisters for CONTEXT {
    fn has_breakpoints(&self) -> bool {
        self.Bcr.iter().any(|&v| v != 0)
            || self.Bvr.iter().any(|&v| v != 0)
            || self.Wcr.iter().any(|&v| v != 0)
            || self.Wvr.iter().any(|&v| v != 0)
    }

    fn clear(&mut self) {
        self.Bcr.fill(0);
        self.Bvr.fill(0);
        self.Wcr.fill(0);
        self.Wvr.fill(0);
    }

    fn log_registers(&self) {
        info!(
            "Hardware breakpoints detected - Bcr:{:?} Bvr:{:?} Wcr:{:?} Wvr:{:?}",
            self.Bcr, self.Bvr, self.Wcr, self.Wvr
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aligned_context_default() {
        let ctx = AlignedContext::default();
        // Default should be zeroed
        assert_eq!(ctx.ctx.ContextFlags, CONTEXT_FLAGS(0));
    }

    #[test]
    fn test_aligned_context_alignment() {
        let ctx = AlignedContext::default();
        let ptr = &raw const ctx;
        // Check 16-byte alignment
        assert_eq!(
            ptr as usize % 16,
            0,
            "AlignedContext must be 16-byte aligned"
        );
    }

    #[test]
    fn test_aligned_context_deref() {
        let mut ctx = AlignedContext::default();
        ctx.ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        // Test Deref
        assert_eq!(ctx.ContextFlags, CONTEXT_DEBUG_REGISTERS);
    }

    #[test]
    fn test_aligned_context_deref_mut() {
        let mut ctx = AlignedContext::default();
        // Test DerefMut - modify through deref
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        assert_eq!(ctx.ctx.ContextFlags, CONTEXT_DEBUG_REGISTERS);
    }

    #[cfg(target_arch = "x86_64")]
    mod x86_64_tests {
        use super::*;

        #[test]
        fn test_has_breakpoints_none_set() {
            let ctx = CONTEXT::default();
            assert!(!ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_dr0_set() {
            let mut ctx = CONTEXT::default();
            ctx.Dr0 = 0x12345678;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_dr1_set() {
            let mut ctx = CONTEXT::default();
            ctx.Dr1 = 0x12345678;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_dr2_set() {
            let mut ctx = CONTEXT::default();
            ctx.Dr2 = 0x12345678;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_dr3_set() {
            let mut ctx = CONTEXT::default();
            ctx.Dr3 = 0x12345678;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_dr7_enabled() {
            let mut ctx = CONTEXT::default();
            ctx.Dr7 = 0x01; // Local enable bit set
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_dr7_high_bits_only() {
            let mut ctx = CONTEXT::default();
            // High bits set but no enable bits in lower byte
            ctx.Dr7 = 0xFF00;
            assert!(!ctx.has_breakpoints());
        }

        #[test]
        fn test_clear_debug_registers() {
            let mut ctx = CONTEXT::default();
            ctx.Dr0 = 0x11111111;
            ctx.Dr1 = 0x22222222;
            ctx.Dr2 = 0x33333333;
            ctx.Dr3 = 0x44444444;
            ctx.Dr6 = 0x55555555;
            ctx.Dr7 = 0x66666666;

            ctx.clear();

            assert_eq!(ctx.Dr0, 0);
            assert_eq!(ctx.Dr1, 0);
            assert_eq!(ctx.Dr2, 0);
            assert_eq!(ctx.Dr3, 0);
            assert_eq!(ctx.Dr6, 0);
            assert_eq!(ctx.Dr7, 0);
        }

        #[test]
        fn test_clear_removes_breakpoints() {
            let mut ctx = CONTEXT::default();
            ctx.Dr0 = 0x12345678;
            ctx.Dr7 = 0x01;
            assert!(ctx.has_breakpoints());

            ctx.clear();
            assert!(!ctx.has_breakpoints());
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod aarch64_tests {
        use super::*;

        #[test]
        fn test_has_breakpoints_none_set() {
            let ctx = CONTEXT::default();
            assert!(!ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_bcr_set() {
            let mut ctx = CONTEXT::default();
            ctx.Bcr[0] = 1;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_bvr_set() {
            let mut ctx = CONTEXT::default();
            ctx.Bvr[0] = 0x12345678;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_wcr_set() {
            let mut ctx = CONTEXT::default();
            ctx.Wcr[0] = 1;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_has_breakpoints_wvr_set() {
            let mut ctx = CONTEXT::default();
            ctx.Wvr[0] = 0x12345678;
            assert!(ctx.has_breakpoints());
        }

        #[test]
        fn test_clear_debug_registers() {
            let mut ctx = CONTEXT::default();
            ctx.Bcr[0] = 1;
            ctx.Bvr[0] = 0x12345678;
            ctx.Wcr[0] = 1;
            ctx.Wvr[0] = 0x87654321;

            ctx.clear();

            assert!(ctx.Bcr.iter().all(|&v| v == 0));
            assert!(ctx.Bvr.iter().all(|&v| v == 0));
            assert!(ctx.Wcr.iter().all(|&v| v == 0));
            assert!(ctx.Wvr.iter().all(|&v| v == 0));
        }

        #[test]
        fn test_clear_removes_breakpoints() {
            let mut ctx = CONTEXT::default();
            ctx.Bcr[0] = 1;
            assert!(ctx.has_breakpoints());

            ctx.clear();
            assert!(!ctx.has_breakpoints());
        }
    }

    #[test]
    fn test_is_debugger_present_returns_bool() {
        // This just verifies the function runs without panicking
        // The actual value depends on whether a debugger is attached
        let _result: bool = is_debugger_present();
    }

    /// Integration test that sets real hardware breakpoints and verifies they get cleared.
    /// This test spawns a thread, sets debug registers on it, then clears them.
    #[test]
    fn test_clear_hardware_breakpoints_integration() {
        use std::sync::{Arc, Barrier};
        use windows::Win32::System::Threading::{
            GetCurrentThreadId, OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
        };

        // Barrier to synchronize between main test thread and target thread
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        // Channel to get the thread ID from the spawned thread
        let (tx, rx) = std::sync::mpsc::channel();

        // Spawn target thread that will have breakpoints set on it
        let target_handle = std::thread::spawn(move || {
            let tid = unsafe { GetCurrentThreadId() };
            tx.send(tid).unwrap();

            // Wait for main thread to set breakpoints
            barrier_clone.wait();

            // Wait for main thread to clear breakpoints
            barrier_clone.wait();

            // Wait for main thread to verify cleanup
            barrier_clone.wait();
        });

        // Get the target thread ID
        let target_tid = rx.recv().expect("Failed to receive thread ID");

        // Open handle to the target thread
        let thread_handle = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                false,
                target_tid,
            )
        }
        .expect("Failed to open thread handle");
        let thread_handle = unsafe { Owned::new(thread_handle) };

        // === Phase 1: Set hardware breakpoints ===
        {
            // Suspend thread to modify context
            let suspend_count = unsafe { SuspendThread(*thread_handle) };
            assert_ne!(suspend_count, u32::MAX, "Failed to suspend thread");

            // Set debug registers
            let mut ctx = AlignedContext {
                ctx: CONTEXT {
                    ContextFlags: CONTEXT_DEBUG_REGISTERS,
                    ..Default::default()
                },
            };

            unsafe { GetThreadContext(*thread_handle, &raw mut ctx.ctx) }
                .expect("Failed to get thread context");

            // Set hardware breakpoints (x86_64 specific values)
            #[cfg(target_arch = "x86_64")]
            {
                ctx.ctx.Dr0 = 0xDEADBEEF;
                ctx.ctx.Dr1 = 0xCAFEBABE;
                ctx.ctx.Dr2 = 0x12345678;
                ctx.ctx.Dr3 = 0x87654321;
                ctx.ctx.Dr7 = 0x00000155; // Enable all 4 breakpoints (local)
            }

            #[cfg(target_arch = "aarch64")]
            {
                ctx.ctx.Bcr[0] = 1;
                ctx.ctx.Bvr[0] = 0xDEADBEEF;
                ctx.ctx.Wcr[0] = 1;
                ctx.ctx.Wvr[0] = 0xCAFEBABE;
            }

            unsafe { SetThreadContext(*thread_handle, &raw const ctx.ctx) }
                .expect("Failed to set thread context with breakpoints");

            // Immediately read back to verify Win32 accepted our values
            let mut verify_ctx = AlignedContext {
                ctx: CONTEXT {
                    ContextFlags: CONTEXT_DEBUG_REGISTERS,
                    ..Default::default()
                },
            };

            unsafe { GetThreadContext(*thread_handle, &raw mut verify_ctx.ctx) }
                .expect("Failed to get thread context for verification");

            // Verify breakpoints match what we set
            assert!(
                verify_ctx.has_breakpoints(),
                "Breakpoints should be set after SetThreadContext"
            );

            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(
                    verify_ctx.ctx.Dr0, 0xDEADBEEF,
                    "DR0 mismatch: expected 0xDEADBEEF, got {:#x}",
                    verify_ctx.ctx.Dr0
                );
                assert_eq!(
                    verify_ctx.ctx.Dr1, 0xCAFEBABE,
                    "DR1 mismatch: expected 0xCAFEBABE, got {:#x}",
                    verify_ctx.ctx.Dr1
                );
                assert_eq!(
                    verify_ctx.ctx.Dr2, 0x12345678,
                    "DR2 mismatch: expected 0x12345678, got {:#x}",
                    verify_ctx.ctx.Dr2
                );
                assert_eq!(
                    verify_ctx.ctx.Dr3, 0x87654321,
                    "DR3 mismatch: expected 0x87654321, got {:#x}",
                    verify_ctx.ctx.Dr3
                );
                assert_eq!(
                    verify_ctx.ctx.Dr7 & 0xFF,
                    0x55,
                    "DR7 enable bits mismatch: expected 0x55, got {:#x}",
                    verify_ctx.ctx.Dr7 & 0xFF
                );
            }

            #[cfg(target_arch = "aarch64")]
            {
                assert_eq!(
                    verify_ctx.ctx.Bcr[0], 1,
                    "Bcr[0] mismatch: expected 1, got {}",
                    verify_ctx.ctx.Bcr[0]
                );
                assert_eq!(
                    verify_ctx.ctx.Bvr[0], 0xDEADBEEF,
                    "Bvr[0] mismatch: expected 0xDEADBEEF, got {:#x}",
                    verify_ctx.ctx.Bvr[0]
                );
                assert_eq!(
                    verify_ctx.ctx.Wcr[0], 1,
                    "Wcr[0] mismatch: expected 1, got {}",
                    verify_ctx.ctx.Wcr[0]
                );
                assert_eq!(
                    verify_ctx.ctx.Wvr[0], 0xCAFEBABE,
                    "Wvr[0] mismatch: expected 0xCAFEBABE, got {:#x}",
                    verify_ctx.ctx.Wvr[0]
                );
            }

            // Resume thread
            let resume_count = unsafe { ResumeThread(*thread_handle) };
            assert_ne!(resume_count, u32::MAX, "Failed to resume thread");
        }

        // Let target thread continue
        barrier.wait();

        // === Phase 3: Clear hardware breakpoints ===
        clear_hardware_breakpoints_on_thread(*thread_handle)
            .expect("Failed to clear hardware breakpoints");

        // Let target thread continue
        barrier.wait();

        // === Phase 4: Verify breakpoints were cleared ===
        {
            let suspend_count = unsafe { SuspendThread(*thread_handle) };
            assert_ne!(suspend_count, u32::MAX, "Failed to suspend thread");

            let mut ctx = AlignedContext {
                ctx: CONTEXT {
                    ContextFlags: CONTEXT_DEBUG_REGISTERS,
                    ..Default::default()
                },
            };

            unsafe { GetThreadContext(*thread_handle, &raw mut ctx.ctx) }
                .expect("Failed to get thread context");

            // Verify all breakpoints are cleared
            assert!(
                !ctx.has_breakpoints(),
                "Breakpoints should be cleared after cleanup"
            );

            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(ctx.ctx.Dr0, 0, "DR0 should be cleared");
                assert_eq!(ctx.ctx.Dr1, 0, "DR1 should be cleared");
                assert_eq!(ctx.ctx.Dr2, 0, "DR2 should be cleared");
                assert_eq!(ctx.ctx.Dr3, 0, "DR3 should be cleared");
                assert_eq!(ctx.ctx.Dr6, 0, "DR6 should be cleared");
                assert_eq!(ctx.ctx.Dr7, 0, "DR7 should be cleared");
            }

            #[cfg(target_arch = "aarch64")]
            {
                assert!(ctx.ctx.Bcr.iter().all(|&v| v == 0), "Bcr should be cleared");
                assert!(ctx.ctx.Bvr.iter().all(|&v| v == 0), "Bvr should be cleared");
                assert!(ctx.ctx.Wcr.iter().all(|&v| v == 0), "Wcr should be cleared");
                assert!(ctx.ctx.Wvr.iter().all(|&v| v == 0), "Wvr should be cleared");
            }

            let resume_count = unsafe { ResumeThread(*thread_handle) };
            assert_ne!(resume_count, u32::MAX, "Failed to resume thread");
        }

        // Release target thread to finish
        barrier.wait();

        // Wait for target thread to complete
        target_handle.join().expect("Target thread panicked");
    }

    /// Test that clearing breakpoints on current thread works via the helper thread mechanism.
    #[test]
    fn test_clear_hardware_breakpoints_current_thread_integration() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use windows::Win32::System::Threading::{
            GetCurrentThreadId, OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
        };

        let test_completed = Arc::new(AtomicBool::new(false));
        let test_completed_clone = Arc::clone(&test_completed);

        // Spawn a thread where we'll set breakpoints and then clear them
        let handle = std::thread::spawn(move || {
            let current_tid = unsafe { GetCurrentThreadId() };

            // We need another thread to set breakpoints on us
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_clone = Arc::clone(&barrier);

            let setter_handle = std::thread::spawn(move || {
                // Wait for signal that we should set breakpoints
                rx.recv().unwrap();

                let thread_handle = unsafe {
                    OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        false,
                        current_tid,
                    )
                }
                .expect("Failed to open thread handle");
                let thread_handle = unsafe { Owned::new(thread_handle) };

                // Suspend and set breakpoints
                let suspend_count = unsafe { SuspendThread(*thread_handle) };
                assert_ne!(suspend_count, u32::MAX);

                let mut ctx = AlignedContext {
                    ctx: CONTEXT {
                        ContextFlags: CONTEXT_DEBUG_REGISTERS,
                        ..Default::default()
                    },
                };

                unsafe { GetThreadContext(*thread_handle, &raw mut ctx.ctx) }.unwrap();

                #[cfg(target_arch = "x86_64")]
                {
                    ctx.ctx.Dr0 = 0xAAAAAAAA;
                    ctx.ctx.Dr7 = 0x01;
                }

                #[cfg(target_arch = "aarch64")]
                {
                    ctx.ctx.Bcr[0] = 1;
                    ctx.ctx.Bvr[0] = 0xAAAAAAAA;
                }

                unsafe { SetThreadContext(*thread_handle, &raw const ctx.ctx) }.unwrap();

                // Immediately read back to verify Win32 accepted our values
                let mut verify_ctx = AlignedContext {
                    ctx: CONTEXT {
                        ContextFlags: CONTEXT_DEBUG_REGISTERS,
                        ..Default::default()
                    },
                };

                unsafe { GetThreadContext(*thread_handle, &raw mut verify_ctx.ctx) }
                    .expect("Failed to get thread context for verification");

                assert!(
                    verify_ctx.has_breakpoints(),
                    "Breakpoints should be set after SetThreadContext"
                );

                #[cfg(target_arch = "x86_64")]
                {
                    assert_eq!(
                        verify_ctx.ctx.Dr0, 0xAAAAAAAA,
                        "DR0 mismatch: expected 0xAAAAAAAA, got {:#x}",
                        verify_ctx.ctx.Dr0
                    );
                    assert_eq!(
                        verify_ctx.ctx.Dr7 & 0xFF,
                        0x01,
                        "DR7 enable bits mismatch: expected 0x01, got {:#x}",
                        verify_ctx.ctx.Dr7 & 0xFF
                    );
                }

                #[cfg(target_arch = "aarch64")]
                {
                    assert_eq!(
                        verify_ctx.ctx.Bcr[0], 1,
                        "Bcr[0] mismatch: expected 1, got {}",
                        verify_ctx.ctx.Bcr[0]
                    );
                    assert_eq!(
                        verify_ctx.ctx.Bvr[0], 0xAAAAAAAA,
                        "Bvr[0] mismatch: expected 0xAAAAAAAA, got {:#x}",
                        verify_ctx.ctx.Bvr[0]
                    );
                }

                let resume_count = unsafe { ResumeThread(*thread_handle) };
                assert_ne!(resume_count, u32::MAX);

                // Signal that breakpoints are set
                barrier_clone.wait();
            });

            // Tell setter thread to set breakpoints
            tx.send(()).unwrap();

            // Wait for breakpoints to be set
            barrier.wait();

            // Now clear them using the current thread function
            clear_hardware_breakpoints_current_thread();

            // Verify they're cleared - need another thread to check
            let (verify_tx, verify_rx) = std::sync::mpsc::channel::<bool>();

            let verifier_handle = std::thread::spawn(move || {
                let thread_handle = unsafe {
                    OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                        false,
                        current_tid,
                    )
                }
                .expect("Failed to open thread handle");
                let thread_handle = unsafe { Owned::new(thread_handle) };

                let suspend_count = unsafe { SuspendThread(*thread_handle) };
                assert_ne!(suspend_count, u32::MAX);

                let mut ctx = AlignedContext {
                    ctx: CONTEXT {
                        ContextFlags: CONTEXT_DEBUG_REGISTERS,
                        ..Default::default()
                    },
                };

                unsafe { GetThreadContext(*thread_handle, &raw mut ctx.ctx) }.unwrap();

                let has_bp = ctx.has_breakpoints();

                let resume_count = unsafe { ResumeThread(*thread_handle) };
                assert_ne!(resume_count, u32::MAX);

                verify_tx.send(has_bp).unwrap();
            });

            setter_handle.join().unwrap();
            verifier_handle.join().unwrap();

            let still_has_breakpoints = verify_rx.recv().unwrap();
            assert!(
                !still_has_breakpoints,
                "Breakpoints should be cleared after clear_hardware_breakpoints_current_thread"
            );

            test_completed_clone.store(true, Ordering::SeqCst);
        });

        handle.join().expect("Test thread panicked");
        assert!(
            test_completed.load(Ordering::SeqCst),
            "Test should have completed successfully"
        );
    }
}
