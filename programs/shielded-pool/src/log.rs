//! Thin `sol_log_` wrapper. Used for short diagnostic strings before
//! mapping an upstream error to our coarser `ShieldedPoolError` variant —
//! so a runtime failure shows up in `solana logs` as a human-readable
//! breadcrumb (which subsystem rejected) on top of the numeric Custom(N).

#[inline]
pub fn log(message: &str) {
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_log_(message.as_ptr(), message.len() as u64);
    }
    #[cfg(not(target_os = "solana"))]
    {
        let _ = message;
    }
}
