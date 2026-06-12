//! Thin `sol_log_` wrapper so failures surface in transaction logs as a
//! human-readable error name on top of the numeric `Custom(N)` code.

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
