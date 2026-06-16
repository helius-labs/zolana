//! Short diagnostic logs for failures that otherwise surface as Custom(N).

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
