use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use spr_program::cpi::PdaSigner;

use crate::error::SwapError;

#[inline(always)]
pub fn check_within_window(now: i64, expiry_unix_ts: u64) -> ProgramResult {
    if now >= 0 && (now as u64) <= expiry_unix_ts {
        Ok(())
    } else {
        Err(SwapError::Expired.into())
    }
}

#[inline(always)]
pub fn check_after_window(now: i64, expiry_unix_ts: u64) -> ProgramResult {
    if now >= 0 && (now as u64) > expiry_unix_ts {
        Ok(())
    } else {
        Err(SwapError::NotYetExpired.into())
    }
}

/// Invokes transact through `spp_accounts`, signing for the order authority PDA.
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed(
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    PdaSigner::find([crate::ORDER_AUTHORITY_PDA_SEED], &crate::ID)
        .invoke_transact::<16>(spp_accounts, transact_bytes)
}
