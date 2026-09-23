#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use light_program_profiler::profile;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    Address,
};
use pinocchio::{AccountView, ProgramResult};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_program::cpi::{SppTransactAccounts, TransactAccountsError};

use crate::error::TimelockEscrowError;

pub fn u64_right_align(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[inline(always)]
pub fn check_after_window(now: i64, unlock_unix_ts: u64) -> ProgramResult {
    if now >= 0 && (now as u64) > unlock_unix_ts {
        Ok(())
    } else {
        Err(TimelockEscrowError::NotYetUnlocked.into())
    }
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed(
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    let (escrow_authority, bump) =
        Address::find_program_address(&[crate::ESCROW_AUTHORITY_PDA_SEED], &crate::ID);
    let signer_pdas = [&escrow_authority];
    let spp =
        SppTransactAccounts::new(spp_accounts, &signer_pdas).map_err(transact_accounts_error)?;
    let bump = [bump];
    let seeds = [
        Seed::from(crate::ESCROW_AUTHORITY_PDA_SEED),
        Seed::from(&bump),
    ];
    spp.invoke::<16>(transact_bytes, &[Signer::from(&seeds)])
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn transact_accounts_error(error: TransactAccountsError) -> ProgramError {
    match error {
        TransactAccountsError::InvalidSppProgram => {
            TimelockEscrowError::InvalidShieldedPoolProgram.into()
        }
        TransactAccountsError::MissingPdaSigner { .. } => {
            TimelockEscrowError::MissingEscrowAuthority.into()
        }
        TransactAccountsError::NotEnoughAccounts => ProgramError::NotEnoughAccountKeys,
    }
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_transact_signed(
    _spp_accounts: &[AccountView],
    _transact_bytes: &[u8],
) -> ProgramResult {
    unimplemented!("cpi_spp_transact_signed requires Solana runtime syscalls")
}
