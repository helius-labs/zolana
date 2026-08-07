#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use light_program_profiler::profile;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    Address,
};
use pinocchio::{AccountView, ProgramResult};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_interface::{
    instruction::tag::{AGGREGATE_TRANSACT, TRANSACT},
    SHIELDED_POOL_PROGRAM_ID,
};

use crate::error::SwapError;

pub fn u64_right_align(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

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

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed(
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    cpi_spp_signed::<16>(spp_accounts, TRANSACT, transact_bytes)
}

/// A batch concatenates one account run per leg, so it needs a wider bound than
/// the solo path.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
#[profile]
pub fn cpi_spp_aggregate_transact_signed(
    spp_accounts: &[AccountView],
    aggregate_bytes: &[u8],
) -> ProgramResult {
    cpi_spp_signed::<32>(spp_accounts, AGGREGATE_TRANSACT, aggregate_bytes)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn cpi_spp_signed<const MAX_ACCOUNTS: usize>(
    spp_accounts: &[AccountView],
    spp_tag: u8,
    payload: &[u8],
) -> ProgramResult {
    let (order_authority, bump) =
        Address::find_program_address(&[crate::ORDER_AUTHORITY_PDA_SEED], &crate::ID);

    let spp_program_account = spp_accounts
        .get(3)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if spp_program_account.address() != &spp_id {
        return Err(SwapError::InvalidShieldedPoolProgram.into());
    }

    if !spp_accounts
        .iter()
        .any(|account| account.address() == &order_authority)
    {
        return Err(SwapError::MissingOrderAuthority.into());
    }

    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|account| {
            let is_signer = account.is_signer() || account.address() == &order_authority;
            InstructionAccount::new(account.address(), account.is_writable(), is_signer)
        })
        .collect();

    let mut instruction_data = Vec::with_capacity(1 + payload.len());
    instruction_data.push(spp_tag);
    instruction_data.extend_from_slice(payload);

    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &instruction_data,
    };
    let bump = [bump];
    let seeds = [
        Seed::from(crate::ORDER_AUTHORITY_PDA_SEED),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    invoke_signed_with_bounds::<MAX_ACCOUNTS, _>(
        &instruction,
        spp_accounts,
        core::slice::from_ref(&signer),
    )
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_transact_signed(
    _spp_accounts: &[AccountView],
    _transact_bytes: &[u8],
) -> ProgramResult {
    unimplemented!("cpi_spp_transact_signed requires Solana runtime syscalls")
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_aggregate_transact_signed(
    _spp_accounts: &[AccountView],
    _aggregate_bytes: &[u8],
) -> ProgramResult {
    unimplemented!("cpi_spp_aggregate_transact_signed requires Solana runtime syscalls")
}
