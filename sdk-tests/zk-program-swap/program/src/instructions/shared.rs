use light_program_profiler::profile;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::cpi::{invoke_signed_with_bounds, Seed, Signer};
use pinocchio::{
    cpi::invoke_with_bounds,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{instruction::tag::TRANSACT, SHIELDED_POOL_PROGRAM_ID};

use crate::error::SwapError;

pub fn u64_right_align(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

/// `owner_pk_field` for an ed25519 owner: `Poseidon(value[16..32], value[0..16])`
/// with each half right-aligned into a field element. Matches
/// `zolana_keypair::hash::hash_field` so the maker's Solana signer pubkey maps
/// to the `owner_pk_field` committed in the order's `maker_owner_hash`.
pub fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let mut low = [0u8; 32];
    low[16..].copy_from_slice(&value[16..32]);
    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&value[0..16]);
    Poseidon::hashv(&[low.as_slice(), high.as_slice()]).map_err(|_| SwapError::HashingFailed.into())
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

#[inline(never)]
#[profile]
pub fn cpi_spp_transact(spp_accounts: &[AccountView], transact_bytes: &[u8]) -> ProgramResult {
    let spp_program_account = spp_accounts
        .last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if spp_program_account.address() != &spp_id {
        return Err(SwapError::InvalidShieldedPoolProgram.into());
    }

    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer(),
            )
        })
        .collect();

    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(TRANSACT);
    instruction_data.extend_from_slice(transact_bytes);

    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &instruction_data,
    };
    invoke_with_bounds::<16, _>(&instruction, spp_accounts)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed(
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    let (order_authority, bump) =
        Address::find_program_address(&[crate::ORDER_AUTHORITY_PDA_SEED], &crate::ID);

    let spp_program_account = spp_accounts
        .last()
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

    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(TRANSACT);
    instruction_data.extend_from_slice(transact_bytes);

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
    invoke_signed_with_bounds::<16, _>(&instruction, spp_accounts, core::slice::from_ref(&signer))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_transact_signed(
    _spp_accounts: &[AccountView],
    _transact_bytes: &[u8],
) -> ProgramResult {
    unimplemented!("cpi_spp_transact_signed requires Solana runtime syscalls")
}
