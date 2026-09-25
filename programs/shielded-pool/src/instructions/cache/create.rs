use super::{init::CacheInitParams, loader::load_cache};
use crate::instructions::shared::{verify_pda, CreatePdaAccount};
use pinocchio::{
    address::address_eq,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateCacheData,
    state::{cache::CACHE_SEED, CacheAccount},
};

/// Create an empty cache at the rent sponsor's nonce-derived PDA.
///
/// Steps:
/// 1. Decode the instruction and require exactly payer, cache, and system program.
/// 2. Require a future expiry.
/// 3. Verify the PDA derived from the rent sponsor and nonce.
/// 4. Return success for an existing cache only if its configuration matches.
/// 5. Otherwise, create and initialize an empty cache.
pub fn process_create_cache(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    // 1. Decode the instruction and validate the three accounts.
    let ix =
        CreateCacheData::from_bytes(data).map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("rent_payer")?;
    let cache = iter.next_mut("cache")?;
    let system = iter.next_account("system_program")?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    if !pinocchio_system::check_id(system.address()) {
        return Err(ShieldedPoolError::InvalidSystemProgram.into());
    }
    // 2. Validate expiry, including on retries.
    let clock = Clock::get()?;
    if ix.expires_at <= clock.unix_timestamp {
        return Err(ShieldedPoolError::CacheExpiryNotInFuture.into());
    }
    // 3. The payer sponsors rent; its address and nonce determine the PDA.
    let rent_sponsor = *payer.address();
    let nonce_le = ix.nonce.to_le_bytes();
    let bump = verify_pda(
        cache.address(),
        &[CACHE_SEED, rent_sponsor.as_array(), &nonce_le],
        &crate::ID,
    )?;
    // 4. A matching retry is a no-op, preserving the utxo hashes. The
    //    derivation already fixes the stored rent sponsor and bump.
    if cache.owned_by(&crate::ID) {
        let current = load_cache(cache)?;
        if !address_eq(&current.write_authority, &ix.write_authority)
            || current.tree_id != ix.tree_id.to_le_bytes()
            || current.expires_at != ix.expires_at.to_le_bytes()
        {
            return Err(ShieldedPoolError::CacheConfigMismatch.into());
        }
        return Ok(());
    }
    // 5. Only an empty system-owned account can become a new cache.
    if !pinocchio_system::check_id(cache.owner()) || cache.data_len() != 0 {
        return Err(ShieldedPoolError::InvalidCache.into());
    }
    CreatePdaAccount {
        fee_payer: payer,
        new_account: cache,
        space: CacheAccount::SIZE,
        owner: &crate::ID,
        signer_seeds: [CACHE_SEED, rent_sponsor.as_array(), &nonce_le],
        bump,
    }
    .execute()?;
    CacheInitParams {
        bump,
        tree_id: ix.tree_id,
        expires_at: ix.expires_at,
        rent_sponsor,
        write_authority: ix.write_authority,
    }
    .init(cache)
}
