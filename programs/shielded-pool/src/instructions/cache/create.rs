use super::{init::CacheInitParams, loader::load_cache};
use crate::instructions::shared::{check_field_element, verify_pda, CreatePdaAccount};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateCacheData,
    state::{cache::CACHE_SEED, CacheAccount},
};

pub fn process_create_cache(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
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
    let clock = Clock::get()?;
    if ix.expires_at <= clock.unix_timestamp {
        return Err(ShieldedPoolError::CacheExpiryNotInFuture.into());
    }
    if ix.owner_identity == [0u8; 32] {
        return Err(ShieldedPoolError::InvalidCache.into());
    }
    check_field_element(
        &ix.owner_identity,
        "cache owner identity",
        None,
        ShieldedPoolError::NonCanonicalCacheOwnerIdentity,
    )?;
    let rent_sponsor = payer.address().to_bytes();
    let nonce_le = ix.nonce.to_le_bytes();
    let bump = verify_pda(
        cache.address(),
        &[CACHE_SEED, &rent_sponsor, &nonce_le],
        &crate::ID,
    )?;
    if cache.owned_by(&crate::ID) {
        let current = load_cache(cache)?;
        if current.owner_identity != ix.owner_identity
            || current.tree_id != ix.tree_id.to_le_bytes()
            || current.expires_at != ix.expires_at.to_le_bytes()
            || current.rent_sponsor != rent_sponsor
            || current.bump != bump
        {
            return Err(ShieldedPoolError::CacheConfigMismatch.into());
        }
        return Ok(());
    }
    if !pinocchio_system::check_id(cache.owner()) || cache.data_len() != 0 {
        return Err(ShieldedPoolError::InvalidCache.into());
    }
    CreatePdaAccount {
        fee_payer: payer,
        new_account: cache,
        space: CacheAccount::SIZE,
        owner: &crate::ID,
        signer_seeds: [CACHE_SEED, &rent_sponsor, &nonce_le],
        bump,
    }
    .execute()?;
    CacheInitParams {
        bump,
        tree_id: ix.tree_id,
        expires_at: ix.expires_at,
        owner_identity: ix.owner_identity,
        rent_sponsor,
    }
    .init(cache)
}
