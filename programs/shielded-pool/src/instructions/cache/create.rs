use super::{init::CacheInitParams, loader::load_cache};
use crate::instructions::{
    ring_config::loader::load_active_ring_config,
    shared::{verify_pda, CreatePdaAccount},
};
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateCacheData,
    state::{
        cache::{CACHE_OWNER_REGISTRY, CACHE_OWNER_RING, CACHE_SEED},
        CacheAccount,
    },
};

pub fn process_create_cache(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        CreateCacheData::from_bytes(data).map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("rent_payer")?;
    let owner = iter.next_signer("owner")?;
    let cache = iter.next_mut("cache")?;
    let system = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system.address()) {
        return Err(ShieldedPoolError::InvalidSystemProgram.into());
    }
    let owner = match ix.owner_kind {
        CACHE_OWNER_REGISTRY => owner.address().to_bytes(),
        CACHE_OWNER_RING => load_active_ring_config(owner)?.program_id.to_bytes(),
        _ => return Err(ShieldedPoolError::CacheOwnerMismatch.into()),
    };
    let bump = verify_pda(
        cache.address(),
        &[CACHE_SEED, &owner, &ix.operation_id],
        &crate::ID,
    )?;
    if cache.owned_by(&crate::ID) {
        let current = load_cache(cache)?;
        if current.owner_kind != ix.owner_kind
            || current.owner != owner
            || current.operation_id != ix.operation_id
            || current.tree_id != ix.tree_id.to_le_bytes()
            || current.rent_sponsor != payer.address().to_bytes()
            || current.close_authority != ix.close_authority
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
        signer_seeds: [CACHE_SEED, &owner, &ix.operation_id],
        bump,
    }
    .execute()?;
    CacheInitParams {
        bump,
        tree_id: ix.tree_id,
        owner_kind: ix.owner_kind,
        owner,
        operation_id: ix.operation_id,
        rent_sponsor: payer.address().to_bytes(),
        close_authority: ix.close_authority,
    }
    .init(cache)
}
