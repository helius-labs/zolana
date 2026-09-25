use light_program_profiler::profile;
use pinocchio::{account::Ref, address::address_eq, error::ProgramError, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::TransactIxDataRef, state::CacheAccount,
};

use super::{account::TransactCacheAccounts, verify::TransactProofInputs};
use crate::instructions::cache::{loader::load_cache, write::CacheWrite};

pub(crate) struct TransactCache<'a> {
    read: Option<CacheRead<'a>>,
    write: Option<CacheWrite<'a>>,
}

enum CacheRead<'a> {
    Own(Ref<'a, CacheAccount>),
    WriteCache,
}

impl<'a> TransactCache<'a> {
    pub fn load(
        accounts: Option<TransactCacheAccounts<'a>>,
        now: i64,
    ) -> Result<Option<Self>, ProgramError> {
        let Some(TransactCacheAccounts {
            read_cache,
            write_cache,
        }) = accounts
        else {
            return Ok(None);
        };
        let shared = read_cache
            .as_deref()
            .zip(write_cache.as_ref())
            .is_some_and(|(read, (write, _))| address_eq(read.address(), write.address()));
        let write = match write_cache {
            Some((cache, writer)) => Some(CacheWrite::load(cache, writer, now)?),
            None => None,
        };
        let read = match read_cache {
            Some(_) if shared => Some(CacheRead::WriteCache),
            Some(cache) => Some(CacheRead::Own(load_cache(cache)?)),
            None => None,
        };
        Ok(Some(Self { read, write }))
    }

    fn read_state(&self) -> Option<&CacheAccount> {
        match &self.read {
            Some(CacheRead::Own(state)) => Some(state),
            Some(CacheRead::WriteCache) => self.write.as_ref().map(CacheWrite::state),
            None => None,
        }
    }

    fn writable(&self) -> Option<&CacheWrite<'a>> {
        self.write.as_ref()
    }
}

pub(crate) fn validate_cache_selection(ix: &TransactIxDataRef<'_>) -> ProgramResult {
    if ix
        .circuit
        .cache_access()
        .is_some_and(|selection| !selection.valid(ix.inputs.len(), ix.outputs.len()))
    {
        return Err(ShieldedPoolError::InvalidCacheBitmap.into());
    }
    Ok(())
}

/// Bind cached inputs from the original account contents, before any writes.
#[profile]
pub(crate) fn bind_cached_inputs(
    cache: Option<&TransactCache<'_>>,
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> ProgramResult {
    let Some(state) = cache.and_then(TransactCache::read_state) else {
        return Ok(());
    };
    proof_inputs.assign_cached_inputs(ix, state)
}

/// Bind the write destination into the transaction's external data hash, so a
/// proof cannot be redirected to another cache or another set of slots.
pub(crate) fn bind_cache_write(
    cache: Option<&TransactCache<'_>>,
    ix: &TransactIxDataRef<'_>,
    external_data_hash: [u8; 32],
) -> Result<[u8; 32], ShieldedPoolError> {
    let write_slots = ix.circuit.cache_access().map(|access| access.write_slots);
    zolana_interface::state::cache::bind_cache_write(
        external_data_hash,
        cache
            .and_then(TransactCache::writable)
            .zip(write_slots.as_ref())
            .map(|(cache, write_slots)| (cache.address(), write_slots)),
    )
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)
}

/// Every output is appended to the output tree, so a written cache must belong
/// to it.
pub(crate) fn check_cache_output_tree(
    cache: Option<&TransactCache<'_>>,
    output_tree_id: u16,
) -> ProgramResult {
    match cache.and_then(TransactCache::writable) {
        Some(cache) => cache.check_output_tree(output_tree_id),
        None => Ok(()),
    }
}

#[profile]
pub(crate) fn write_cached_outputs(
    cache: Option<TransactCache<'_>>,
    ix: &TransactIxDataRef<'_>,
) -> ProgramResult {
    let (
        Some(TransactCache {
            write: Some(mut cache),
            ..
        }),
        Some(access),
    ) = (cache, ix.circuit.cache_access())
    else {
        return Ok(());
    };
    for entry in access.writes() {
        let output = ix
            .outputs
            .get(usize::from(entry.output))
            .ok_or(ShieldedPoolError::InvalidCacheBitmap)?;
        cache.write(entry.slot, output.utxo_hash)?;
    }
    Ok(())
}
