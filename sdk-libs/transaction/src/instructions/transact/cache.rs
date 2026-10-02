use solana_address::Address;
use zolana_interface::{
    state::cache::{bind_cache_write, CACHE_CAPACITY},
    verifying_keys::{CacheAccess, CacheWrite, MAX_CACHE_WRITES},
};

use super::{ExternalData, SppProofOutputUtxo};
use crate::error::TransactionError;

pub fn cache_write_slots(
    outputs: &[SppProofOutputUtxo],
    cache: Option<Address>,
) -> Result<[CacheWrite; MAX_CACHE_WRITES], TransactionError> {
    let mut write_slots = CacheAccess::NO_WRITES;
    let mut used = 0;
    for (index, output_utxo) in outputs.iter().enumerate() {
        let Some(slot) = output_utxo.cache_slot else {
            continue;
        };
        if cache.is_none() {
            return Err(TransactionError::CachedOutputWithoutWriteCache { index });
        }
        if output_utxo.is_dummy() {
            return Err(TransactionError::CachedDummyOutput);
        }
        if usize::from(slot) >= CACHE_CAPACITY {
            return Err(TransactionError::CacheSlotOutOfRange { slot });
        }
        if write_slots
            .iter()
            .take(used)
            .any(|entry| entry.slot == slot)
        {
            return Err(TransactionError::DuplicateCacheWriteSlot { index, slot });
        }
        let entry = write_slots
            .get_mut(used)
            .ok_or(TransactionError::TooManyCacheWrites {
                index,
                max: MAX_CACHE_WRITES,
            })?;
        *entry = CacheWrite {
            output: u8::try_from(index).map_err(|_| TransactionError::TooManyOutputsForShape {
                got: outputs.len(),
                max: usize::from(u8::MAX),
            })?,
            slot,
        };
        used += 1;
    }
    if cache.is_some() && used == 0 {
        return Err(TransactionError::UnusedWriteCache);
    }
    Ok(write_slots)
}

pub fn cache_bound_external_data_hash(
    external_data: &ExternalData,
    write_slots: &[CacheWrite; MAX_CACHE_WRITES],
    write_cache: Option<Address>,
) -> Result<[u8; 32], TransactionError> {
    let write_cache = write_cache.map(|cache| cache.to_bytes());
    Ok(bind_cache_write(
        external_data.hash()?,
        write_cache.as_ref().map(|cache| (cache, write_slots)),
    )?)
}
