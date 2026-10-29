//! Authenticate a cache account and the commitments a spend intends to read.

use std::collections::HashSet;

use spr_instruction::instruction::CreateCache;
use spr_interface::{
    state::cache::{CacheAccount, CACHE_CAPACITY},
    PROGRAM_ID_PUBKEY,
};

use crate::{ClientError, Rpc};

/// Check the cache derived by `create`, its authorities, tree, expiry and every
/// expected slot. Callers must independently authenticate the private openings
/// of those commitments. This does not establish whether their nullifiers have
/// already been spent, nor protect against a later authorized cache overwrite.
pub fn verify_cache<R: Rpc + ?Sized>(
    rpc: &R,
    create: &CreateCache,
    expected: &[(u8, [u8; 32])],
    now: i64,
) -> Result<(), ClientError> {
    let invalid = |message: &str| ClientError::Rpc(message.to_owned());
    if expected.is_empty() {
        return Err(invalid("cached inputs are empty"));
    }
    if create.data.expires_at <= now {
        return Err(invalid("cache expired"));
    }
    let account = rpc
        .get_account(create.cache())?
        .ok_or_else(|| invalid("cache is not available yet or has been closed"))?;
    if account.owner != PROGRAM_ID_PUBKEY || account.data.len() != CacheAccount::SIZE {
        return Err(invalid("invalid cache account owner or size"));
    }
    let cache = bytemuck::try_pod_read_unaligned::<CacheAccount>(&account.data)
        .map_err(|_| invalid("invalid cache account"))?;
    if !cache.has_discriminator()
        || cache.rent_sponsor != create.payer
        || cache.write_authority != create.data.write_authority
        || u16::from_le_bytes(cache.tree_id) != create.data.tree_id
        || cache.expiry_unix_ts() != create.data.expires_at
    {
        return Err(invalid("cache account does not match expected metadata"));
    }
    let mut slots = HashSet::new();
    for &(slot, hash) in expected {
        if usize::from(slot) >= CACHE_CAPACITY || !slots.insert(slot) {
            return Err(invalid("cached inputs must use distinct valid slots"));
        }
        if hash == [0; 32] || cache.utxo_hashes[usize::from(slot)] != hash {
            return Err(invalid("cache slot does not hold the expected output"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
