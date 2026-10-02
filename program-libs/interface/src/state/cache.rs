use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_hasher::{
    sha256::Sha256BE,
    zero_suffix_hash_chain::{
        create_padded_right_hash_chain_4, ZERO_SUFFIX_CHAINS, ZERO_SUFFIX_CHAIN_MAX_WIDTH,
        ZERO_SUFFIX_GROUPS,
    },
    Hasher, HasherError,
};

use crate::{
    instruction::instruction_data::merge_transact::MAX_MERGE_INPUTS,
    tree_slot::tree_id_field,
    verifying_keys::{CacheWrite, MAX_CACHE_WRITES},
    MAX_OUTPUTS, MAX_TRANSACT_INPUTS,
};

pub const CACHE_SEED: &[u8] = b"cache";
pub const CACHE_CAPACITY: usize = 36;

const EMPTY_SLOT: [u8; 32] = [0u8; 32];

// Every right-folded public-input chain pads its width from the zero-suffix
// table, which must reach the widest one.
const _: () = assert!(MAX_TRANSACT_INPUTS <= ZERO_SUFFIX_CHAIN_MAX_WIDTH);
const _: () = assert!(MAX_MERGE_INPUTS <= ZERO_SUFFIX_CHAIN_MAX_WIDTH);
const _: () = assert!(MAX_OUTPUTS <= ZERO_SUFFIX_CHAIN_MAX_WIDTH);

/// Bind optional cache writes to the existing transaction external-data hash.
/// Read-only and uncached transactions retain their original preimage.
pub fn bind_cache_write(
    external_data_hash: [u8; 32],
    destination: Option<(&[u8; 32], &[CacheWrite; MAX_CACHE_WRITES])>,
) -> Result<[u8; 32], HasherError> {
    match destination {
        Some((address, write_slots)) => {
            let mut writes = [0u8; 2 * MAX_CACHE_WRITES];
            let bytes = write_slots
                .iter()
                .flat_map(|entry| [entry.output, entry.slot]);
            for (byte, value) in writes.iter_mut().zip(bytes) {
                *byte = value;
            }
            Sha256BE::hashv(&[b"cache_write", &external_data_hash, address, &writes])
        }
        None => Ok(external_data_hash),
    }
}

/// Verified UTXO hashes managed by the write authority, which alone decides what
/// the slots hold. Spending never trusts the cache: the proof authorizes every
/// cached input, and nullifiers protect each entry across cached spends,
/// overwrites and the tree fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct CacheAccount {
    pub discriminator: u8,
    pub bump: u8,
    pub tree_id: [u8; 2],
    pub expires_at: [u8; 8],
    pub rent_sponsor: Address,
    /// Must sign every instruction writing this cache, independently of its payer.
    pub write_authority: Address,
    /// Zero marks an empty slot; a verified merge or transact output collides
    /// with this sentinel only with negligible probability.
    pub utxo_hashes: [[u8; 32]; CACHE_CAPACITY],
}

impl CacheAccount {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == super::discriminator::CACHE
    }

    pub fn expiry_unix_ts(&self) -> i64 {
        i64::from_le_bytes(self.expires_at)
    }
}

const _: () = assert!(CacheAccount::SIZE == 1228);
const _: () = assert!(core::mem::align_of::<CacheAccount>() == 1);

pub fn cached_input_fields(
    read_bitmap: u64,
    tree_id: u16,
    slots: &[[u8; 32]; CACHE_CAPACITY],
    input_count: usize,
) -> Result<[[u8; 32]; 2], HasherError> {
    if read_bitmap == 0 {
        return empty_cached_input_fields(input_count);
    }
    let read_count = read_bitmap.count_ones() as usize;
    if read_bitmap >> CACHE_CAPACITY != 0 || read_count > input_count {
        return Err(HasherError::InvalidInputLength(input_count, read_count));
    }
    let selected = slots
        .iter()
        .enumerate()
        .filter(|(slot, _)| read_bitmap >> slot & 1 == 1)
        .map(|(_, hash)| hash);
    Ok([
        tree_id_field(tree_id),
        create_padded_right_hash_chain_4(selected, input_count)?,
    ])
}

/// The selection published by a spend that reads no cached input: no tree and
/// the chain over `input_count` empty slots. Every owner-signed circuit hashes a
/// selection unconditionally, so one verifying key serves spends with and
/// without a cache.
///
/// A zero tree id right-aligns to the zero field element, and the chain over
/// zeros is the table entry for the whole width, so nothing here needs hashing.
pub fn empty_cached_input_fields(input_count: usize) -> Result<[[u8; 32]; 2], HasherError> {
    let groups = input_count.saturating_sub(1).div_ceil(3);
    let chain = ZERO_SUFFIX_CHAINS
        .get(groups)
        .ok_or(HasherError::InvalidInputLength(ZERO_SUFFIX_GROUPS, groups))?;
    Ok([EMPTY_SLOT, *chain])
}
