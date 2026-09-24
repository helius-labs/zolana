use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_hasher::{
    hash_chain::create_right_hash_chain_4_from_seed, sha256::Sha256BE, Hasher, HasherError,
};

use crate::{
    tree_slot::tree_id_field,
    verifying_keys::{CacheWrite, MAX_CACHE_WRITES},
    MAX_TRANSACT_INPUTS,
};

pub const CACHE_SEED: &[u8] = b"cache";
pub const CACHE_CAPACITY: usize = 36;

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
    let mut reads = [EMPTY_SLOT; MAX_TRANSACT_INPUTS];
    let selected = slots
        .iter()
        .enumerate()
        .filter(|(slot, _)| read_bitmap >> slot & 1 == 1)
        .map(|(_, hash)| hash);
    for (entry, hash) in reads.iter_mut().zip(selected) {
        *entry = *hash;
    }
    let list = reads
        .get(..input_count)
        .ok_or(HasherError::InvalidInputLength(
            MAX_TRANSACT_INPUTS,
            input_count,
        ))?;
    Ok([tree_id_field(tree_id), cached_utxo_hash_chain(list)?])
}

/// Number of groups the right fold visits after its seed, at the widest shape.
const ZERO_SUFFIX_GROUPS: usize = (MAX_TRANSACT_INPUTS - 1).div_ceil(3);

/// `Z(k)`, the right fold over an all-zero suffix of `1 + 3k` elements:
/// `Z(0) = 0` and `Z(k) = Poseidon(0, 0, 0, Z(k - 1))`.
///
/// The value depends on the suffix length alone and not on the vector that
/// ends with it, so one table serves every input count: a cached spend seeds
/// the fold from the entry its unselected tail reaches, and a spend that draws
/// on no cache seeds from the entry for its whole width and hashes nothing.
///
/// Pinned by `the_zero_suffix_table_is_the_fold_over_zeros`; regenerate with
/// the ignored `print_zero_suffix_chains`.
pub static ZERO_SUFFIX_CHAINS: [[u8; 32]; ZERO_SUFFIX_GROUPS + 1] = [
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0x05, 0x32, 0xfd, 0x43, 0x6e, 0x19, 0xc7, 0x0e, 0x51, 0x20, 0x96, 0x94, 0xd9, 0xc2, 0x15,
        0x25, 0x09, 0x37, 0x92, 0x1b, 0x8b, 0x79, 0x06, 0x04, 0x88, 0xc1, 0x20, 0x6d, 0xb7, 0x3e,
        0x99, 0x46,
    ],
    [
        0x22, 0x2c, 0xfa, 0x7d, 0x71, 0xf7, 0x74, 0xd4, 0x48, 0x7b, 0x28, 0x0c, 0x0c, 0xc0, 0x8e,
        0x3c, 0xd2, 0xb9, 0xa8, 0x6e, 0xf5, 0x5e, 0xad, 0x0c, 0x0b, 0x79, 0x5c, 0x3f, 0xf1, 0x8b,
        0x12, 0x18,
    ],
    [
        0x05, 0xff, 0xd3, 0x79, 0x1f, 0xc6, 0x58, 0x90, 0xb6, 0xcd, 0xd8, 0x2c, 0x6c, 0xa3, 0x6e,
        0x3b, 0x89, 0x7c, 0x19, 0x96, 0xca, 0xb0, 0x34, 0x01, 0x9f, 0xf0, 0x1a, 0x68, 0x3d, 0x46,
        0x20, 0x54,
    ],
    [
        0x0b, 0xa4, 0xc4, 0xef, 0x2b, 0x93, 0xcc, 0x95, 0xe6, 0x7e, 0x42, 0xde, 0xed, 0xfc, 0x2d,
        0x44, 0x12, 0x8c, 0xc7, 0x82, 0x4a, 0xb3, 0x72, 0x52, 0x4d, 0xa3, 0x5d, 0x90, 0x58, 0xab,
        0xb8, 0xdf,
    ],
    [
        0x2b, 0x9f, 0xb7, 0x31, 0xbe, 0x7d, 0xa2, 0x03, 0xd6, 0x74, 0x75, 0xea, 0xb6, 0x41, 0x45,
        0x99, 0x10, 0x39, 0x3a, 0x65, 0x88, 0xc0, 0x5a, 0x47, 0xff, 0x03, 0xd8, 0xd1, 0xfa, 0x22,
        0x89, 0xe1,
    ],
    [
        0x1d, 0x95, 0x3d, 0x02, 0xfd, 0xb1, 0x1e, 0x89, 0x40, 0xce, 0xb2, 0x60, 0x7b, 0xf2, 0xee,
        0x3b, 0x73, 0x2c, 0xf6, 0x7f, 0xaa, 0x2f, 0x47, 0x4f, 0x06, 0x40, 0x92, 0xd2, 0xef, 0x2e,
        0x9a, 0x75,
    ],
    [
        0x20, 0xef, 0x7e, 0xfc, 0xe9, 0xa1, 0xc5, 0x1a, 0x4b, 0xf2, 0x01, 0xe1, 0x78, 0x07, 0x95,
        0x09, 0x3e, 0xe3, 0x1f, 0x2a, 0x6c, 0x32, 0x7d, 0xa3, 0xd0, 0xcf, 0xc0, 0xe7, 0x2e, 0x15,
        0x95, 0xc3,
    ],
    [
        0x2d, 0x6f, 0xd5, 0x72, 0xbf, 0x9c, 0xe2, 0x8a, 0x14, 0xfc, 0x93, 0x32, 0xb1, 0x8a, 0x01,
        0x2d, 0x61, 0xfb, 0x2d, 0x04, 0xda, 0xc2, 0x2d, 0xe1, 0x54, 0x32, 0x4e, 0xd3, 0xaf, 0x41,
        0x53, 0xc3,
    ],
    [
        0x0f, 0xd2, 0x85, 0x7c, 0x4e, 0x79, 0xf2, 0x93, 0xf2, 0xb6, 0xe2, 0x80, 0xd4, 0x4b, 0x53,
        0x53, 0x3c, 0x0f, 0x23, 0x5c, 0x46, 0xfd, 0x76, 0x8d, 0x45, 0x0b, 0xff, 0x19, 0x6d, 0xb0,
        0xc4, 0x81,
    ],
    [
        0x1b, 0x73, 0x40, 0x6f, 0x05, 0x0e, 0xa1, 0xf2, 0x02, 0xcb, 0xa6, 0xef, 0x9c, 0x00, 0x23,
        0xf0, 0x19, 0xb2, 0xdf, 0x15, 0x19, 0x44, 0x57, 0xed, 0x6e, 0xa6, 0xff, 0xac, 0x3a, 0x69,
        0x38, 0x09,
    ],
    [
        0x0a, 0xc2, 0x4d, 0x49, 0xd1, 0xd4, 0x71, 0xaf, 0x65, 0x92, 0x90, 0x6a, 0xe0, 0x22, 0x64,
        0x72, 0x6e, 0xfb, 0xdc, 0x14, 0x03, 0x60, 0x54, 0xea, 0x65, 0x12, 0xb6, 0x52, 0xfe, 0x25,
        0x19, 0x13,
    ],
    [
        0x03, 0xa4, 0x63, 0xc6, 0xbc, 0xda, 0xe7, 0x25, 0x45, 0x7e, 0xd4, 0x28, 0x0e, 0x8a, 0x96,
        0xc6, 0x7d, 0xfe, 0xee, 0x08, 0x57, 0x56, 0x8d, 0xa8, 0x13, 0x76, 0x62, 0x35, 0xb5, 0xde,
        0x03, 0x1a,
    ],
];

const EMPTY_SLOT: [u8; 32] = [0u8; 32];

/// The right fold of `utxo_hashes`, seeded past its trailing zeros.
///
/// Every whole group of trailing zeros the fold would visit first folds to a
/// constant of the suffix length alone, so it is a table entry instead of a
/// Poseidon call. That is plain algebra over zeros and holds for any input, so
/// the result is always the full fold.
fn cached_utxo_hash_chain(utxo_hashes: &[[u8; 32]]) -> Result<[u8; 32], HasherError> {
    let Some((last, prefix)) = utxo_hashes.split_last() else {
        return Ok(EMPTY_SLOT);
    };
    if *last != EMPTY_SLOT {
        return create_right_hash_chain_4_from_seed(prefix, *last);
    }
    // `rchunks` walks the groups in the order the fold visits them, so the
    // leading run of zero groups is the part the table already holds.
    let skipped = prefix
        .rchunks(3)
        .take_while(|group| group.iter().all(|slot| *slot == EMPTY_SLOT))
        .count();
    let seed = ZERO_SUFFIX_CHAINS
        .get(skipped)
        .ok_or(HasherError::InvalidInputLength(ZERO_SUFFIX_GROUPS, skipped))?;
    // Removing a multiple of three from the right leaves the remaining group
    // boundaries where the unskipped fold put them.
    let remaining = prefix.len().saturating_sub(3 * skipped);
    let head = prefix
        .get(..remaining)
        .ok_or(HasherError::InvalidInputLength(prefix.len(), remaining))?;
    create_right_hash_chain_4_from_seed(head, *seed)
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
