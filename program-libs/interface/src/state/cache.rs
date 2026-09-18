use bytemuck::{Pod, Zeroable};
use zolana_hasher::{
    hash_chain::create_right_hash_chain_4_from_seed, primitives::right_align, HasherError,
};

use crate::{tree_slot::tree_id_field, MAX_TRANSACT_INPUTS};

pub const CACHE_SEED: &[u8] = b"cache";
pub const CACHE_CAPACITY: usize = 36;

/// Cached UTXO commitments written by verified merges. The first spend freezes insertion; nullifiers
/// protect each entry across subsequent cache spends and the tree fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct CacheAccount {
    pub discriminator: u8,
    pub bump: u8,
    pub frozen: u8,
    pub tree_id: [u8; 2],
    pub expires_at: [u8; 8],
    pub owner_identity: [u8; 32], // TODO: user Address, rename to utxo owner
    pub rent_sponsor: [u8; 32],
    /// Zero marks an empty slot; a verified merge's Poseidon output collides
    /// with this sentinel only with negligible probability.
    pub commitments: [[u8; 32]; CACHE_CAPACITY], // TODO: rename to UTXO hashes
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

const _: () = assert!(CacheAccount::SIZE == 1229);
const _: () = assert!(core::mem::align_of::<CacheAccount>() == 1);

/// The three elements every owner-signed transfer appends to its public-input
/// hash preimage, mirroring `CachedInputs` in Go
/// `circuits/spp_transaction/shared/cache.go`; the program and the client share
/// this one implementation.
///
/// `commitments` runs over all `n_inputs` slots in input order with every
/// unselected slot zeroed, which is what the circuit hashes after masking each
/// commitment by its selection bit.
///
/// The chain folds right so that an unselected tail costs nothing: its value
/// depends on the tail's length alone, which is what
/// [`empty_cached_input_fields`] looks up.
pub fn cached_input_fields(
    input_bitmap: u64,
    tree_id: u16,
    commitments: &[[u8; 32]],
) -> Result<[[u8; 32]; 3], HasherError> {
    Ok([
        right_align(&input_bitmap.to_be_bytes()),
        tree_id_field(tree_id),
        cached_commitment_chain(commitments)?,
    ])
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

/// The cached-commitment chain, seeded past the unselected tail.
///
/// A selected slot's commitment is never zero -- the program rejects an empty
/// slot -- so a zero element means that slot is unselected, and every whole
/// group of trailing zeros the fold would visit first is a table entry instead
/// of a Poseidon call. The number of hashes therefore follows the selection,
/// which discloses nothing: the bitmap that determines it is a public input of
/// the same proof.
fn cached_commitment_chain(commitments: &[[u8; 32]]) -> Result<[u8; 32], HasherError> {
    let Some((last, prefix)) = commitments.split_last() else {
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

/// The selection published by a spend that uses no cache: no inputs selected,
/// no tree, and the chain over `input_count` empty slots. The circuit hashes
/// these unconditionally, so the preimage length never reveals whether a cache
/// was used.
///
/// A zero bitmap and tree id right-align to the zero field element, and the
/// chain over zeros is the table entry for the whole width, so nothing here
/// needs hashing.
pub fn empty_cached_input_fields(input_count: usize) -> Result<[[u8; 32]; 3], HasherError> {
    let groups = input_count.saturating_sub(1).div_ceil(3);
    let chain = ZERO_SUFFIX_CHAINS
        .get(groups)
        .ok_or(HasherError::InvalidInputLength(ZERO_SUFFIX_GROUPS, groups))?;
    Ok([EMPTY_SLOT, EMPTY_SLOT, *chain])
}
