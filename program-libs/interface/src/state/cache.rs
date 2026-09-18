use bytemuck::{Pod, Zeroable};
use zolana_hasher::{hash_chain::create_hash_chain_4, primitives::right_align, HasherError};

use crate::tree_slot::tree_id_field;

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

static EMPTY_COMMITMENT: [u8; 32] = [0u8; 32];

/// The three elements every owner-signed transfer appends to its public-input
/// hash preimage, mirroring `CachedInputs` in Go
/// `circuits/spp_transaction/shared/cache.go`; the program and the client share
/// this one implementation.
///
/// `commitments` runs over all `n_inputs` slots in input order with every
/// unselected slot zeroed, which is what the circuit hashes after masking each
/// commitment by its selection bit.
pub fn cached_input_fields<'a>(
    input_bitmap: u64,
    tree_id: u16,
    commitments: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<[[u8; 32]; 3], HasherError> {
    Ok([
        right_align(&input_bitmap.to_be_bytes()),
        tree_id_field(tree_id),
        create_hash_chain_4(commitments)?,
    ])
}

/// The selection published by a spend that uses no cache: no inputs selected,
/// no tree, and the chain over `input_count` empty slots. The circuit hashes
/// these unconditionally, so the preimage length never reveals whether a cache
/// was used.
pub fn empty_cached_input_fields(input_count: usize) -> Result<[[u8; 32]; 3], HasherError> {
    cached_input_fields(0, 0, core::iter::repeat_n(&EMPTY_COMMITMENT, input_count))
}
