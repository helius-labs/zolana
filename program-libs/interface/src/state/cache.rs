use bytemuck::{Pod, Zeroable};

pub const CACHE_SEED: &[u8] = b"cache";
pub const CACHE_CAPACITY: usize = 36;
pub const CACHE_OWNER_REGISTRY: u8 = 0;
pub const CACHE_OWNER_RING: u8 = 1;

/// Cached UTXO commitments written by verified merges. The first spend freezes insertion; nullifiers
/// protect each entry across subsequent cache spends and the tree fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct CacheAccount {
    pub discriminator: u8,
    pub bump: u8,
    pub frozen: u8,
    pub tree_id: [u8; 2],
    pub owner_kind: u8,
    pub owner: [u8; 32],
    pub operation_id: [u8; 32],
    pub rent_sponsor: [u8; 32],
    pub close_authority: [u8; 32],
    /// Zero marks an empty slot; a verified merge's Poseidon output collides
    /// with this sentinel only with negligible probability.
    pub commitments: [[u8; 32]; CACHE_CAPACITY],
}

impl CacheAccount {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == super::discriminator::CACHE
    }
}

const _: () = assert!(CacheAccount::SIZE == 1286);
const _: () = assert!(core::mem::align_of::<CacheAccount>() == 1);
