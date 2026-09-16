use bytemuck::{Pod, Zeroable};

// Keep PDA derivation stable across naming changes.
pub const CACHE_SEED: &[u8] = b"prove_by_index";
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
    pub commitments: [[u8; 32]; CACHE_CAPACITY],
}

impl CacheAccount {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn is_valid(&self) -> bool {
        self.discriminator == super::discriminator::CACHE
            && self.frozen <= 1
            && matches!(self.owner_kind, CACHE_OWNER_REGISTRY | CACHE_OWNER_RING)
    }
}

const _: () = assert!(CacheAccount::SIZE == 1286);
const _: () = assert!(core::mem::align_of::<CacheAccount>() == 1);
