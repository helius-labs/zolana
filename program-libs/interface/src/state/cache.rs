use bytemuck::{Pod, Zeroable};

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
    pub owner_identity: [u8; 32],
    pub rent_sponsor: [u8; 32],
    /// Zero marks an empty slot; a verified merge's Poseidon output collides
    /// with this sentinel only with negligible probability.
    pub commitments: [[u8; 32]; CACHE_CAPACITY],
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
