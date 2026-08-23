use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_hasher::{sha256::Sha256, Hasher, HasherError};

use crate::{ReaderKeyBytes, COMPRESSED_P256_KEY_LEN};

pub const CONFIG_PDA_SEED: &[u8] = b"config";
pub const READER_RECORD_PDA_SEED: &[u8] = b"reader";
/// Discriminator of [`RingProgramConfig`]. Value 0 stays reserved for
/// uninitialized accounts.
pub const RING_PROGRAM_CONFIG: u8 = 1;
pub const READER_RECORD: u8 = 2;

/// The ring's singleton config: who may register the ring with SPP, and the
/// auditor key every `transact` must verifiably encrypt the transaction viewing
/// secret key to.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingProgramConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Auditor P256 public key in SEC1 compressed form (`0x02`/`0x03 || x`).
    pub auditor_pubkey: [u8; COMPRESSED_P256_KEY_LEN],
    pub bump: u8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ReaderRecord {
    pub discriminator: u8,
    pub reader: ReaderKeyBytes,
    pub bump: u8,
}

impl RingProgramConfig {
    pub const SEED: &'static [u8] = CONFIG_PDA_SEED;
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl ReaderRecord {
    pub const SEED: &'static [u8] = READER_RECORD_PDA_SEED;
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn seed_hash(reader: &ReaderKeyBytes) -> Result<[u8; 32], HasherError> {
        Sha256::hash(reader)
    }
}

// Every field is byte-typed (`Address` is a 32-byte, align-1 newtype), so the
// struct carries no padding: its `Pod` image is exactly its field bytes and
// `SIZE` is the on-chain account length.
const _: () = assert!(RingProgramConfig::SIZE == 67);
const _: () = assert!(core::mem::align_of::<RingProgramConfig>() == 1);
const _: () = assert!(ReaderRecord::SIZE == 36);
const _: () = assert!(core::mem::align_of::<ReaderRecord>() == 1);
