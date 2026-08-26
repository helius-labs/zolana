use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_hasher::{sha256::Sha256, Hasher, HasherError};

use crate::{ReaderKeyBytes, COMPRESSED_P256_KEY_LEN};

pub const CONFIG_PDA_SEED: &[u8] = b"config";
pub const READ_ACCESS_RECORD_PDA_SEED: &[u8] = b"reader";
/// Discriminator of [`RingProgramConfig`]. Value 0 stays reserved for
/// uninitialized accounts.
pub const RING_PROGRAM_CONFIG: u8 = 1;
pub const READ_ACCESS_RECORD: u8 = 2;

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
pub struct ReadAccessRecord {
    pub discriminator: u8,
    pub reader: ReaderKeyBytes,
    pub bump: u8,
}

impl RingProgramConfig {
    pub const SEED: &'static [u8] = CONFIG_PDA_SEED;
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl ReadAccessRecord {
    pub const SEED: &'static [u8] = READ_ACCESS_RECORD_PDA_SEED;
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
const _: () = assert!(ReadAccessRecord::SIZE == 36);
const _: () = assert!(core::mem::align_of::<ReadAccessRecord>() == 1);

pub const POLICY_CONFIG_PDA_SEED: &[u8] = b"policy";
pub const POLICY_CONFIG: u8 = 3;
pub const N_POLICY_SOURCE_SLOTS: usize = 8;

/// One record kind's source, slot `i` is empty (`kind == 0`) or serves kind
/// `i + 1`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PolicySourceSlot {
    pub kind: u8,
    /// The records PDA serving the kind, the ring's own or a curator's.
    pub records: Address,
}

/// Pinned at `create_policy`, a mutation that recomputes a different
/// `policy_hash` fails closed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PolicyConfig {
    pub discriminator: u8,
    pub policy_hash: [u8; 32],
    /// All records live in one tree, presence and absence stay provable against its roots.
    pub records_tree: Address,
    pub records_bump: u8,
    pub bump: u8,
    /// Non-empty exactly for the kinds the compiled table references.
    pub sources: [PolicySourceSlot; N_POLICY_SOURCE_SLOTS],
}

impl PolicyConfig {
    pub const SEED: &'static [u8] = POLICY_CONFIG_PDA_SEED;
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// The records owner serving `kind`, `None` when the table does not
    /// reference it.
    pub fn source_for(&self, kind: u8) -> Option<Address> {
        let slot = self.sources[kind as usize - 1];
        (slot.kind != 0).then_some(slot.records)
    }
}

const _: () = assert!(core::mem::size_of::<PolicySourceSlot>() == 33);
const _: () = assert!(PolicyConfig::SIZE == 331);
const _: () = assert!(core::mem::align_of::<PolicyConfig>() == 1);
