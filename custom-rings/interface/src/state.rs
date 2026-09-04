use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_hasher::{sha256::Sha256, Hasher, HasherError};
use zolana_ring_policy::{EncodedRuleTable, ListId, RuleTable, RuleTableError};

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
    /// Nonzero selects the folded policy proof, zero the audit-only proof.
    pub has_policy: u8,
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
const _: () = assert!(RingProgramConfig::SIZE == 68);
const _: () = assert!(core::mem::align_of::<RingProgramConfig>() == 1);
const _: () = assert!(ReadAccessRecord::SIZE == 36);
const _: () = assert!(core::mem::align_of::<ReadAccessRecord>() == 1);

/// Seed of the account pinning the policy hash and the source map.
pub const POLICY_CONFIG_PDA_SEED: &[u8] = b"policy";
/// First byte of an initialized policy config.
pub const POLICY_CONFIG: u8 = 3;
/// One slot per list the enum can name, all eight enter the hash.
pub const N_SOURCE_SLOTS: usize = zolana_ring_policy::MAX_SOURCES;

/// One list's source, slot `i` is empty (`list_id == 0`) or serves list
/// `i + 1`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SourceSlot {
    pub list_id: u8,
    /// The namespace PDA serving the list, the ring's own or a curator's.
    pub namespace: Address,
}

/// Every write of `rules` or `sources` repins `policy_hash`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PolicyConfig {
    pub discriminator: u8,
    pub policy_hash: [u8; 32],
    /// All entries live in one tree, presence and absence stay provable against its roots.
    pub entries_tree: Address,
    pub namespace_bump: u8,
    pub bump: u8,
    /// Non-empty exactly for the lists `rules` references.
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
    pub rules: EncodedRuleTable,
    /// Little endian, 1 at `create_policy`, one more at every table or source write.
    pub generation: [u8; 4],
    /// Little endian, the slot of the write `generation` counts.
    pub generation_slot: [u8; 8],
}

impl PolicyConfig {
    pub const SEED: &'static [u8] = POLICY_CONFIG_PDA_SEED;
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// The namespace owner serving `list_id`, `None` when the table does not
    /// reference it.
    pub fn source_for(&self, list_id: ListId) -> Option<Address> {
        let slot = self.sources[list_id.slot()];
        (slot.list_id != 0).then_some(slot.namespace)
    }

    pub const fn generation(&self) -> u32 {
        u32::from_le_bytes(self.generation)
    }

    pub const fn generation_slot(&self) -> u64 {
        u64::from_le_bytes(self.generation_slot)
    }

    pub fn rule_table(&self) -> Result<RuleTable, RuleTableError> {
        self.rules.decode()
    }
}

const _: () = assert!(core::mem::size_of::<SourceSlot>() == 33);
const _: () = assert!(PolicyConfig::SIZE == 1177);
const _: () = assert!(core::mem::align_of::<PolicyConfig>() == 1);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, rules) == 331);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, generation) == 1165);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, generation_slot) == 1169);
