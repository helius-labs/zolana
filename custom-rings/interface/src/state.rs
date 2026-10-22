use core::ops::BitOr;

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_hasher::{sha256::Sha256, Hasher, HasherError};
use zolana_ring_policy::{
    registry_field, EncodedRuleTable, ListId, PolicySource, RuleTable, SourceMap,
};

use crate::{
    error::CustomRingError,
    member_registry::{
        queue_chain, QueueEntry, APPLY_DELAY_SLOTS, AUTHORITY_RESERVED_LEAVES, GRACE_SLOTS,
        MEMBER_QUEUE_LIMIT, MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT, QUEUE_CAPACITY,
    },
    statement::ApplyRecordsStatement,
    ApplyRecordsIxData, ReaderKeyBytes, TAGGED_X25519_KEY_LEN,
};

pub const MAX_CO_SIGNER_THRESHOLDS: usize = 8;
/// Roots a transfer proof may bind, applications in between leave it provable.
pub const ROOT_HISTORY: usize = 32;
/// One slot per list the enum can name, all eight enter the hash.
pub const N_SOURCE_SLOTS: usize = zolana_ring_policy::MAX_SOURCES;

/// Created only at its canonical PDA, an owned account with the discriminator needs no address check.
pub trait RingAccount: Pod + sealed::Sealed {
    const DISCRIMINATOR: u8;
    const SEED: &'static [u8];
    const SIZE: usize = core::mem::size_of::<Self>();
    /// Not an initialized account of the program.
    const INVALID: CustomRingError;
    /// Creation over an existing account.
    const EXISTS: CustomRingError;
    /// Not the canonical address.
    const ADDRESS: CustomRingError;

    fn bump(&self) -> u8;

    /// Field invariants the setters keep.
    fn valid(&self) -> bool {
        true
    }

    /// The initialized account in `data`, `None` for another length or discriminator.
    fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|account| data[0] == Self::DISCRIMINATOR && account.valid())
    }

    fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        let initialized = data.first() == Some(&Self::DISCRIMINATOR);
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|account| initialized && account.valid())
    }

    /// `program`'s initialized account for off-chain readers.
    fn decode(owner: &Address, program: &Address, data: &[u8]) -> Option<Self> {
        (owner == program)
            .then(|| Self::from_data(data).copied())
            .flatten()
    }
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! ring_accounts {
    ($(
        $ty:ident = $disc:ident: $disc_value:literal, $seed:ident: $seed_value:literal,
        $invalid:ident, $exists:ident, $address:ident $(, $valid:expr)?;
    )*) => {$(
        pub const $disc: u8 = $disc_value;
        pub const $seed: &[u8] = $seed_value;

        impl sealed::Sealed for $ty {}

        impl $ty {
            pub const SEED: &'static [u8] = $seed;
            pub const SIZE: usize = core::mem::size_of::<Self>();
        }

        impl RingAccount for $ty {
            const DISCRIMINATOR: u8 = $disc;
            const SEED: &'static [u8] = $seed;
            const INVALID: CustomRingError = CustomRingError::$invalid;
            const EXISTS: CustomRingError = CustomRingError::$exists;
            const ADDRESS: CustomRingError = CustomRingError::$address;

            fn bump(&self) -> u8 {
                self.bump
            }

            $(fn valid(&self) -> bool {
                ($valid)(self)
            })?
        }

        // Byte fields only, the `Pod` image is the account data with no padding.
        const _: () = assert!(core::mem::align_of::<$ty>() == 1);
    )*};
}

// Discriminator zero marks an uninitialized account.
// Discriminators 1 and 3 to 9 are retired, never reuse them.
ring_accounts! {
    ReadAccessRecord = READ_ACCESS_RECORD: 2, READ_ACCESS_RECORD_PDA_SEED: b"reader",
        InvalidReadAccessRecord, ReadAccessRecordAlreadyExists, InvalidReadAccessRecord;
    RingProgramConfig = RING_PROGRAM_CONFIG: 10, CONFIG_PDA_SEED: b"config",
        ConfigNotInitialized, ConfigAlreadyInitialized, InvalidConfigPda,
        |config: &RingProgramConfig| config.mode().is_ok()
            && config.has_policy <= 1
            && usize::from(config.threshold_count) <= MAX_CO_SIGNER_THRESHOLDS;
    MemberRegistry = MEMBER_REGISTRY: 11, MEMBER_REGISTRY_PDA_SEED: b"members",
        InvalidMemberRegistry, MemberRegistryAlreadyExists, InvalidMemberRegistry,
        |registry: &MemberRegistry| usize::from(registry.history_cursor) < ROOT_HISTORY
            && u64::from(registry.next_index()) <= MEMBER_REGISTRY_CAPACITY;
    RecordQueue = RECORD_QUEUE: 12, RECORD_QUEUE_PDA_SEED: b"queue",
        InvalidRecordQueue, MemberRegistryAlreadyExists, InvalidRecordQueue,
        |queue: &RecordQueue| queue.head() <= queue.tail()
            && queue.pending() <= QUEUE_CAPACITY as u64;
}

macro_rules! le_getters {
    ($($ty:ident { $($field:ident: $int:ty),* })*) => {$(
        impl $ty {
            $(pub const fn $field(&self) -> $int {
                <$int>::from_le_bytes(self.$field)
            })*
        }
    )*};
}

le_getters! {
    WithdrawalThresholdRow { amount: u64 }
    RingProgramConfig { insert_fee: u64, created_slot: u64 }
    MemberRegistry {
        next_index: u32, floor: u64, prior_floor: u64, floor_slot: u64, generation: u32,
        generation_slot: u64
    }
    RootEntry { applied: u64, slot: u64 }
    RecordQueue { head: u64, tail: u64, next_apply_slot: u64 }
    QueueCheckpoint { slot: u64 }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ReadAccessRecord {
    pub discriminator: u8,
    pub reader: ReaderKeyBytes,
    pub bump: u8,
}

impl ReadAccessRecord {
    pub fn seed_hash(reader: &ReaderKeyBytes) -> Result<[u8; 32], HasherError> {
        Sha256::hash(reader)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingProgramConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Auditor X25519 public key as `0x04 || canonical little-endian u`.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub bump: u8,
    /// One for a policy ring.
    pub has_policy: u8,
    /// [`RingMode`] byte.
    pub mode: u8,
    /// Lamports a record write by a signer other than the authority pays the authority.
    pub insert_fee: [u8; 8],
    /// Zero without a co-signer.
    pub co_signer: Address,
    /// [`CoSignScope`] bits, zero without a co-signer.
    pub co_sign_scope: u8,
    pub threshold_count: u8,
    pub thresholds: [WithdrawalThresholdRow; MAX_CO_SIGNER_THRESHOLDS],
    /// Zero without a delegate.
    pub delegate: Address,
    /// Little endian, the slot `CreateConfig` ran in, a restored wallet scans from its epoch.
    pub created_slot: [u8; 8],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum RingMode {
    Off = 0,
    /// Escrows every output nullifier key in the registry.
    Registry = 1,
    /// Hides the sender and discloses every opening to the auditor.
    Anonymous = 2,
}

impl TryFrom<u8> for RingMode {
    type Error = CustomRingError;

    fn try_from(byte: u8) -> Result<Self, CustomRingError> {
        match byte {
            0 => Ok(Self::Off),
            1 => Ok(Self::Registry),
            2 => Ok(Self::Anonymous),
            _ => Err(CustomRingError::InvalidRingMode),
        }
    }
}

impl RingProgramConfig {
    pub fn mode(&self) -> Result<RingMode, CustomRingError> {
        RingMode::try_from(self.mode)
    }

    pub const fn has_policy(&self) -> bool {
        self.has_policy == 1
    }

    pub fn co_signer(&self) -> Option<&Address> {
        (self.co_signer != Address::default()).then_some(&self.co_signer)
    }

    /// `None` without a co-signer, every set scope bit is a known class.
    pub const fn co_sign_scope(&self) -> Option<CoSignScope> {
        CoSignScope::new(self.co_sign_scope)
    }

    /// Empty for an overlong count, an unlisted mint always needs the co-signer.
    pub fn thresholds(&self) -> &[WithdrawalThresholdRow] {
        self.thresholds
            .get(..usize::from(self.threshold_count))
            .unwrap_or_default()
    }

    pub fn threshold(&self, mint: &Address) -> Option<u64> {
        self.thresholds()
            .iter()
            .find(|row| &row.mint == mint)
            .map(WithdrawalThresholdRow::amount)
    }

    pub fn delegate(&self) -> Option<&Address> {
        (self.delegate != Address::default()).then_some(&self.delegate)
    }

    /// `None` when the authority writes or the ring charges no fee.
    pub fn insert_fee_for(&self, writer: &Address) -> Option<u64> {
        let fee = self.insert_fee();
        (fee != 0 && *writer != self.authority).then_some(fee)
    }
}

/// Nonzero subset of the class bits.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CoSignScope(u8);

impl CoSignScope {
    pub const TRANSFERS: Self = Self(1);
    pub const DEPOSITS: Self = Self(2);
    pub const WITHDRAWALS: Self = Self(4);
    pub const ALL: Self = Self(Self::TRANSFERS.0 | Self::DEPOSITS.0 | Self::WITHDRAWALS.0);

    pub const fn new(bits: u8) -> Option<Self> {
        if bits == 0 || bits & !Self::ALL.0 != 0 {
            return None;
        }
        Some(Self(bits))
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl BitOr for CoSignScope {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Summed per transaction, exceeding it needs the co-signer.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct WithdrawalThresholdRow {
    pub mint: Address,
    /// Little endian.
    pub amount: [u8; 8],
}

/// `applied` is the queue head right after the application that pushed the root.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RootEntry {
    pub root: [u8; 32],
    pub applied: [u8; 8],
    pub slot: [u8; 8],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AppliedAt {
    pub applied: u64,
    pub slot: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct MemberRegistry {
    pub discriminator: u8,
    pub bump: u8,
    /// Slot of the newest root in `history`.
    pub history_cursor: u8,
    /// Little endian, the leaf the next insert takes.
    pub next_index: [u8; 4],
    /// Little endian, the applied position every own-ring root must reach.
    pub floor: [u8; 8],
    /// Little endian, the floor before the last raise.
    pub prior_floor: [u8; 8],
    /// Little endian, the slot of the last floor raise.
    pub floor_slot: [u8; 8],
    pub history: [RootEntry; ROOT_HISTORY],
    /// Zero without a policy.
    pub policy_hash: [u8; 32],
    /// Non-empty exactly for the lists `rules` references.
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
    pub rules: EncodedRuleTable,
    /// Little endian, one more at every table or source write.
    pub generation: [u8; 4],
    /// Little endian, the slot of the write `generation` counts.
    pub generation_slot: [u8; 8],
}

/// One list's source, slot `i` is empty (`list_id == 0`) or serves list `i + 1`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SourceSlot {
    pub list_id: u8,
    /// The curator's `MemberRegistry` account serving the list, zero for the ring's own.
    pub registry: Address,
}

impl SourceSlot {
    /// The field the policy hash and the circuit read for the slot.
    pub fn policy_source(&self) -> Result<PolicySource, HasherError> {
        let registry = if self.registry == Address::default() {
            [0u8; 32]
        } else {
            registry_field(self.registry.as_array())?
        };
        Ok(PolicySource {
            list_id: self.list_id,
            registry,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ListRegistry {
    Own,
    Curator(Address),
}

impl MemberRegistry {
    /// The fresh registry, its first root holds only the sentinel.
    pub fn new(bump: u8, slot: u64) -> Self {
        let mut registry: Self = Zeroable::zeroed();
        registry.discriminator = MEMBER_REGISTRY;
        registry.bump = bump;
        registry.next_index = 1u32.to_le_bytes();
        registry.history[0] = RootEntry {
            root: MEMBER_REGISTRY_EMPTY_ROOT,
            applied: [0; 8],
            slot: slot.to_le_bytes(),
        };
        registry
    }

    /// The root an own-ring statement binds, `applied` must reach the floor.
    pub fn own_root(&self, index: u8) -> Result<[u8; 32], CustomRingError> {
        let entry = self.entry(index)?;
        if entry.applied() < self.floor() {
            return Err(CustomRingError::RootBelowFloor);
        }
        Ok(entry.root)
    }

    /// A curator root at the floor, or within `GRACE_SLOTS` of the last raise at the prior floor.
    pub fn curator_root(&self, index: u8, now: u64) -> Result<[u8; 32], CustomRingError> {
        let entry = self.entry(index)?;
        let applied = entry.applied();
        let in_grace = now < self.floor_slot().saturating_add(GRACE_SLOTS);
        if applied >= self.floor() || (in_grace && applied >= self.prior_floor()) {
            return Ok(entry.root);
        }
        Err(CustomRingError::CuratorRootStale)
    }

    /// The root the next application starts from.
    pub fn current_root(&self) -> [u8; 32] {
        self.history[usize::from(self.history_cursor)].root
    }

    /// Records an application, the oldest root leaves the history.
    pub fn push_root(&mut self, root: [u8; 32], at: AppliedAt) {
        let cursor = (usize::from(self.history_cursor) + 1) % ROOT_HISTORY;
        self.history[cursor] = RootEntry {
            root,
            applied: at.applied.to_le_bytes(),
            slot: at.slot.to_le_bytes(),
        };
        self.history_cursor = cursor as u8;
    }

    /// Every authority write floors the own ring, curators keep the prior floor for `GRACE_SLOTS`.
    pub fn raise_floor(&mut self) {
        let newest = self.history[usize::from(self.history_cursor)];
        self.prior_floor = self.floor;
        self.floor = newest.applied;
        self.floor_slot = newest.slot;
    }

    /// `PolicyNotSet` before the first policy write.
    pub fn policy_hash(&self) -> Result<&[u8; 32], CustomRingError> {
        if self.policy_hash == [0; 32] {
            return Err(CustomRingError::PolicyNotSet);
        }
        Ok(&self.policy_hash)
    }

    /// Validates the table against the sources and repins its hash.
    pub fn set_policy(
        &mut self,
        sources: [SourceSlot; N_SOURCE_SLOTS],
        rules: EncodedRuleTable,
        slot: u64,
    ) -> Result<(), CustomRingError> {
        let generation = self
            .generation()
            .checked_add(1)
            .ok_or(CustomRingError::PolicyGenerationOverflow)?;
        let source_map = source_map(&sources)?;
        rules.validate(&source_map)?;
        self.policy_hash = rules.hash(&source_map)?;
        self.sources = sources;
        self.rules = rules;
        self.generation = generation.to_le_bytes();
        self.generation_slot = slot.to_le_bytes();
        Ok(())
    }

    /// The registry serving `list_id`, `None` when the table does not reference it.
    pub fn registry_for(&self, list_id: ListId) -> Option<ListRegistry> {
        let slot = self.sources[list_id.slot()];
        (slot.list_id != 0).then(|| match slot.registry {
            registry if registry == Address::default() => ListRegistry::Own,
            registry => ListRegistry::Curator(registry),
        })
    }

    /// The one curator registry the sources name, `None` when every list is the ring's own.
    pub fn curator(&self) -> Option<Address> {
        self.sources
            .iter()
            .map(|slot| slot.registry)
            .find(|registry| *registry != Address::default())
    }

    /// The map `policy_hash` was computed over.
    pub fn source_map(&self) -> Result<SourceMap, CustomRingError> {
        source_map(&self.sources)
    }

    pub fn rule_table(&self) -> Result<RuleTable, CustomRingError> {
        Ok(self.rules.validate(&self.source_map()?)?)
    }

    fn entry(&self, index: u8) -> Result<&RootEntry, CustomRingError> {
        self.history
            .get(usize::from(index))
            .filter(|entry| entry.root != [0; 32])
            .ok_or(CustomRingError::RootIndexEmpty)
    }
}

fn source_map(sources: &[SourceSlot; N_SOURCE_SLOTS]) -> Result<SourceMap, CustomRingError> {
    let mut slots = [PolicySource::default(); N_SOURCE_SLOTS];
    for (dst, slot) in slots.iter_mut().zip(sources) {
        *dst = slot.policy_source()?;
    }
    Ok(SourceMap::from_slots(slots)?)
}

/// `chain(p)` and the slot `p` was queued at.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct QueueCheckpoint {
    pub chain: [u8; 32],
    pub slot: [u8; 8],
}

/// Chain checkpoints of the pending record writes, the writes stay in instruction data.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RecordQueue {
    pub discriminator: u8,
    pub bump: u8,
    /// Little endian, the position of the oldest pending write.
    pub head: [u8; 8],
    /// Little endian, the position the next write takes.
    pub tail: [u8; 8],
    /// `chain(head - 1)`.
    pub chain_head: [u8; 32],
    /// Position `p` sits at `p mod QUEUE_CAPACITY`.
    pub checkpoints: [QueueCheckpoint; QUEUE_CAPACITY],
    /// Little endian, the first slot a permissionless application may land in.
    pub next_apply_slot: [u8; 8],
}

impl RecordQueue {
    pub fn new(bump: u8) -> Self {
        let mut queue: Self = Zeroable::zeroed();
        queue.discriminator = RECORD_QUEUE;
        queue.bump = bump;
        queue
    }

    pub const fn pending(&self) -> u64 {
        self.tail().saturating_sub(self.head())
    }

    /// `chain(tail - 1)`, the chain an application of every pending write ends at.
    pub fn chain_tail(&self) -> [u8; 32] {
        match self.tail().checked_sub(1) {
            Some(last) if self.pending() > 0 => self.checkpoint(last).chain,
            _ => self.chain_head,
        }
    }

    /// A member write or a key registration fits the member share of the queue and of the leaves.
    pub fn admit_member_write(&self, registry: &MemberRegistry) -> Result<(), CustomRingError> {
        if self.pending() >= MEMBER_QUEUE_LIMIT {
            return Err(CustomRingError::QueueFull);
        }
        if self.reserved(registry, 1) > MEMBER_REGISTRY_CAPACITY - AUTHORITY_RESERVED_LEAVES {
            return Err(CustomRingError::AuthorityLeafReserve);
        }
        Ok(())
    }

    /// The authority's writes fit the batch beside every pending write.
    pub fn admit_authority_writes(&self, count: u64) -> Result<(), CustomRingError> {
        if self.pending().saturating_add(count) > QUEUE_CAPACITY as u64 {
            return Err(CustomRingError::AuthorityBatchTooLarge);
        }
        Ok(())
    }

    /// Appends one admitted write at `tail`.
    pub fn push(&mut self, entry: &QueueEntry, slot: u64) -> Result<(), CustomRingError> {
        let chain = queue_chain(&self.chain_tail(), entry)?;
        let tail = self.tail();
        self.checkpoints[checkpoint_index(tail)] = QueueCheckpoint {
            chain,
            slot: slot.to_le_bytes(),
        };
        self.tail = (tail + 1).to_le_bytes();
        Ok(())
    }

    /// Anyone applies a full or aged queue, at most once per `APPLY_DELAY_SLOTS`.
    pub fn apply_due(&self, slot: u64) -> Result<(), CustomRingError> {
        let pending = self.pending();
        let aged = || {
            let queued = self.checkpoint(self.head()).slot();
            slot >= queued.saturating_add(APPLY_DELAY_SLOTS)
        };
        if pending == 0 || (pending < MEMBER_QUEUE_LIMIT && !aged()) {
            return Err(CustomRingError::ApplyNotDue);
        }
        if slot < self.next_apply_slot() {
            return Err(CustomRingError::ApplyTooSoon);
        }
        Ok(())
    }

    fn checkpoint(&self, position: u64) -> &QueueCheckpoint {
        &self.checkpoints[checkpoint_index(position)]
    }

    /// The leaves taken once every pending write and `count` more insert.
    fn reserved(&self, registry: &MemberRegistry, count: u64) -> u64 {
        u64::from(registry.next_index())
            .saturating_add(self.pending())
            .saturating_add(count)
    }
}

const fn checkpoint_index(position: u64) -> usize {
    (position % QUEUE_CAPACITY as u64) as usize
}

pub struct PendingApplication<'a> {
    pub registry: &'a mut MemberRegistry,
    pub queue: &'a mut RecordQueue,
}

impl PendingApplication<'_> {
    /// The statement the apply proof is verified against.
    pub fn statement(&self, data: &ApplyRecordsIxData) -> ApplyRecordsStatement {
        ApplyRecordsStatement {
            old_root: self.registry.current_root(),
            new_root: data.new_root,
            old_next_index: self.registry.next_index(),
            new_next_index: data.new_next_index(),
            chain_start: self.queue.chain_head,
            chain_end: self.queue.chain_tail(),
            count: self.queue.pending(),
        }
    }

    /// Settles a verified `ApplyRecords` at `slot`, the next one waits `APPLY_DELAY_SLOTS`.
    pub fn settle_permissionless(mut self, data: &ApplyRecordsIxData, slot: u64) {
        self.queue.next_apply_slot = slot.saturating_add(APPLY_DELAY_SLOTS).to_le_bytes();
        self.settle(data, slot);
    }

    /// Settles a verified `AuthorityWriteRecords` at `slot`, its writes floor the own root.
    pub fn settle_authority(mut self, data: &ApplyRecordsIxData, slot: u64) {
        self.settle(data, slot);
        self.registry.raise_floor();
    }

    fn settle(&mut self, data: &ApplyRecordsIxData, slot: u64) {
        let applied = self.queue.tail();
        self.queue.chain_head = self.queue.chain_tail();
        self.queue.head = applied.to_le_bytes();
        self.registry
            .push_root(data.new_root, AppliedAt { applied, slot });
        self.registry.next_index = data.new_next_index;
    }
}

const _: () = assert!(ReadAccessRecord::SIZE == 36);
const _: () = assert!(RingProgramConfig::SIZE == 471);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, insert_fee) == 69);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, co_signer) == 77);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, thresholds) == 111);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, delegate) == 431);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, created_slot) == 463);
const _: () = assert!(core::mem::size_of::<SourceSlot>() == 33);
const _: () = assert!(MemberRegistry::SIZE == 3094);
const _: () = assert!(core::mem::offset_of!(MemberRegistry, next_index) == 3);
const _: () = assert!(core::mem::offset_of!(MemberRegistry, history) == 31);
const _: () = assert!(core::mem::offset_of!(MemberRegistry, policy_hash) == 1567);
const _: () = assert!(core::mem::offset_of!(MemberRegistry, rules) == 1863);
const _: () = assert!(core::mem::offset_of!(MemberRegistry, generation_slot) == 3086);
const _: () = assert!(ROOT_HISTORY <= u8::MAX as usize);
const _: () = assert!(RecordQueue::SIZE == 698);
const _: () = assert!(core::mem::offset_of!(RecordQueue, next_apply_slot) == 690);
const _: () = assert!(core::mem::offset_of!(RecordQueue, checkpoints) == 50);
