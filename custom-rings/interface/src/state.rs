use core::ops::BitOr;

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_hasher::{sha256::Sha256, Hasher, HasherError};
use zolana_ring_policy::{
    registry_field, EncodedRuleTable, ListId, PolicySource, RuleTable, RuleTableError, SourceMap,
    SourceMapError,
};

use crate::{error::CustomRingError, ReaderKeyBytes, TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG};

pub const MAX_CO_SIGNER_THRESHOLDS: usize = 8;
/// Roots a transfer proof may bind, registrations in between leave it provable.
pub const MEMBER_REGISTRY_ROOT_HISTORY: usize = 32;
/// One slot per list the enum can name, all eight enter the hash.
pub const N_SOURCE_SLOTS: usize = zolana_ring_policy::MAX_SOURCES;

/// An account of the ring program, created only at its canonical PDA, so an
/// owned account with the discriminator needs no address check.
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
ring_accounts! {
    RingProgramConfig = RING_PROGRAM_CONFIG: 1, CONFIG_PDA_SEED: b"config",
        ConfigNotInitialized, ConfigAlreadyInitialized, InvalidConfigPda;
    ReadAccessRecord = READ_ACCESS_RECORD: 2, READ_ACCESS_RECORD_PDA_SEED: b"reader",
        InvalidReadAccessRecord, ReadAccessRecordAlreadyExists, InvalidReadAccessRecord;
    PolicyConfig = POLICY_CONFIG: 3, POLICY_CONFIG_PDA_SEED: b"policy",
        PolicyConfigNotInitialized, PolicyConfigAlreadyInitialized, InvalidPolicyConfigPda;
    CoSigner = CO_SIGNER: 4, CO_SIGNER_PDA_SEED: b"cosigner",
        InvalidCoSigner, InvalidCoSigner, InvalidCoSigner,
        |signer: &CoSigner| usize::from(signer.threshold_count) <= MAX_CO_SIGNER_THRESHOLDS;
    // Discriminator 5 is retired, never reuse it.
    Delegate = DELEGATE: 6, DELEGATE_PDA_SEED: b"delegate",
        InvalidDelegate, DelegateAlreadySet, InvalidDelegate;
    // Discriminator 7 is retired, never reuse it.
    DepositAudit = DEPOSIT_AUDIT: 8, DEPOSIT_AUDIT_PDA_SEED: b"deposit_audit",
        InvalidDepositAudit, InvalidDepositAudit, InvalidDepositAudit,
        |audit: &DepositAudit| audit.required <= 1;
    MemberRegistryRoot = MEMBER_REGISTRY_ROOT: 9, MEMBER_REGISTRY_ROOT_PDA_SEED: b"members",
        InvalidMemberRegistryRoot, MemberRegistryRootAlreadyExists, InvalidMemberRegistryRoot;
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
    MemberRegistryRoot { next_index: u64 }
    PolicyConfig { address_tree_id: u16, generation: u32, generation_slot: u64 }
}

/// Optional ring setting requiring proven auditor disclosure on direct deposits.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct DepositAudit {
    pub discriminator: u8,
    pub required: u8,
    pub bump: u8,
}

/// Who may register the ring with SPP, and the auditor every `transact` encrypts to.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingProgramConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Auditor X25519 public key as `0x04 || canonical little-endian u`.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub bump: u8,
    /// Nonzero selects the folded policy proof, zero the audit-only proof.
    pub has_policy: u8,
    /// [`RingMode`] byte.
    pub mode: u8,
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

impl RingProgramConfig {
    /// `None` for an unknown byte, which every caller refuses.
    pub const fn mode(&self) -> Option<RingMode> {
        match self.mode {
            0 => Some(RingMode::Off),
            1 => Some(RingMode::Registry),
            2 => Some(RingMode::Anonymous),
            _ => None,
        }
    }

    /// Only an X25519 auditor key can receive a proven disclosure.
    pub const fn has_legacy_auditor_key(&self) -> bool {
        self.auditor_pubkey[0] != VIEWING_PUBKEY_TAG
    }
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

/// Configured second signer and the public operation classes requiring approval.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct CoSigner {
    pub discriminator: u8,
    pub signer: Address,
    pub scope: u8,
    pub threshold_count: u8,
    pub thresholds: [WithdrawalThresholdRow; MAX_CO_SIGNER_THRESHOLDS],
    pub bump: u8,
}

impl CoSigner {
    pub const fn scope(&self) -> CoSignScope {
        CoSignScope(self.scope)
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
}

/// Solana signer authorized to move ring notes, separate from the auditor viewing key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Delegate {
    pub discriminator: u8,
    pub delegate: Address,
    pub bump: u8,
}

/// The ring's member registry, one per ring, its history lets a transfer bind a recent root.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct MemberRegistryRoot {
    pub discriminator: u8,
    /// Little endian, the next free leaf index an insert appends at.
    pub next_index: [u8; 8],
    pub bump: u8,
    /// Slot of the current root in `history`.
    pub history_cursor: u8,
    /// Records change under a newer root, a proof bound to an older one reads the older records.
    pub history: [[u8; 32]; MEMBER_REGISTRY_ROOT_HISTORY],
}

impl MemberRegistryRoot {
    pub fn root(&self) -> Option<[u8; 32]> {
        self.root_at(self.history_cursor)
    }

    /// `None` past the history or for a slot no root was written to.
    pub fn root_at(&self, index: u8) -> Option<[u8; 32]> {
        self.history
            .get(usize::from(index))
            .filter(|root| **root != [0u8; 32])
            .copied()
    }
}

/// One list's source, slot `i` is empty (`list_id == 0`) or serves list `i + 1`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SourceSlot {
    pub list_id: u8,
    /// The curator's `MemberRegistryRoot` account serving the list, zero for the ring's own.
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

/// Every write of `rules` or `sources` repins `policy_hash`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PolicyConfig {
    pub discriminator: u8,
    pub policy_hash: [u8; 32],
    /// The address tree every policy transfer binds.
    pub address_tree: Address,
    /// Little endian, the id the statement carries for `address_tree`.
    pub address_tree_id: [u8; 2],
    pub namespace_bump: u8,
    pub bump: u8,
    /// The shielded owner no transfer slot may open to.
    pub namespace_owner_hash: [u8; 32],
    /// Non-empty exactly for the lists `rules` references.
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
    pub rules: EncodedRuleTable,
    /// Little endian, 1 at `create_policy`, one more at every table or source write.
    pub generation: [u8; 4],
    /// Little endian, the slot of the write `generation` counts.
    pub generation_slot: [u8; 8],
}

/// Where a policy list is read from.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ListRegistry {
    Own,
    Curator(Address),
}

impl PolicyConfig {
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
    pub fn source_map(&self) -> Result<SourceMap, SourceMapError> {
        let mut slots = [PolicySource::default(); N_SOURCE_SLOTS];
        for (dst, slot) in slots.iter_mut().zip(&self.sources) {
            *dst = slot
                .policy_source()
                .map_err(|_| SourceMapError::NotPositional)?;
        }
        SourceMap::from_slots(slots)
    }

    pub fn rule_table(&self) -> Result<RuleTable, RuleTableError> {
        self.rules.decode()
    }
}

const _: () = assert!(DepositAudit::SIZE == 3);
const _: () = assert!(RingProgramConfig::SIZE == 69);
const _: () = assert!(ReadAccessRecord::SIZE == 36);
const _: () = assert!(CoSigner::SIZE == 356);
const _: () = assert!(Delegate::SIZE == 34);
const _: () = assert!(MemberRegistryRoot::SIZE == 1035);
const _: () = assert!(core::mem::offset_of!(MemberRegistryRoot, next_index) == 1);
const _: () = assert!(core::mem::offset_of!(MemberRegistryRoot, history_cursor) == 10);
const _: () = assert!(core::mem::offset_of!(MemberRegistryRoot, history) == 11);
const _: () = assert!(MEMBER_REGISTRY_ROOT_HISTORY <= u8::MAX as usize);
const _: () = assert!(core::mem::size_of::<SourceSlot>() == 33);
const _: () = assert!(PolicyConfig::SIZE == 1596);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, address_tree) == 33);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, address_tree_id) == 65);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, rules) == 365);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, generation) == 1584);
const _: () = assert!(core::mem::offset_of!(PolicyConfig, generation_slot) == 1588);
