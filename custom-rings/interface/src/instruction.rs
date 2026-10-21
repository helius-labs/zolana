use bytemuck::{Pod, Zeroable};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_ring_policy::{ListSet, ListWrite, OutflowLimit, Writer};

use crate::{
    error::CustomRingError,
    member_registry::{check_member, QueueEntry, APPLY_BATCH},
    ReaderKeyBytes, AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

/// Account slots of the record instructions the indexer reads.
pub mod accounts {
    /// The member of `WriteRecords` and `RegisterKey`, the authority of `AuthorityWriteRecords`.
    pub const RECORD_WRITE_SIGNER: usize = 0;
    pub const RECORD_WRITE_REGISTRY: usize = 2;
    pub const RECORD_WRITE_QUEUE: usize = 3;
    pub const APPLY_RECORDS_REGISTRY: usize = 0;
    pub const APPLY_RECORDS_QUEUE: usize = 1;
    pub const CREATE_MEMBER_REGISTRY_REGISTRY: usize = 3;
    pub const CREATE_MEMBER_REGISTRY_QUEUE: usize = 4;
    /// `CreatePolicy`, `SetPolicyRules` and `SetPolicySource`.
    pub const POLICY_WRITE_REGISTRY: usize = 2;
}

macro_rules! instruction_tags {
    ($($(#[$doc:meta])* $variant:ident = $tag:ident: $value:expr => $units:expr,)*) => {
        pub mod tag {
            $($(#[$doc])* pub const $tag: u8 = $value;)*
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum InstructionTag {
            $($variant = tag::$tag,)*
        }

        impl TryFrom<u8> for InstructionTag {
            type Error = CustomRingError;

            fn try_from(value: u8) -> Result<Self, CustomRingError> {
                match value {
                    $(tag::$tag => Ok(Self::$variant),)*
                    _ => Err(CustomRingError::InvalidInstructionData),
                }
            }
        }

        pub const fn compute_unit_limit(tag: InstructionTag) -> u32 {
            match tag {
                $(InstructionTag::$variant => $units,)*
            }
        }
    };
}

const ACCOUNT_UNITS: u32 = 50_000;
/// One policy hash plus a curator registry load.
const POLICY_UNITS: u32 = 150_000;
/// A ring proof, and for most the SPP CPI with its own proof.
const PROOF_UNITS: u32 = 1_400_000;

instruction_tags! {
    CreateConfig = CREATE_CONFIG: 1 => ACCOUNT_UNITS,
    InitSppRingConfig = INIT_SPP_RING_CONFIG: 2 => ACCOUNT_UNITS,
    Transact = TRANSACT: 3 => PROOF_UNITS,
    /// Always refused, deposits go through `AuditedDeposit`.
    Deposit = DEPOSIT: zolana_interface::instruction::tag::RING_DEPOSIT => 200_000,
    Merge = MERGE: zolana_interface::instruction::tag::RING_MERGE_TRANSACT => PROOF_UNITS,
    GrantReadAccess = GRANT_READ_ACCESS: 4 => ACCOUNT_UNITS,
    RevokeReadAccess = REVOKE_READ_ACCESS: 5 => ACCOUNT_UNITS,
    SetAuthority = SET_AUTHORITY: 6 => ACCOUNT_UNITS,
    CreatePolicy = CREATE_POLICY: 7 => POLICY_UNITS,
    // Tags 8 and 9 are retired, never reuse them.
    SetPolicySource = SET_POLICY_SOURCE: 10 => POLICY_UNITS,
    SetPaused = SET_PAUSED: 11 => ACCOUNT_UNITS,
    SetPolicyRules = SET_POLICY_RULES: 12 => POLICY_UNITS,
    /// Ring-local tags must not collide with the forwarded SPP deposit and merge tags.
    SetCoSigner = SET_CO_SIGNER: 27 => ACCOUNT_UNITS,
    ClearCoSigner = CLEAR_CO_SIGNER: 21 => ACCOUNT_UNITS,
    // Tags 22, 23 and 26 are retired, never reuse them.
    SetDelegate = SET_DELEGATE: 24 => ACCOUNT_UNITS,
    /// Tag 3 data over the SPP authority rail, signed by the delegate.
    DelegateTransact = DELEGATE_TRANSACT: 25 => PROOF_UNITS,
    CreateMemberRegistry = CREATE_MEMBER_REGISTRY: 28 => ACCOUNT_UNITS,
    RegisterKey = REGISTER_KEY: 29 => PROOF_UNITS,
    // Tag 30 is retired, never reuse it.
    AuditedDeposit = AUDITED_DEPOSIT: 31 => PROOF_UNITS,
    // Tags 32 to 38 are retired, never reuse them.
    WriteRecords = WRITE_RECORDS: 39 => ACCOUNT_UNITS,
    AuthorityWriteRecords = AUTHORITY_WRITE_RECORDS: 40 => PROOF_UNITS,
    ApplyRecords = APPLY_RECORDS: 41 => PROOF_UNITS,
    SetInsertFee = SET_INSERT_FEE: 42 => ACCOUNT_UNITS,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateConfigIxData {
    /// Auditor X25519 public key as `0x04 || canonical little-endian u`.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    /// Selects a policy ring over an audit-only ring.
    pub has_policy: bool,
    /// Selects an anonymous ring, fixed for the ring's life.
    pub anonymous: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReaderIxData {
    pub reader: ReaderKeyBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPausedIxData {
    pub paused: bool,
}

/// Public withdrawal total per mint that requires approval when exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawalThreshold {
    pub mint: [u8; 32],
    pub amount: u64,
}

/// Requires co-signing for the selected public operations.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetCoSignerIxData {
    pub signer: [u8; 32],
    /// [`CoSignScope`](crate::CoSignScope) bits.
    pub scope: u8,
    #[wincode(with = "containers::Vec<WithdrawalThreshold, FixIntLen<u8>>")]
    pub thresholds: Vec<WithdrawalThreshold>,
}

impl SetCoSignerIxData {
    /// The scope a stored co-signer takes, every threshold naming a distinct mint.
    pub fn check(&self) -> Result<crate::CoSignScope, CustomRingError> {
        let scope =
            crate::CoSignScope::new(self.scope).ok_or(CustomRingError::InvalidCoSignerScope)?;
        if self.signer == [0; 32] {
            return Err(CustomRingError::InvalidCoSigner);
        }
        let repeated = || {
            self.thresholds
                .iter()
                .enumerate()
                .any(|(index, threshold)| {
                    self.thresholds[..index]
                        .iter()
                        .any(|earlier| earlier.mint == threshold.mint)
                })
        };
        if self.thresholds.len() > crate::MAX_CO_SIGNER_THRESHOLDS || repeated() {
            return Err(CustomRingError::InvalidCoSignerThresholds);
        }
        Ok(scope)
    }
}

/// Emulated field arithmetic adds one BSB22 commitment, its point and proof of knowledge are mandatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
pub struct CustomRingProof {
    pub groth16: PlainGroth16Proof,
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

impl CustomRingProof {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

const _: () = assert!(CustomRingProof::SIZE == 192);

/// `tag || proof || registry_root_index`, then the SPP deposit instruction unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct AuditedDepositPrefix {
    pub tag: u8,
    pub proof: CustomRingProof,
    /// The registry history slot of the bound root, zero unless the ring escrows nullifier keys.
    pub registry_root_index: u8,
}

/// Compressed Groth16 points, `b` decompresses to SPP's raw 128 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
pub struct PlainGroth16Proof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

/// `source` 0 names the ring's own registry, `k` the `k`-th trailing curator registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SourceSpec {
    pub list_id: u8,
    pub source: u8,
}

/// Policy parameters must reproduce the configured policy hash.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PolicyTableIxData {
    #[wincode(with = "containers::Vec<SourceSpec, FixIntLen<u8>>")]
    pub sources: Vec<SourceSpec>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub rules: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub inline_assets: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<u64, FixIntLen<u8>>")]
    pub inline_limits: Vec<u64>,
    #[wincode(with = "containers::Vec<OutflowLimit, FixIntLen<u8>>")]
    pub limits: Vec<OutflowLimit>,
}

/// `source` 0 is the ring's own registry, 1 the single trailing curator member registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPolicySourceIxData {
    pub list_id: u8,
    pub source: u8,
}

/// Tag 39, a member's masked write of its own lists, the lists of one authority write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct WriteRecordsIxData {
    pub mask: [u8; 8],
    pub value: [u8; 8],
}

/// One authority write inside `AuthorityWriteRecords`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RecordWriteData {
    pub member: [u8; 32],
    pub lists: WriteRecordsIxData,
}

/// Tag 41, the proof that applies every pending write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ApplyRecordsIxData {
    pub proof: CustomRingProof,
    pub new_root: [u8; 32],
    pub new_next_index: [u8; 4],
}

/// Tag 40, `count u8 || count writes || ApplyRecordsIxData`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityWriteRecordsIxData<'a> {
    pub writes: &'a [RecordWriteData],
    pub apply: &'a ApplyRecordsIxData,
}

/// Tag 29, the proof that seals the member's nullifier secret to the auditor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RegisterKeyIxData {
    pub proof: CustomRingProof,
    pub nullifier_pk: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

/// Tag 42.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SetInsertFeeIxData {
    pub fee: [u8; 8],
}

macro_rules! fixed_ix_data {
    ($($ty:ident),*) => {$(
        impl $ty {
            pub const SIZE: usize = core::mem::size_of::<Self>();

            /// The data of exactly one instance.
            pub fn parse(data: &[u8]) -> Result<&Self, CustomRingError> {
                bytemuck::try_from_bytes(data).map_err(|_| CustomRingError::InvalidInstructionData)
            }
        }

        const _: () = assert!(core::mem::align_of::<$ty>() == 1);
    )*};
}

fixed_ix_data!(
    WriteRecordsIxData,
    ApplyRecordsIxData,
    RegisterKeyIxData,
    SetInsertFeeIxData
);

impl WriteRecordsIxData {
    pub const fn new(write: ListWrite) -> Self {
        Self {
            mask: write.mask().to_le_bytes(),
            value: write.value().to_le_bytes(),
        }
    }

    pub const fn mask(&self) -> u64 {
        u64::from_le_bytes(self.mask)
    }

    pub const fn value(&self) -> u64 {
        u64::from_le_bytes(self.value)
    }

    /// The queue entry of `writer` changing `member`'s lists, only the lists `writer` owns.
    pub fn entry(&self, member: [u8; 32], writer: Writer) -> Result<QueueEntry, CustomRingError> {
        check_member(&member)?;
        let (mask, value) = (self.mask(), self.value());
        if mask == 0 || value & !mask != 0 {
            return Err(CustomRingError::ValueOutsideMask);
        }
        let writable = match writer {
            Writer::Member => ListSet::MEMBER_WRITES,
            Writer::Authority => ListSet::AUTHORITY_WRITES,
        };
        if !ListSet::from_record_bits(mask).is_some_and(|lists| lists.is_subset(writable)) {
            return Err(CustomRingError::ListBitNotWritable);
        }
        Ok(QueueEntry {
            member,
            mask,
            value,
            escrow_key: [0; 32],
        })
    }
}

impl RecordWriteData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn entry(&self) -> Result<QueueEntry, CustomRingError> {
        self.lists.entry(self.member, Writer::Authority)
    }
}

impl ApplyRecordsIxData {
    pub const fn new_next_index(&self) -> u32 {
        u32::from_le_bytes(self.new_next_index)
    }
}

impl SetInsertFeeIxData {
    pub const fn fee(&self) -> u64 {
        u64::from_le_bytes(self.fee)
    }
}

impl<'a> AuthorityWriteRecordsIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let (count, rest) = data
            .split_first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let count = write_count(usize::from(*count))?;
        let (writes, apply) = rest
            .split_at_checked(usize::from(count) * RecordWriteData::SIZE)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        Ok(Self {
            writes: bytemuck::try_cast_slice(writes)
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
            apply: ApplyRecordsIxData::parse(apply)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        let count = write_count(self.writes.len())?;
        Ok([
            &[count][..],
            bytemuck::cast_slice(self.writes),
            bytemuck::bytes_of(self.apply),
        ]
        .concat())
    }
}

/// One to `APPLY_BATCH` writes, `AuthorityBatchTooLarge` past it.
fn write_count(count: usize) -> Result<u8, CustomRingError> {
    match count {
        0 => Err(CustomRingError::InvalidInstructionData),
        1..=APPLY_BATCH => Ok(count as u8),
        _ => Err(CustomRingError::AuthorityBatchTooLarge),
    }
}

const _: () = assert!(WriteRecordsIxData::SIZE == 16);
const _: () = assert!(core::mem::align_of::<RecordWriteData>() == 1);
const _: () = assert!(RecordWriteData::SIZE == 48);
const _: () = assert!(ApplyRecordsIxData::SIZE == 228);
const _: () = assert!(RegisterKeyIxData::SIZE == 288);
const _: () = assert!(APPLY_BATCH <= u8::MAX as usize);

#[cfg(test)]
mod tests {
    use zolana_hasher::primitives::right_align;
    use zolana_ring_policy::ListId;

    use super::*;

    fn lists(mask: u64, value: u64) -> WriteRecordsIxData {
        WriteRecordsIxData {
            mask: mask.to_le_bytes(),
            value: value.to_le_bytes(),
        }
    }

    #[test]
    fn a_member_writes_only_its_own_lists_within_the_mask() {
        let member = right_align(&[7]);
        let recovery = ListId::Recovery.record_bit();
        let allow = ListId::Allow.record_bit();
        let write = |mask, value| lists(mask, value).entry(member, Writer::Member);
        assert!(write(recovery, recovery).is_ok());
        assert_eq!(
            write(allow, allow),
            Err(CustomRingError::ListBitNotWritable)
        );
        assert_eq!(
            write(ListId::Escrow.record_bit(), 0),
            Err(CustomRingError::ListBitNotWritable)
        );
        assert_eq!(write(1 << 8, 0), Err(CustomRingError::ListBitNotWritable));
        assert_eq!(
            write(recovery, recovery | allow),
            Err(CustomRingError::ValueOutsideMask)
        );
        assert_eq!(write(0, 0), Err(CustomRingError::ValueOutsideMask));
        assert_eq!(
            lists(recovery, 0).entry([0; 32], Writer::Member),
            Err(CustomRingError::MemberOutOfRange)
        );
    }

    #[test]
    fn the_authority_writes_only_the_authority_lists() {
        let write = |mask| {
            RecordWriteData {
                member: right_align(&[9]),
                lists: lists(mask, 0),
            }
            .entry()
        };
        assert!(write(ListId::Block.record_bit()).is_ok());
        assert_eq!(
            write(ListId::RingViewing.record_bit()),
            Err(CustomRingError::ListBitNotWritable)
        );
        assert_eq!(
            write(ListId::Escrow.record_bit()),
            Err(CustomRingError::ListBitNotWritable)
        );
    }
}
