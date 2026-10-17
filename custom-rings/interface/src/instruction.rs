use bytemuck::{Pod, Zeroable};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_interface::instruction::{instruction_data::transact::TreeContext, TransactIxData};
use zolana_ring_policy::{OutflowLimit, N_FOREIGN};

use crate::{ReaderKeyBytes, AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN};

/// Account slot indices the processors and the indexer agree on.
pub mod accounts {
    pub const REGISTER_KEY_MEMBER: usize = 0;
    pub const REGISTER_KEY_CONFIG: usize = 1;
    pub const REGISTER_KEY_ROOT: usize = 2;
    pub const CREATE_MEMBER_REGISTRY_ROOT_ROOT: usize = 3;
    pub const UPDATE_MEMBERS_CONFIG: usize = 0;
    pub const UPDATE_MEMBERS_ROOT: usize = 1;
}

macro_rules! instruction_tags {
    ($($(#[$doc:meta])* $variant:ident = $tag:ident: $value:expr => $units:expr,)*) => {
        pub mod tag {
            $($(#[$doc])* pub const $tag: u8 = $value;)*
        }

        /// The first byte of the instruction data.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum InstructionTag {
            $($variant = tag::$tag,)*
        }

        impl TryFrom<u8> for InstructionTag {
            type Error = ();

            fn try_from(value: u8) -> Result<Self, ()> {
                match value {
                    $(tag::$tag => Ok(Self::$variant),)*
                    _ => Err(()),
                }
            }
        }

        /// The compute budget one instruction of `tag` declares.
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
/// A ring proof, most also CPI into SPP and its own proof.
const PROOF_UNITS: u32 = 1_400_000;

instruction_tags! {
    CreateConfig = CREATE_CONFIG: 1 => ACCOUNT_UNITS,
    InitSppRingConfig = INIT_SPP_RING_CONFIG: 2 => ACCOUNT_UNITS,
    Transact = TRANSACT: 3 => PROOF_UNITS,
    /// Rejected when verified deposit disclosure is required.
    Deposit = DEPOSIT: zolana_interface::instruction::tag::RING_DEPOSIT => 200_000,
    Merge = MERGE: zolana_interface::instruction::tag::RING_MERGE_TRANSACT => PROOF_UNITS,
    GrantReadAccess = GRANT_READ_ACCESS: 4 => ACCOUNT_UNITS,
    RevokeReadAccess = REVOKE_READ_ACCESS: 5 => ACCOUNT_UNITS,
    SetAuthority = SET_AUTHORITY: 6 => ACCOUNT_UNITS,
    CreatePolicy = CREATE_POLICY: 7 => POLICY_UNITS,
    // Tags 8 and 9 are retired with the list entries, never reuse them.
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
    CreateMemberRegistryRoot = CREATE_MEMBER_REGISTRY_ROOT: 28 => ACCOUNT_UNITS,
    RegisterKey = REGISTER_KEY: 29 => PROOF_UNITS,
    SetDepositAudit = SET_DEPOSIT_AUDIT: 30 => ACCOUNT_UNITS,
    AuditedDeposit = AUDITED_DEPOSIT: 31 => PROOF_UNITS,
    UpdateMembers = UPDATE_MEMBERS: 32 => PROOF_UNITS,
}

/// Config-authority change to the direct-deposit disclosure requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetDepositAuditIxData {
    pub required: bool,
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

/// Compressed Groth16 points without the audited circuits' BSB22 commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
pub struct PlainGroth16Proof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

/// Tag 3, the ring's own proof followed by the SPP content it forwards verbatim.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingTransactIxData {
    pub proof: CustomRingProof,
    /// One per policy tree account in order, empty on an audit-only ring.
    #[wincode(with = "containers::Vec<TreeContext, FixIntLen<u8>>")]
    pub policy_trees: Vec<TreeContext>,
    /// The history slot of the bound root in the ring's member registry, zero on an audit-only ring.
    pub registry_root_index: u8,
    /// Per curator registry account, the history slot of its bound root, zero without a curator.
    pub foreign_root_indexes: [u8; N_FOREIGN],
    /// Proof-bound approval demand, false when no outflow limit applies.
    pub approval_required: bool,
    pub transact: TransactIxData,
}

/// `source` 0 is the ring's own registry, 1 the trailing curator member registry root.
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

/// One record rewrite, the program authorizes the change from the old fields to the new.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MemberUpdate {
    pub member: [u8; 32],
    pub old_lists: u64,
    pub old_escrow_key: [u8; 32],
    pub lists: u64,
    pub escrow_key: [u8; 32],
    /// The record's leaf, the append slot for an insert.
    pub index: u64,
}

impl MemberUpdate {
    /// An insert, the registry has no record of the member yet.
    pub const fn inserts(&self, next_index: u64) -> bool {
        self.index >= next_index
    }
}

/// Proven batch rewrite of member records, items strictly ascending by member.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateMembersIxData {
    pub proof: CustomRingProof,
    /// The history slot the proof's old root was read from, the current one or the batch is stale.
    pub old_root_index: u8,
    pub new_root: [u8; 32],
    #[wincode(with = "containers::Vec<MemberUpdate, FixIntLen<u8>>")]
    pub items: Vec<MemberUpdate>,
}

/// Proven enrollment of a member's auditor-encrypted nullifier key in its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RegisterKeyIxData {
    pub proof: CustomRingProof,
    /// The history slot the proof's old root was read from, the current one or the proof is stale.
    pub old_root_index: u8,
    pub new_root: [u8; 32],
    /// Keeps the lists and sets the escrow key, an insert when the member has no record.
    pub item: MemberUpdate,
    /// The member's nullifier public key, bound by the proof to the ciphertext.
    pub nullifier_pk: [u8; 32],
    /// Tagged X25519 ephemeral key the auditor rederives the shared secret from.
    pub eph_pk: [u8; TAGGED_X25519_KEY_LEN],
    /// AES-256-CTR ciphertext of the nullifier secret, sealed to the auditor.
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

/// `source` 0 is the ring's own registry, 1 the single trailing curator member registry root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPolicySourceIxData {
    pub list_id: u8,
    pub source: u8,
}
