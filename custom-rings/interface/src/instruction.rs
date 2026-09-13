use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_interface::instruction::TransactIxData;

use crate::{ReaderKeyBytes, COMPRESSED_P256_KEY_LEN};

pub mod tag {
    pub const CREATE_CONFIG: u8 = 1;
    pub const INIT_SPP_RING_CONFIG: u8 = 2;
    pub const TRANSACT: u8 = 3;
    /// Ring deposits carry no proof and are forwarded to SPP byte for byte, so
    /// the dispatcher matches SPP's own deposit tag instead of a program-local
    /// one: the client builds the SPP-shaped instruction and only re-targets the
    /// program id.
    pub const DEPOSIT: u8 = zolana_interface::instruction::tag::RING_DEPOSIT;
    /// SPP ring merge wire tag.
    pub const MERGE: u8 = zolana_interface::instruction::tag::RING_MERGE_TRANSACT;
    pub const GRANT_READ_ACCESS: u8 = 4;
    pub const REVOKE_READ_ACCESS: u8 = 5;
    pub const SET_AUTHORITY: u8 = 6;
    pub const CREATE_POLICY: u8 = 7;
    pub const CREATE_ENTRY: u8 = 8;
    pub const UPDATE_ENTRY: u8 = 9;
    pub const SET_POLICY_SOURCE: u8 = 10;
    pub const SET_PAUSED: u8 = 11;
    pub const SET_POLICY_RULES: u8 = 12;
    /// Ring-local tags must not collide with the forwarded SPP deposit and merge tags.
    pub const SET_CO_SIGNER: u8 = 28;
    pub const CLEAR_CO_SIGNER: u8 = 21;
    pub const SET_SPEND_WINDOW: u8 = 22;
    pub const CLEAR_SPEND_WINDOW: u8 = 23;
    pub const SET_DELEGATE: u8 = 24;
    /// Tag 3 data over the SPP authority rail, signed by the delegate.
    pub const DELEGATE_TRANSACT: u8 = 25;
    pub const REGISTER_SPEND: u8 = 26;
    pub const CREATE_HEAD_MAP_ROOT: u8 = 27;
}

pub const CREATE_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const READ_ACCESS_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_AUTHORITY_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_PAUSED_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_CO_SIGNER_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_DELEGATE_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const CREATE_HEAD_MAP_ROOT_COMPUTE_UNIT_LIMIT: u32 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateConfigIxData {
    /// Auditor P256 public key in SEC1 compressed form.
    pub auditor_pubkey: [u8; COMPRESSED_P256_KEY_LEN],
    /// One selects a policy ring, zero an audit-only ring.
    pub has_policy: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReaderIxData {
    pub reader: ReaderKeyBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPausedIxData {
    /// 1 pauses the ring on SPP, 0 resumes it, any other value is rejected.
    pub paused: u8,
}

/// Sets the aggregate withdrawal amount that requires approval for one mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawalThresholdIxData {
    pub mint: [u8; 32],
    pub amount: u64,
}

/// Configures the ring's additional signer and the operations requiring its approval.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetCoSignerIxData {
    pub signer: [u8; 32],
    pub scope: u8,
    #[wincode(with = "containers::Vec<WithdrawalThresholdIxData, FixIntLen<u8>>")]
    pub thresholds: Vec<WithdrawalThresholdIxData>,
}

/// Replaces one mint's public settlement caps and restarts its fixed-window counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetSpendWindowIxData {
    pub mint: [u8; 32],
    pub window_slots: u64,
    pub deposit_cap: u64,
    pub withdrawal_cap: u64,
}

/// Groth16 proof of the custom-ring circuit. The circuit's emulated P256
/// arithmetic adds one BSB22 commitment, so the commitment and its
/// proof-of-knowledge are not optional here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

/// Carries a registration proof without the audit circuit's BSB22 commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PlainGroth16Proof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

/// Declares the exact current root consumed and the successor root authorized by a transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct HeadMapTransition {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
}

/// Wire format of tag 3, the ring's own proof followed by the SPP content this
/// ring forwards verbatim.
///
/// The root indices name the tree history entries a policy statement binds. A
/// audit-only ring carries them unread, one encoding serves both tiers.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingTransactIxData {
    pub proof: CustomRingProof,
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    /// Proof-bound approval demand, zero when member amount controls do not apply.
    pub approval_required: u8,
    /// Required only on the windowed member rail.
    pub head_transition: Option<HeadMapTransition>,
    pub transact: TransactIxData,
}

/// Covers one v2 hash pin plus up to eight curator config loads.
pub const CREATE_POLICY_COMPUTE_UNIT_LIMIT: u32 = 150_000;
pub const SET_POLICY_RULES_COMPUTE_UNIT_LIMIT: u32 = 150_000;
/// Entry mutations CPI a full SPP transact with its proof verification.
pub const ENTRY_MUTATION_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// `source` 0 is the ring's own entries, `1 + i` the `i`-th trailing curator
/// policy config account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SourceSpec {
    pub list_id: u8,
    pub source: u8,
}

/// Sets one asset's outflow cap and private-amount approval threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct VelocityRowIxData {
    pub asset: [u8; 32],
    pub cap: u64,
    pub cosign_above: u64,
}

/// Commits list requirements and amount controls under one policy hash.
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
    pub window_slots: u64,
    #[wincode(with = "containers::Vec<VelocityRowIxData, FixIntLen<u8>>")]
    pub velocity: Vec<VelocityRowIxData>,
}

pub const REGISTER_SPEND_COMPUTE_UNIT_LIMIT: u32 = ENTRY_MUTATION_COMPUTE_UNIT_LIMIT;

/// Couples the payer's first compressed spend record with its head-map registration proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RegisterSpendIxData {
    /// The SPP output blinding, the proof fails unless it is the derived one.
    pub blinding: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
    pub head_old_root: [u8; 32],
    pub head_new_root: [u8; 32],
    pub head_next_index: u64,
    pub head_proof: PlainGroth16Proof,
}

/// One hash over the stored rows plus one curator verification.
pub const SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT: u32 = 150_000;

/// `source` 0 is the ring's own entries, 1 the single trailing curator policy
/// config account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPolicySourceIxData {
    pub list_id: u8,
    pub source: u8,
}

/// A member-written list requires the payer's Solana address to derive to `member`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateEntryIxData {
    pub list_id: u8,
    pub member: [u8; 32],
    pub state: u8,
    pub content_hash: [u8; 32],
    /// The SPP output blinding, the proof fails unless it is the derived one.
    pub blinding: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
}

/// The spent fields reconstruct the live version, a wrong reconstruction is a
/// leaf the SPP proof cannot include.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateEntryIxData {
    pub list_id: u8,
    pub member: [u8; 32],
    pub spent_state: u8,
    pub spent_content_hash: [u8; 32],
    pub spent_version: u64,
    pub spent_blinding: [u8; 32],
    pub state: u8,
    pub content_hash: [u8; 32],
    pub blinding: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
}
