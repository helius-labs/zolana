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
    pub const GRANT_READ_ACCESS: u8 = 4;
    pub const REVOKE_READ_ACCESS: u8 = 5;
    pub const SET_AUTHORITY: u8 = 6;
    pub const CREATE_POLICY: u8 = 7;
    pub const CREATE_ENTRY: u8 = 8;
    pub const UPDATE_ENTRY: u8 = 9;
    pub const SET_POLICY_SOURCE: u8 = 10;
    pub const SET_PAUSED: u8 = 11;
    pub const SET_POLICY_RULES: u8 = 12;
}

pub const CREATE_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const READ_ACCESS_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_AUTHORITY_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_PAUSED_COMPUTE_UNIT_LIMIT: u32 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateConfigIxData {
    /// Auditor P256 public key in SEC1 compressed form.
    pub auditor_pubkey: [u8; COMPRESSED_P256_KEY_LEN],
    /// Nonzero deploys a policy ring, zero an audit-only ring.
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

/// Wire format of tag 3, the ring's own proof followed by the SPP content this
/// ring forwards verbatim.
///
/// The root indices name the tree history entries a policy statement binds. A
/// ring without rules carries them unread, one encoding serves both tiers.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingTransactIxData {
    pub proof: CustomRingProof,
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
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

/// One source per list the rules reference.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PolicyTableIxData {
    #[wincode(with = "containers::Vec<SourceSpec, FixIntLen<u8>>")]
    pub sources: Vec<SourceSpec>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub rules: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub inline_assets: Vec<[u8; 32]>,
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
    pub state: u8,
    pub content_hash: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
}
