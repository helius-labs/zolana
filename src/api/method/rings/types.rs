use crate::common::typedefs::bs64_string::Base64String;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::limit::Limit;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::serializable_signature::SerializableSignature;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetRingsByTagsRequest {
    pub tags: Vec<Hash>,
    #[serde(default)]
    pub cursor: Option<Base64String>,
    #[serde(default)]
    pub limit: Option<Limit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct EncryptedUtxoMatch {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub output_slot: RingsOutputSlot,
    pub tx_viewing_pk: Option<Base64String>,
    /// Transaction-level AES salt shared by every output ciphertext.
    pub salt: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetEncryptedUtxosByTagsResponse {
    pub context: Context,
    /// Output-level matches; every returned output slot has a view tag from the request.
    pub matches: Vec<EncryptedUtxoMatch>,
    pub next_cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RingsOutputContext {
    pub hash: Hash,
    pub tree: SerializablePubkey,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RingsOutputSlot {
    pub view_tag: Hash,
    pub output_context: RingsOutputContext,
    pub payload: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub tx_viewing_pk: Option<Base64String>,
    /// Transaction-level AES salt shared by every output ciphertext.
    pub salt: Option<Base64String>,
    pub output_slots: Vec<RingsOutputSlot>,
    pub nullifiers: Vec<Hash>,
    /// True when at least one output in this transaction is proofless.
    pub proofless: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetShieldedTransactionsByTagsResponse {
    pub context: Context,
    /// Transaction-level matches; each returned transaction has at least one requested
    /// output view tag and includes all of its output slots.
    pub transactions: Vec<ShieldedTransaction>,
    pub next_cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetMerkleProofsRequest {
    pub tree_account: SerializablePubkey,
    pub leaves: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetMerkleProofsResponse {
    pub context: Context,
    pub proofs: Vec<MerkleProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MerkleContext {
    pub tree_type: u16,
    pub tree: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MerkleProof {
    pub leaf: Hash,
    pub merkle_context: MerkleContext,
    pub path: Vec<Hash>,
    pub leaf_index: u64,
    pub root: Hash,
    pub root_seq: u64,
    pub root_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetNonInclusionProofsRequest {
    pub tree_account: SerializablePubkey,
    pub leaves: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetNonInclusionProofsResponse {
    pub context: Context,
    pub proofs: Vec<NonInclusionProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct NonInclusionProof {
    pub leaf: Hash,
    pub merkle_context: MerkleContext,
    pub path: Vec<Hash>,
    pub low_element: Hash,
    pub low_element_index: u64,
    pub high_element: Hash,
    pub high_element_index: u64,
    pub root: Hash,
    pub root_seq: u64,
    pub root_index: u16,
}
