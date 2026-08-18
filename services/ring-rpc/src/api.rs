//! Wire types of the Ring RPC. Scalars use the indexer's encodings (base58
//! keys and signatures, base64 bytes, hex hashes).

use serde::{Deserialize, Serialize};
use zolana_indexer_api::{
    Base64String, Context, Hash, Limit, SerializablePubkey, SerializableSignature,
};

pub const HEALTH: &str = "health";
pub const CREATE_AUDITOR_KEY: &str = "createAuditorKey";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct HealthResponse {
    /// `local` serves one key, `derived` a key per ring.
    pub mode: String,
    /// The local key's tag; absent when keys are derived per ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auditor_view_tag: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CreateAuditorKeyRequest {
    pub ring_program_id: SerializablePubkey,
}

/// The public half of a ring's auditor key. Idempotent: the same ring gets
/// the same key back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CreateAuditorKeyResponse {
    pub ring_program_id: SerializablePubkey,
    /// SEC1 compressed, what `create_config` takes.
    pub auditor_pubkey: Base64String,
    pub auditor_view_tag: Hash,
    pub key_version: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetDecryptedTransactionsRequest {
    /// Required when the instance derives keys per ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    /// Opaque indexer cursor from a previous page.
    #[serde(default)]
    pub cursor: Option<Base64String>,
    #[serde(default)]
    pub limit: Option<Limit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetDecryptedTransactionsResponse {
    pub context: Context,
    pub value: DecryptedTransactionsPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecryptedTransactionsPage {
    pub items: Vec<DecryptedTransaction>,
    /// Transactions tagged for this auditor that did not audit: a message
    /// encrypted to another key, a malformed message, or an asset the service
    /// cannot resolve. Reported so a gap is visible instead of silent.
    pub skipped: Vec<SkippedTransaction>,
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecryptedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    /// Solana signers of the transaction. On the eddsa rail the spent inputs'
    /// owners sign, so this is the sender side; the fee payer is among them.
    pub signers: Vec<SerializablePubkey>,
    /// SEC1 compressed transaction viewing pubkey the recovered key matched.
    pub tx_viewing_pk: Base64String,
    pub outputs: Vec<DecryptedOutput>,
    /// Slot positions the recovered key did not open: dummies, other schemes,
    /// or ciphertexts under another transaction key.
    pub undecryptable_slots: Vec<u32>,
    pub nullifiers: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecryptedOutput {
    pub slot_index: u32,
    /// SEC1 compressed viewing pubkey of the output's recipient, the "to".
    /// The sender's change carries the sender's own viewing key.
    pub recipient_viewing_pk: Base64String,
    pub asset: SerializablePubkey,
    pub amount: u64,
    pub blinding: Base64String,
    pub ring_program_id: Option<SerializablePubkey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SkippedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub reason: String,
}
