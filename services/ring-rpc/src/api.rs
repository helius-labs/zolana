//! Wire types of the Ring RPC. Scalars reuse the indexer's encodings so a client
//! that reads Photon reads this service the same way.

use serde::{Deserialize, Serialize};
pub use zolana_indexer_api::PAGE_LIMIT;
use zolana_indexer_api::{Base64String, Context, Hash, SerializablePubkey, SerializableSignature};

pub const HEALTH: &str = "health";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct HealthResponse {
    /// The tag every audited transaction carries, the auditor key's x-coordinate.
    pub auditor_view_tag: Hash,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetDecryptedTransactionsRequest {
    /// Opaque indexer cursor from a previous page.
    #[serde(default)]
    pub cursor: Option<Base64String>,
    /// Page size, `1..=PAGE_LIMIT`.
    #[serde(default)]
    pub limit: Option<u32>,
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
