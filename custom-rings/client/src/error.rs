use solana_signature::Signature;
use thiserror::Error;
use zolana_client::{BlockingInsideRuntime, ClientError};
use zolana_hasher::HasherError;
use zolana_keypair::KeypairError;
use zolana_ring_policy::MemberError;
use zolana_transaction::TransactionError;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("transaction carries no message tagged for the auditor")]
    MissingAuditorMessage,
    #[error("transaction carries more than one message tagged for the auditor")]
    DuplicateAuditorMessage,
    /// The program accepts the auditor message only as the last message.
    #[error("auditor message is at index {index} of {count} messages, expected the last")]
    AuditorMessageNotLast { index: usize, count: usize },
    #[error("transaction publishes no tx_viewing_pk")]
    MissingTxViewingPk,
    #[error("transaction publishes no salt")]
    MissingSalt,
    #[error("recovered transaction viewing key does not match the published tx_viewing_pk")]
    TxViewingKeyMismatch,
    #[error("recovered transaction viewing secret is zero or not below the P-256 order")]
    NonCanonicalViewingKey,
    #[error("transaction has {0} output slots, but the audit proof supports four")]
    OutputDisclosureCount(usize),
    #[error("proof-bound opening does not match output commitment at slot {0}")]
    OutputCommitmentMismatch(u32),
    #[error("recipient ciphertext disagrees with the proof-bound opening at slot {0}")]
    OutputPlaintextMismatch(u32),
    #[error("decrypted output references unknown asset id {asset_id}")]
    UnknownAsset {
        asset_id: u64,
        source: TransactionError,
    },
    #[error("ring transaction event index is unavailable")]
    MissingEventIndex,
    #[error("message view tag is not the auditor view tag")]
    ViewTagMismatch,
    #[error("auditor message data must be {expected} bytes, got {0}", expected = crate::AUDITOR_MESSAGE_LEN)]
    MessageLength(usize),
    #[error("output disclosure contains a value at or above the field modulus")]
    DisclosureField,
    #[error("output count must be between one and four, got {0}")]
    OutputCount(usize),
    #[error("nullifier ciphertext did not decrypt to a zero-padded secret")]
    NullifierPad,
    #[error("deposit count must be between one and eight, got {0}")]
    DepositCount(usize),
    #[error("deposit slot must be below eight, got {0}")]
    DepositSlot(usize),
    #[error("deposit opening does not match the owner commitment")]
    DepositOpeningMismatch,
    #[error("recovered nullifier key does not match the source member identity")]
    NullifierKeyMismatch,
    #[error("ring history exceeds the scan bound, spent notes cannot be excluded")]
    IncompleteScan,
    #[error("audited output slot index {0} is absent from its transaction")]
    MissingOutputSlot(u32),
    #[error("transaction {signature} is unavailable {message}")]
    Unavailable {
        signature: Signature,
        message: String,
    },
    #[error("inner instruction stack height {0} has no parent")]
    InvalidStackHeight(u32),
    #[error("ring transact instruction data is undecodable {0}")]
    InvalidTransactData(String),
    #[error("ring transact settlement accounts do not match its interface transfers")]
    SettlementAccounts,
    #[error("trusted event index {0} is unavailable")]
    InvalidEventIndex(u16),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
}

impl From<BlockingInsideRuntime> for AuditError {
    fn from(error: BlockingInsideRuntime) -> Self {
        Self::Client(error.into())
    }
}
