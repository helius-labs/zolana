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
    #[error("recovered transaction viewing secret is not the canonical clamped X25519 encoding")]
    NonCanonicalViewingKey,
    #[error("transaction has {0} output slots, but the audit proof supports four")]
    OutputDisclosureCount(usize),
    #[error("proof-bound opening does not match output commitment at slot {0}")]
    OutputCommitmentMismatch(u32),
    #[error("ring transaction event index is unavailable")]
    MissingEventIndex,
    #[error("message view tag is not the auditor view tag")]
    ViewTagMismatch,
    #[error("auditor message data of {0} bytes does not fit the disclosure shape")]
    MessageLength(usize),
    #[error("output disclosure contains a value at or above the field modulus")]
    DisclosureField,
    #[error("disclosure shape does not match the transaction")]
    DisclosureShape,
    #[error("disclosure padding is not zero")]
    DisclosurePadding,
    #[error("disclosed output slot kind {0} is unknown")]
    DisclosureOutputKind(u8),
    #[error("disclosed output identity tag {0} is not the Solana owner tag")]
    DisclosureIdentityTag(u8),
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
    #[error("member registry root or paged record opening is invalid")]
    InvalidMemberRegistry,
    #[error("ring history exceeds the scan bound, spent notes cannot be excluded")]
    IncompleteScan,
    #[error("indexer page names neither a next cursor nor a scan frontier")]
    ScanFrontierMissing,
    #[error("a verified anonymous merge disclosure does not open its settled output")]
    MergeDisclosureMismatch,
    #[error("merge audit exceeded its key-search work budget")]
    MergeAuditWorkBudget,
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
    #[error("confirmed audited deposit data is undecodable {0}")]
    InvalidDepositData(String),
    #[error("ring transact settlement accounts do not match its interface transfers")]
    SettlementAccounts,
    #[error("trusted event index {0} is unavailable")]
    InvalidEventIndex(u16),
    #[error("confirmed SPP event cannot be reconstructed {0}")]
    InvalidConfirmedEvent(String),
    #[error("indexed event does not match the confirmed SPP instruction and event")]
    ConfirmedEventMismatch,
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
