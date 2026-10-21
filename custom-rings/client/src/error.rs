use custom_ring_interface::stream::StreamError;
use solana_signature::Signature;
use thiserror::Error;
use zolana_client::{BlockingInsideRuntime, ClientError};
use zolana_hasher::HasherError;
use zolana_keypair::KeypairError;
use zolana_ring_policy::MemberError;
use zolana_transaction::TransactionError;

use crate::OutputPayloadErrorKind;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("transaction carries no message tagged for the auditor")]
    MissingAuditorMessage,
    #[error("transaction carries more than one message tagged for the auditor")]
    DuplicateAuditorMessage,
    /// The program accepts the auditor message only as the last message.
    #[error("auditor message is at index {index} of {count} messages, expected the last")]
    AuditorMessageNotLast { index: usize, count: usize },
    #[error("auditor message of {0} bytes does not fit the disclosure layout")]
    AuditorMessageLength(usize),
    #[error("transaction publishes no tx_viewing_pk")]
    MissingTxViewingPk,
    #[error("transaction publishes no salt")]
    MissingSalt,
    #[error("transaction publishes no nullifier")]
    MissingNullifier,
    #[error("transaction names no ring program")]
    MissingRingProgram,
    #[error("recovered transaction viewing key does not match the published tx_viewing_pk")]
    TxViewingKeyMismatch,
    #[error("recovered transaction viewing secret is not the canonical clamped X25519 encoding")]
    NonCanonicalViewingKey,
    #[error("disclosure field lies at or above the field modulus")]
    DisclosureField,
    #[error("disclosure does not fit its layout")]
    DisclosureLayout,
    #[error("disclosure padding is not zero")]
    DisclosurePadding,
    #[error("{trees} input trees do not match {inputs} published inputs")]
    InputTreeCount { trees: usize, inputs: usize },
    #[error("spent UTXO {commitment:?} is in no output the auditor opened")]
    UnseenInput { commitment: [u8; 32] },
    #[error("the transfer names no ring Transact frame its audit layout is bound to")]
    MissingRingTransact,
    #[error("output slot {slot} does not open, {kind:?}")]
    UnopenedOutput {
        slot: u32,
        kind: OutputPayloadErrorKind,
    },
    #[error("ring transaction event index is unavailable")]
    MissingEventIndex,
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
    #[error(transparent)]
    Stream(#[from] StreamError),
}

impl From<BlockingInsideRuntime> for AuditError {
    fn from(error: BlockingInsideRuntime) -> Self {
        Self::Client(error.into())
    }
}
