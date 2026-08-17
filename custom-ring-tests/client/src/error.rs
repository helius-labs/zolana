use custom_ring_sdk::AuditEncryptionError;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("transaction carries no message tagged for the auditor")]
    MissingAuditorMessage,
    #[error("transaction carries more than one message tagged for the auditor")]
    DuplicateAuditorMessage,
    /// The ring program accepts the auditor message only as the last entry of
    /// `TransactIxData::messages`, so a match anywhere else is a transaction the
    /// program cannot have verified.
    #[error("auditor message is at index {index} of {count} messages, expected the last")]
    AuditorMessageNotLast { index: usize, count: usize },
    #[error("transaction publishes no tx_viewing_pk")]
    MissingTxViewingPk,
    #[error("transaction publishes no salt")]
    MissingSalt,
    /// The ring proof binds the ciphertext to `tx_viewing_pk`, so on a
    /// program-verified transaction this cannot happen; it means the message was
    /// tagged for this auditor but encrypted for someone else, or was tampered
    /// with after indexing.
    #[error("recovered transaction viewing key does not match the published tx_viewing_pk")]
    TxViewingKeyMismatch,
    #[error("recovered transaction viewing scalar is not a valid P-256 secret key: {0}")]
    RecoveredKeyInvalid(KeypairError),
    #[error("output slot count exceeds the u32 slot index the ciphertexts are bound to: {0}")]
    SlotIndexOverflow(usize),
    #[error("decrypted output references asset id {asset_id}, which the registry cannot resolve")]
    UnknownAsset {
        asset_id: u64,
        source: TransactionError,
    },
    #[error(transparent)]
    Encryption(#[from] AuditEncryptionError),
    #[error(transparent)]
    Indexer(#[from] ClientError),
}
