//! Backend error type.

use thiserror::Error;
use zolana_client::ClientError;
use zolana_squads_sdk::{
    encrypted_utxo::EncryptedUtxoError, prover::SquadsProverError,
    viewing_key_account::ViewingKeyAccountError,
};

/// Errors surfaced by the Squads backend endpoints.
#[derive(Debug, Error)]
pub enum SquadsBackendError {
    #[error("indexer/rpc error: {0}")]
    Client(#[from] ClientError),

    #[error("viewing key account error: {0}")]
    ViewingKeyAccount(#[from] ViewingKeyAccountError),

    #[error("encrypted utxo error: {0}")]
    EncryptedUtxo(#[from] EncryptedUtxoError),

    #[error("prover error: {0}")]
    Prover(#[from] SquadsProverError),

    #[error("keypair error: {0}")]
    Keypair(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("recovered shared viewing key does not match the account's shared_viewing_key")]
    SharedKeyCommitmentMismatch,

    #[error("account {0} is not a viewing key account or failed to deserialize")]
    InvalidViewingKeyAccount(String),

    #[error("account {0} not found")]
    AccountNotFound(String),

    #[error("signature does not authorize reading {0}")]
    UnauthorizedRead(String),

    #[error("unsupported request: {0}")]
    Unsupported(String),

    #[error("owner kind {0} is not a known variant")]
    InvalidOwnerKind(u8),
}

/// Backend result alias.
pub type Result<T> = core::result::Result<T, SquadsBackendError>;
