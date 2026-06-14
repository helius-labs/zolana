use solana_address::Address;
use thiserror::Error;
use zolana_keypair::KeypairError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionError {
    #[error("unexpected discriminator: {0}")]
    BadDiscriminator(u8),

    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("serialization failed: {0}")]
    Serialize(String),

    #[error("deserialization failed: {0}")]
    Deserialize(String),

    #[error("unknown asset id: {0}")]
    UnknownAsset(u64),

    #[error("unknown mint: {0}")]
    UnknownMint(Address),

    #[error("reserved asset id: {0}")]
    ReservedAssetId(u64),

    #[error("duplicate asset id: {0}")]
    DuplicateAssetId(u64),

    #[error("duplicate mint: {0}")]
    DuplicateMint(Address),

    #[error("data attached to an output with zero amount")]
    DataWithoutOutput,

    #[error("too many outputs to derive blinding positions")]
    TooManyOutputs,

    #[error("duplicate data record")]
    DuplicateDataRecord,

    #[error("data records out of canonical order")]
    NonCanonicalDataOrder,

    #[error("zone data present without zone program id")]
    MissingZoneProgramId,

    #[error("poseidon hash failed: {0}")]
    Poseidon(String),

    #[error("keypair error: {0}")]
    Keypair(#[from] KeypairError),
}

impl From<wincode::WriteError> for TransactionError {
    fn from(e: wincode::WriteError) -> Self {
        TransactionError::Serialize(e.to_string())
    }
}

impl From<wincode::ReadError> for TransactionError {
    fn from(e: wincode::ReadError) -> Self {
        TransactionError::Deserialize(e.to_string())
    }
}
