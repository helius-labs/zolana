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

    #[error("program/zone data on this output cannot be processed yet")]
    UnsupportedOutputData,

    #[error("poseidon hash failed: {0}")]
    Poseidon(String),

    #[error("hash failed: {0}")]
    Hash(String),

    #[error("transaction has no output slots")]
    MissingOutput,

    #[error("missing encryption context for scheme")]
    MissingEncryptionContext,

    #[error("transaction has no inputs")]
    NoInputs,

    #[error("withdrawal already set")]
    WithdrawalAlreadySet,

    #[error("split cannot be combined with send, custom output, or withdrawal")]
    SplitWithOtherActions,

    #[error("multiple public spl assets in one transaction")]
    MultiplePublicSplAssets,

    #[error("insufficient balance: requested {requested}, available {available}")]
    InsufficientBalance { requested: u64, available: u64 },

    #[error("a split must produce at least one output")]
    SplitWithoutOutputs,

    #[error("no split was configured")]
    SplitNotConfigured,

    #[error("split asset mismatch: input has {input}, split requested {requested}")]
    SplitAssetMismatch { input: Address, requested: Address },

    #[error("split output amounts sum to {requested} but the selected input holds {available}")]
    SplitAmountMismatch { requested: u64, available: u64 },

    #[error("a split spends exactly one input; got {0}")]
    SplitInputCount(usize),

    #[error("unsupported proof shape: {n_in} input(s), {n_out} output(s)")]
    UnsupportedShape { n_in: usize, n_out: usize },

    #[error("too many inputs: got {got}, max {max}")]
    TooManyInputs { got: usize, max: usize },

    #[error("too many outputs: got {got}, max {max}")]
    TooManyOutputsForShape { got: usize, max: usize },

    #[error("merge input {index} has a different owner rail")]
    MergeInputRailMismatch { index: usize },

    #[error("merge input {index} has a different asset")]
    MergeInputAssetMismatch { index: usize },

    #[error("merge input {index} has a different zone program id")]
    MergeInputZoneMismatch { index: usize },

    #[error("selected balance overflow")]
    SelectedBalanceOverflow,

    #[error("merge input {index} carries program or zone data, which is not supported")]
    MergeInputHasData { index: usize },

    #[error("p256 error: {0}")]
    P256(String),

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
