use solana_program_error::ProgramError;
use thiserror::Error;
use zolana_account_checks::error::AccountError;
use zolana_hasher::HasherError;

#[derive(Debug, Error, PartialEq)]
pub enum NullifierTreeError {
    #[error("Batch is not ready to be inserted")]
    BatchNotReady,
    #[error("Batch is already inserted")]
    BatchAlreadyInserted,
    #[error("Batch size not divisible by ZKP batch size.")]
    BatchSizeNotDivisibleByZkpBatchSize,
    #[error("Invalid batch index")]
    InvalidBatchIndex,
    #[error("Invalid index")]
    InvalidIndex,
    #[error("Batch state word holds an invalid value.")]
    InvalidBatchState,
    #[error("Queue batch metadata is inconsistent.")]
    InvalidBatchConfiguration,
    #[error("Batched Merkle tree is full.")]
    TreeIsFull,
    #[error("Value is not a canonical BN254 scalar field element.")]
    NonCanonicalFieldElement,
    #[error("Arithmetic overflow.")]
    ArithmeticOverflow,
    #[error("Cached tree update index is out of range.")]
    CachedTreeUpdateIndexOutOfRange,
    #[error("Hash chain for the requested zkp batch is not finalized.")]
    HashChainNotReady,
    #[error("Hash chain region is full, cannot push any new elements.")]
    HashChainFull,
    #[error("Invalid tree type.")]
    InvalidTreeType,
    #[error("Invalid height.")]
    InvalidHeight,
    #[error("Root history must contain exactly one queue batch of ZKP update roots.")]
    InvalidRootHistoryCapacity,
    #[error("Account data length does not match the tree layout size.")]
    InvalidAccountSize,
    #[error("PublicInputsTryIntoFailed")]
    PublicInputsTryIntoFailed,
    #[error("DecompressG1Failed")]
    DecompressG1Failed,
    #[error("DecompressG2Failed")]
    DecompressG2Failed,
    #[error("InvalidPublicInputsLength")]
    InvalidPublicInputsLength,
    #[error("CreateGroth16VerifierFailed")]
    CreateGroth16VerifierFailed,
    #[error("ProofVerificationFailed")]
    ProofVerificationFailed,
    #[error("InvalidBatchSize supported batch sizes are 10 and 250")]
    InvalidBatchSize,
    #[error("Invalid proof size: expected 128 bytes, got {0}")]
    InvalidProofSize(usize),
    #[error("Hasher error: {0}")]
    Hasher(#[from] HasherError),
    #[error("Program error {0}")]
    ProgramError(#[from] ProgramError),
    #[error("Account error {0}")]
    AccountError(#[from] AccountError),
}

impl From<NullifierTreeError> for u32 {
    fn from(e: NullifierTreeError) -> u32 {
        match e {
            NullifierTreeError::BatchNotReady => 14001,
            NullifierTreeError::BatchAlreadyInserted => 14002,
            NullifierTreeError::BatchSizeNotDivisibleByZkpBatchSize => 14003,
            NullifierTreeError::InvalidBatchIndex => 14004,
            NullifierTreeError::InvalidIndex => 14005,
            NullifierTreeError::InvalidBatchState => 14006,
            NullifierTreeError::InvalidBatchConfiguration => 14007,
            NullifierTreeError::TreeIsFull => 14008,
            // 14009 was QueueIndexMismatch, removed with the redundant queue
            // counter cross-check; do not reuse the code.
            NullifierTreeError::NonCanonicalFieldElement => 14010,
            NullifierTreeError::ArithmeticOverflow => 14011,
            NullifierTreeError::CachedTreeUpdateIndexOutOfRange => 14012,
            NullifierTreeError::HashChainNotReady => 14013,
            NullifierTreeError::HashChainFull => 14014,
            NullifierTreeError::InvalidTreeType => 14015,
            NullifierTreeError::InvalidHeight => 14016,
            NullifierTreeError::InvalidRootHistoryCapacity => 14017,
            NullifierTreeError::InvalidAccountSize => 14018,
            NullifierTreeError::PublicInputsTryIntoFailed => 14019,
            NullifierTreeError::DecompressG1Failed => 14020,
            NullifierTreeError::DecompressG2Failed => 14021,
            NullifierTreeError::InvalidPublicInputsLength => 14022,
            NullifierTreeError::CreateGroth16VerifierFailed => 14023,
            NullifierTreeError::ProofVerificationFailed => 14024,
            NullifierTreeError::InvalidBatchSize => 14025,
            NullifierTreeError::InvalidProofSize(_) => 14026,
            NullifierTreeError::Hasher(e) => e.into(),
            NullifierTreeError::AccountError(e) => e.into(),
            #[allow(clippy::useless_conversion)]
            NullifierTreeError::ProgramError(e) => u32::try_from(u64::from(e)).unwrap(),
        }
    }
}

impl From<NullifierTreeError> for ProgramError {
    fn from(e: NullifierTreeError) -> Self {
        ProgramError::Custom(e.into())
    }
}
