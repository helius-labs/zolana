use solana_program_error::ProgramError;
use thiserror::Error;
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
    #[error("ZKP batch index is out of range.")]
    ZkpBatchIndexOutOfRange,
    #[error("Hash chain for the requested zkp batch is not finalized.")]
    HashChainNotReady,
    #[error("Hash chain region is full, cannot push any new elements.")]
    HashChainFull,
    #[error("Invalid height.")]
    InvalidHeight,
    #[error("Root history must contain exactly one queue batch of ZKP update roots.")]
    InvalidRootHistoryCapacity,
    #[error("Account data length does not match the tree layout size.")]
    InvalidAccountSize,
    #[error("DecompressG1Failed")]
    DecompressG1Failed,
    #[error("DecompressG2Failed")]
    DecompressG2Failed,
    #[error("CreateGroth16VerifierFailed")]
    CreateGroth16VerifierFailed,
    #[error("ProofVerificationFailed")]
    ProofVerificationFailed,
    #[error("InvalidBatchSize supported batch sizes are 10 and 250")]
    InvalidBatchSize,
    #[error("Hasher error: {0}")]
    Hasher(#[from] HasherError),
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
            NullifierTreeError::ZkpBatchIndexOutOfRange => 14012,
            NullifierTreeError::HashChainNotReady => 14013,
            NullifierTreeError::HashChainFull => 14014,
            // 14015 was InvalidTreeType, removed with the tree_type layout
            // word; do not reuse the code.
            NullifierTreeError::InvalidHeight => 14016,
            NullifierTreeError::InvalidRootHistoryCapacity => 14017,
            NullifierTreeError::InvalidAccountSize => 14018,
            NullifierTreeError::DecompressG1Failed => 14020,
            NullifierTreeError::DecompressG2Failed => 14021,
            NullifierTreeError::CreateGroth16VerifierFailed => 14023,
            NullifierTreeError::ProofVerificationFailed => 14024,
            NullifierTreeError::InvalidBatchSize => 14025,
            NullifierTreeError::Hasher(e) => e.into(),
        }
    }
}

impl From<NullifierTreeError> for ProgramError {
    fn from(e: NullifierTreeError) -> Self {
        ProgramError::Custom(e.into())
    }
}
