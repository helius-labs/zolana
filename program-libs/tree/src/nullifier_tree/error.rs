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
