use thiserror::Error;
use zolana_account_checks::error::AccountError;
use zolana_hasher::HasherError;

use crate::{verify::VerifierError, zero_copy::ZeroCopyError};

#[derive(Debug, Error, PartialEq)]
pub enum MerkleTreeMetadataError {
    #[error("Invalid tree type.")]
    InvalidTreeType,
    #[error("Invalid Height.")]
    InvalidHeight,
    #[error("Root history must contain exactly one queue batch of ZKP update roots.")]
    InvalidRootHistoryCapacity,
}

impl From<MerkleTreeMetadataError> for u32 {
    fn from(e: MerkleTreeMetadataError) -> u32 {
        match e {
            MerkleTreeMetadataError::InvalidTreeType => 14007,
            MerkleTreeMetadataError::InvalidHeight => 14009,
            MerkleTreeMetadataError::InvalidRootHistoryCapacity => 14010,
        }
    }
}

impl From<MerkleTreeMetadataError> for solana_program_error::ProgramError {
    fn from(e: MerkleTreeMetadataError) -> Self {
        solana_program_error::ProgramError::Custom(e.into())
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum BatchedMerkleTreeError {
    #[error("Batch is not ready to be inserted")]
    BatchNotReady,
    #[error("Batch is already inserted")]
    BatchAlreadyInserted,
    #[error("Batch size not divisible by ZKP batch size.")]
    BatchSizeNotDivisibleByZkpBatchSize,
    #[error("Hasher error: {0}")]
    Hasher(#[from] HasherError),
    #[error("Zero copy error {0}")]
    ZeroCopy(#[from] ZeroCopyError),
    #[error("Merkle tree metadata error {0}")]
    MerkleTreeMetadata(#[from] MerkleTreeMetadataError),
    #[error("Program error {0}")]
    ProgramError(#[from] solana_program_error::ProgramError),
    #[error("Verifier error {0}")]
    VerifierErrorError(#[from] VerifierError),
    #[error("Invalid batch index")]
    InvalidBatchIndex,
    #[error("Invalid index")]
    InvalidIndex,
    #[error("Batched Merkle tree is full.")]
    TreeIsFull,
    #[error("Batch must be reclaimable prior to reusing it.")]
    BatchNotReclaimable,
    #[error("Account error {0}")]
    AccountError(#[from] AccountError),
    #[error("Cached tree update index is out of range.")]
    CachedTreeUpdateIndexOutOfRange,
    #[error("Hash chain for the requested zkp batch is not finalized.")]
    HashChainNotReady,
    #[error("Arithmetic overflow.")]
    ArithmeticOverflow,
    #[error("Batch state word holds an invalid value.")]
    InvalidBatchState,
    #[error("Value is not a canonical BN254 scalar field element.")]
    NonCanonicalFieldElement,
    #[error("Queue index does not match the current batch position.")]
    QueueIndexMismatch,
    #[error("Queue batch metadata is inconsistent.")]
    InvalidBatchConfiguration,
}

impl From<BatchedMerkleTreeError> for u32 {
    fn from(e: BatchedMerkleTreeError) -> u32 {
        match e {
            BatchedMerkleTreeError::BatchNotReady => 14301,
            BatchedMerkleTreeError::BatchAlreadyInserted => 14302,
            BatchedMerkleTreeError::BatchSizeNotDivisibleByZkpBatchSize => 14306,
            BatchedMerkleTreeError::InvalidBatchIndex => 14308,
            BatchedMerkleTreeError::InvalidIndex => 14309,
            BatchedMerkleTreeError::TreeIsFull => 14310,
            BatchedMerkleTreeError::BatchNotReclaimable => 14312,
            BatchedMerkleTreeError::CachedTreeUpdateIndexOutOfRange => 14313,
            BatchedMerkleTreeError::HashChainNotReady => 14314,
            BatchedMerkleTreeError::ArithmeticOverflow => 14315,
            BatchedMerkleTreeError::InvalidBatchState => 14316,
            BatchedMerkleTreeError::NonCanonicalFieldElement => 14317,
            BatchedMerkleTreeError::QueueIndexMismatch => 14318,
            BatchedMerkleTreeError::InvalidBatchConfiguration => 14319,
            BatchedMerkleTreeError::Hasher(e) => e.into(),
            BatchedMerkleTreeError::ZeroCopy(e) => e.into(),
            BatchedMerkleTreeError::MerkleTreeMetadata(e) => e.into(),
            BatchedMerkleTreeError::VerifierErrorError(e) => e.into(),
            #[allow(clippy::useless_conversion)]
            BatchedMerkleTreeError::ProgramError(e) => u32::try_from(u64::from(e)).unwrap(),
            BatchedMerkleTreeError::AccountError(e) => e.into(),
        }
    }
}

impl From<BatchedMerkleTreeError> for solana_program_error::ProgramError {
    fn from(e: BatchedMerkleTreeError) -> Self {
        solana_program_error::ProgramError::Custom(e.into())
    }
}
