use thiserror::Error;
use zolana_account_checks::error::AccountError;
use zolana_bloom_filter::BloomFilterError;
use zolana_hasher::HasherError;

use crate::{verify::VerifierError, zero_copy::ZeroCopyError};

#[derive(Debug, Error, PartialEq)]
pub enum MerkleTreeMetadataError {
    #[error("Invalid tree type.")]
    InvalidTreeType,
    #[error("Invalid Height.")]
    InvalidHeight,
}

impl From<MerkleTreeMetadataError> for u32 {
    fn from(e: MerkleTreeMetadataError) -> u32 {
        match e {
            MerkleTreeMetadataError::InvalidTreeType => 14007,
            MerkleTreeMetadataError::InvalidHeight => 14009,
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
    #[error("Bloom filter error {0}")]
    BloomFilter(#[from] BloomFilterError),
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
    #[error("Value already exists in bloom filter.")]
    NonInclusionCheckFailed,
    #[error("Bloom filter must be zeroed prior to reusing a batch.")]
    BloomFilterNotZeroed,
    #[error("Account error {0}")]
    AccountError(#[from] AccountError),
    #[error("Cached tree update index is out of range.")]
    CachedTreeUpdateIndexOutOfRange,
    #[error("Hash chain for the requested zkp batch is not finalized.")]
    HashChainNotReady,
    #[error("Arithmetic overflow.")]
    ArithmeticOverflow,
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
            BatchedMerkleTreeError::NonInclusionCheckFailed => 14311,
            BatchedMerkleTreeError::BloomFilterNotZeroed => 14312,
            BatchedMerkleTreeError::CachedTreeUpdateIndexOutOfRange => 14313,
            BatchedMerkleTreeError::HashChainNotReady => 14314,
            BatchedMerkleTreeError::ArithmeticOverflow => 14315,
            BatchedMerkleTreeError::Hasher(e) => e.into(),
            BatchedMerkleTreeError::ZeroCopy(e) => e.into(),
            BatchedMerkleTreeError::MerkleTreeMetadata(e) => e.into(),
            BatchedMerkleTreeError::BloomFilter(e) => e.into(),
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
