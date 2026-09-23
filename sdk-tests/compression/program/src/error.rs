use solana_program_error::ProgramError;
use thiserror::Error;
use zolana_hasher::HasherError;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum CompressionError {
    #[error("instruction data is invalid")]
    InvalidInstructionData = 12000,
    #[error("account list is invalid")]
    InvalidAccounts = 12001,
    #[error("authority account is invalid")]
    InvalidAuthority = 12002,
    #[error("account PDA does not match the authority derivation")]
    InvalidPda = 12003,
    #[error("tree account is not the default tree")]
    InvalidTree = 12004,
    #[error("hashing failed")]
    HashingFailed = 12008,
    #[error("serialization failed")]
    SerializationFailed = 12009,
    #[error("read proof verification failed")]
    ProofVerificationFailed = 12010,
    #[error("nullifier PDA does not match the state's nullifier")]
    InvalidNullifierPda = 12011,
    #[error("account state is spent: its nullifier PDA exists")]
    StateSpent = 12012,
    #[error("tree root index is not in the root history")]
    InvalidRootIndex = 12013,
    #[error("tree account is not a shielded-pool tree")]
    InvalidTreeAccount = 12014,
}

impl From<CompressionError> for ProgramError {
    fn from(error: CompressionError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

impl From<HasherError> for CompressionError {
    fn from(_: HasherError) -> Self {
        Self::HashingFailed
    }
}
