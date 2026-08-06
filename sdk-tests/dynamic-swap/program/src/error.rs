use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum DynamicSwapError {
    #[error("escrow has expired")]
    Expired = 9000,
    #[error("escrow has not yet expired")]
    NotYetExpired = 9001,
    #[error("proof verification failed")]
    ProofVerificationFailed = 9002,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9003,
    #[error("trailing account is not the shielded-pool program")]
    InvalidShieldedPoolProgram = 9004,
    #[error("pool-authority account is missing from the transact account list")]
    MissingPoolAuthority = 9005,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 9006,
    #[error("hashing failed")]
    HashingFailed = 9007,
    #[error("account address does not match the derived PDA")]
    InvalidPda = 9008,
    #[error("signer is not the pair's authority")]
    Unauthorized = 9012,
    #[error("client-supplied creation time is too far from the on-chain clock")]
    CreatedAtOutOfTolerance = 9014,
    #[error("account does not belong to the pair passed in")]
    PairMismatch = 9015,
    #[error("price must be nonzero")]
    InvalidPrice = 9016,
    #[error("advertised order capacity is exhausted")]
    InsufficientCapacity = 9018,
    #[error("capacity update is inconsistent with public state")]
    InvalidCapacity = 9019,
}

impl From<DynamicSwapError> for ProgramError {
    fn from(error: DynamicSwapError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
