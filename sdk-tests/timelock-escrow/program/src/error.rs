use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum TimelockEscrowError {
    #[error("proof verification failed")]
    ProofVerificationFailed = 9000,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9001,
    #[error("trailing account is not the shielded-pool program")]
    InvalidShieldedPoolProgram = 9002,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 9003,
    #[error("hashing failed")]
    HashingFailed = 9004,
    #[error("escrow has not yet unlocked")]
    NotYetUnlocked = 9005,
}

impl From<TimelockEscrowError> for ProgramError {
    fn from(error: TimelockEscrowError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
