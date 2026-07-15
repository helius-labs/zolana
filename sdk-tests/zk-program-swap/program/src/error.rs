use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum SwapError {
    #[error("order has expired")]
    Expired = 8005,
    #[error("order has not yet expired")]
    NotYetExpired = 8006,
    #[error("proof verification failed")]
    ProofVerificationFailed = 8007,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 8011,
    #[error("trailing account is not the shielded-pool program")]
    InvalidShieldedPoolProgram = 8012,
    #[error("order-authority account is missing from the transact account list")]
    MissingOrderAuthority = 8013,
    #[error("make transact must carry exactly one marker message")]
    InvalidMarkerMessage = 8014,
    #[error("make marker message data must be empty")]
    MarkerDataNotEmpty = 8015,
    #[error("hashing failed")]
    HashingFailed = 8016,
}

impl From<SwapError> for ProgramError {
    fn from(error: SwapError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
