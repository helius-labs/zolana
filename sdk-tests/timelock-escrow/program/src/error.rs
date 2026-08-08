use solana_program_error::ProgramError;
use thiserror::Error;
use zolana_hasher::HasherError;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum TimelockEscrowError {
    #[error("proof verification failed")]
    ProofVerificationFailed = 9000,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9001,
    #[error("shielded-pool program account is invalid")]
    InvalidShieldedPoolProgram = 9002,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 9003,
    #[error("hashing failed")]
    HashingFailed = 9004,
    #[error("escrow has not yet unlocked")]
    NotYetUnlocked = 9005,
    #[error("VK registry account does not match the instruction's spec")]
    InvalidVkRegistryAccount = 9006,
    #[error("VK registry index is out of range")]
    InvalidVkRegistryIndex = 9007,
    #[error("VK registry account is already finalized")]
    VkRegistryAlreadyInitialized = 9008,
    #[error("VK registry account is not finalized")]
    VkRegistryNotReady = 9009,
    #[error("VK registry init syscall rejected the account or sources")]
    VkRegistryInitFailed = 9010,
}

impl From<TimelockEscrowError> for ProgramError {
    fn from(error: TimelockEscrowError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

impl From<HasherError> for TimelockEscrowError {
    fn from(_: HasherError) -> Self {
        Self::HashingFailed
    }
}
