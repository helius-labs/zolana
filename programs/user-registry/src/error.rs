use pinocchio::error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum UserRegistryError {
    #[error("invalid instruction data")]
    InvalidInstructionData,
    #[error("signer is not the record owner")]
    UnauthorizedSigner,
    #[error("user record account does not match the expected PDA")]
    InvalidRecordPda,
    #[error("record owner does not match the owner account")]
    OwnerMismatch,
    #[error("user record account is invalid")]
    InvalidRecordAccount,
    #[error("system program account mismatch")]
    InvalidSystemProgram,
}

impl UserRegistryError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidInstructionData => "InvalidInstructionData",
            Self::UnauthorizedSigner => "UnauthorizedSigner",
            Self::InvalidRecordPda => "InvalidRecordPda",
            Self::OwnerMismatch => "OwnerMismatch",
            Self::InvalidRecordAccount => "InvalidRecordAccount",
            Self::InvalidSystemProgram => "InvalidSystemProgram",
        }
    }
}

impl From<UserRegistryError> for ProgramError {
    fn from(error: UserRegistryError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

pub fn fail(error: UserRegistryError) -> ProgramError {
    solana_msg::sol_log(error.name());
    error.into()
}
