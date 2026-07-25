use pinocchio::error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum UserRegistryError {
    #[error("invalid instruction data")]
    InvalidInstructionData,
    #[error("no sync delegate is currently set")]
    SyncDelegateNotSet,
    #[error("signer is not the owner or active sync delegate")]
    UnauthorizedSigner,
    #[error("signer does not match the active sync delegate")]
    InvalidSyncDelegate,
    #[error("user record account does not match the expected PDA")]
    InvalidRecordPda,
    #[error("record owner does not match the owner account")]
    OwnerMismatch,
    #[error("user record account is invalid")]
    InvalidRecordAccount,
    #[error("system program account mismatch")]
    InvalidSystemProgram,
    #[error("p256 owner claim account is invalid")]
    InvalidP256ClaimAccount,
    #[error("p256 owner identity account does not match the expected PDA")]
    InvalidP256IdentityAccount,
    #[error("p256 owner identity is already claimed by another record")]
    P256IdentityAlreadyClaimed,
    #[error("p256 owner identity is a registered owner's identity")]
    P256IdentityIsRegisteredOwner,
}

impl UserRegistryError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidInstructionData => "InvalidInstructionData",
            Self::SyncDelegateNotSet => "SyncDelegateNotSet",
            Self::UnauthorizedSigner => "UnauthorizedSigner",
            Self::InvalidSyncDelegate => "InvalidSyncDelegate",
            Self::InvalidRecordPda => "InvalidRecordPda",
            Self::OwnerMismatch => "OwnerMismatch",
            Self::InvalidRecordAccount => "InvalidRecordAccount",
            Self::InvalidSystemProgram => "InvalidSystemProgram",
            Self::InvalidP256ClaimAccount => "InvalidP256ClaimAccount",
            Self::InvalidP256IdentityAccount => "InvalidP256IdentityAccount",
            Self::P256IdentityAlreadyClaimed => "P256IdentityAlreadyClaimed",
            Self::P256IdentityIsRegisteredOwner => "P256IdentityIsRegisteredOwner",
        }
    }
}

impl From<UserRegistryError> for ProgramError {
    fn from(error: UserRegistryError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

/// Log the error name (so clients can match on it in transaction logs) and
/// convert to a `ProgramError`.
pub fn fail(error: UserRegistryError) -> ProgramError {
    solana_msg::sol_log(error.name());
    error.into()
}
