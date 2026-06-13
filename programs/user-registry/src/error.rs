use pinocchio::error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum UserRegistryError {
    #[error("invalid instruction data")]
    InvalidInstructionData,
    #[error("P-256 compressed pubkey prefix must be 0x02 or 0x03")]
    InvalidP256Prefix,
    #[error("nullifier_pubkey must be a canonical BN254 field element (< Fr)")]
    NonCanonicalNullifierPubkey,
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
}

impl UserRegistryError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidInstructionData => "InvalidInstructionData",
            Self::InvalidP256Prefix => "InvalidP256Prefix",
            Self::NonCanonicalNullifierPubkey => "NonCanonicalNullifierPubkey",
            Self::SyncDelegateNotSet => "SyncDelegateNotSet",
            Self::UnauthorizedSigner => "UnauthorizedSigner",
            Self::InvalidSyncDelegate => "InvalidSyncDelegate",
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

/// Log the error name (so clients can match on it in transaction logs) and
/// convert to a `ProgramError`.
pub fn fail(error: UserRegistryError) -> ProgramError {
    crate::log::log(error.name());
    error.into()
}
