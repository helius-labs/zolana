use pinocchio::error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ShieldedPoolError {
    #[error("invalid instruction data")]
    InvalidInstructionData,
    #[error("invalid address tree configuration")]
    InvalidAddressTreeConfig,
    #[error("insert addresses requires at least one address")]
    EmptyAddressBatch,
    #[error("batch update root cannot be zero")]
    EmptyBatchUpdateRoot,
    #[error("address tree accounts are invalid")]
    InvalidAddressTreeAccounts,
    #[error("address tree state mutation is not implemented for this scaffold")]
    AddressTreeMutationUnsupported,
    #[error("invalid state tree configuration")]
    InvalidStateTreeConfig,
    #[error("append state leaves requires at least one leaf")]
    EmptyStateLeafBatch,
    #[error("state tree accounts are invalid")]
    InvalidStateTreeAccounts,
    #[error("state tree mutation is not implemented for this scaffold")]
    StateTreeMutationUnsupported,
}

impl From<ShieldedPoolError> for ProgramError {
    fn from(error: ShieldedPoolError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
