use pinocchio::error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ShieldedPoolError {
    #[error("invalid instruction data")]
    InvalidInstructionData,
    #[error("pool tree accounts are invalid")]
    InvalidPoolTreeAccounts,
    #[error("insert addresses requires at least one address")]
    EmptyAddressBatch,
    #[error("append state leaves requires at least one leaf")]
    EmptyStateLeafBatch,
    #[error("batch update root cannot be zero")]
    EmptyBatchUpdateRoot,
    #[error("pool tree mutation failed")]
    PoolTreeMutationFailed,
}

impl From<ShieldedPoolError> for ProgramError {
    fn from(error: ShieldedPoolError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
