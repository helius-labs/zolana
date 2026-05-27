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
    #[error("caller is not the registry's CPI authority")]
    UnauthorizedCaller,
    #[error("state sub-tree append failed")]
    StateAppendFailed,
    #[error("address queue insert failed")]
    AddressQueueInsertFailed,
    #[error("batch address-tree proof verification failed")]
    BatchProofVerificationFailed,
    #[error("transaction has expired")]
    ExpiredTransaction,
    #[error("transact instruction shape is invalid")]
    InvalidTransactShape,
    #[error("transact proof encoding is invalid")]
    InvalidTransactProofEncoding,
    #[error("transact proof verification failed")]
    TransactProofVerificationFailed,
    #[error("transact settlement accounts are invalid")]
    InvalidSettlementAccounts,
    #[error("transact public settlement failed")]
    PublicSettlementFailed,
    #[error("SPL asset registry account is invalid")]
    InvalidSplAssetRegistry,
}

impl From<ShieldedPoolError> for ProgramError {
    fn from(error: ShieldedPoolError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
