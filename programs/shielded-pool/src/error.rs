use pinocchio::error::ProgramError;
use thiserror::Error;

/// Program errors surfaced on-chain as `ProgramError::Custom(code)`.
///
/// The discriminants below ARE the stable on-chain error codes: clients and
/// tests match on `Custom(N)`, so the values must never change. New variants
/// MUST be appended with the next free discriminant — never inserted or
/// reordered. `error_codes_are_stable` pins the full mapping.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum ShieldedPoolError {
    #[error("invalid instruction data")]
    InvalidInstructionData = 0,
    #[error("pool tree accounts are invalid")]
    InvalidPoolTreeAccounts = 1,
    #[error("insert addresses requires at least one address")]
    EmptyAddressBatch = 2,
    #[error("append state leaves requires at least one leaf")]
    EmptyStateLeafBatch = 3,
    #[error("batch update root cannot be zero")]
    EmptyBatchUpdateRoot = 4,
    #[error("caller is not the registry's CPI authority")]
    UnauthorizedCaller = 5,
    #[error("state sub-tree append failed")]
    StateAppendFailed = 6,
    #[error("address queue insert failed")]
    AddressQueueInsertFailed = 7,
    #[error("batch address-tree proof verification failed")]
    BatchProofVerificationFailed = 8,
    #[error("transaction has expired")]
    ExpiredTransaction = 9,
    #[error("transact instruction shape is invalid")]
    InvalidTransactShape = 10,
    #[error("transact proof encoding is invalid")]
    InvalidTransactProofEncoding = 11,
    #[error("transact proof verification failed")]
    TransactProofVerificationFailed = 12,
    #[error("transact settlement accounts are invalid")]
    InvalidSettlementAccounts = 13,
    #[error("transact public settlement failed")]
    PublicSettlementFailed = 14,
    #[error("SPL asset registry account is invalid")]
    InvalidSplAssetRegistry = 15,
    #[error("protocol config account is invalid")]
    InvalidProtocolConfig = 16,
    #[error("pool tree is paused")]
    PoolTreePaused = 17,
    #[error("zone config account is invalid")]
    InvalidZoneConfig = 18,
    #[error("nullifier root index references a zeroed (stale) root-history slot")]
    StaleNullifierRoot = 19,
}

impl From<ShieldedPoolError> for ProgramError {
    fn from(error: ShieldedPoolError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::ShieldedPoolError::*;

    /// Pin every on-chain error code. A failure here means a variant was
    /// inserted or reordered, which would silently change the `Custom(N)`
    /// codes that clients and tests depend on.
    #[test]
    fn error_codes_are_stable() {
        let table = [
            (InvalidInstructionData as u32, 0),
            (InvalidPoolTreeAccounts as u32, 1),
            (EmptyAddressBatch as u32, 2),
            (EmptyStateLeafBatch as u32, 3),
            (EmptyBatchUpdateRoot as u32, 4),
            (UnauthorizedCaller as u32, 5),
            (StateAppendFailed as u32, 6),
            (AddressQueueInsertFailed as u32, 7),
            (BatchProofVerificationFailed as u32, 8),
            (ExpiredTransaction as u32, 9),
            (InvalidTransactShape as u32, 10),
            (InvalidTransactProofEncoding as u32, 11),
            (TransactProofVerificationFailed as u32, 12),
            (InvalidSettlementAccounts as u32, 13),
            (PublicSettlementFailed as u32, 14),
            (InvalidSplAssetRegistry as u32, 15),
            (InvalidProtocolConfig as u32, 16),
            (PoolTreePaused as u32, 17),
            (InvalidZoneConfig as u32, 18),
            (StaleNullifierRoot as u32, 19),
        ];
        for (got, want) in table {
            assert_eq!(got, want, "error code drifted");
        }
    }
}
