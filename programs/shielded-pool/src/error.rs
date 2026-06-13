use pinocchio::error::ProgramError;
use thiserror::Error;

/// Program errors surfaced on-chain as `ProgramError::Custom(code)`.
///
/// The discriminants below are the on-chain error codes for this program
/// version. `error_codes_are_stable` pins the mapping so intentional ABI
/// changes are explicit.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum ShieldedPoolError {
    #[error("invalid instruction data")]
    InvalidInstructionData = 0,
    #[error("pool tree accounts are invalid")]
    InvalidTreeAccounts = 1,
    #[error("nullifier tree maintenance failed")]
    NullifierTreeUpdateFailed = 2,
    #[error("caller is not authorized")]
    UnauthorizedCaller = 3,
    #[error("state sub-tree append failed")]
    StateAppendFailed = 4,
    #[error("transaction has expired")]
    ExpiredTransaction = 5,
    #[error("transact instruction shape is invalid")]
    InvalidTransactShape = 6,
    #[error("transact proof encoding is invalid")]
    InvalidTransactProofEncoding = 7,
    #[error("transact proof verification failed")]
    TransactProofVerificationFailed = 8,
    #[error("transact settlement accounts are invalid")]
    InvalidSettlementAccounts = 9,
    #[error("transact public settlement failed")]
    PublicSettlementFailed = 10,
    #[error("SPL asset registry account is invalid")]
    InvalidSplAssetRegistry = 11,
    #[error("protocol config account is invalid")]
    InvalidProtocolConfig = 12,
    #[error("pool tree is paused")]
    TreePaused = 13,
    #[error("zone config account is invalid")]
    InvalidZoneConfig = 14,
    #[error("nullifier root index references a zeroed (stale) root-history slot")]
    StaleNullifierRoot = 15,
}

impl From<ShieldedPoolError> for ProgramError {
    fn from(error: ShieldedPoolError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::ShieldedPoolError::*;

    /// Pin every on-chain error code for this program version.
    #[test]
    fn error_codes_are_stable() {
        let table = [
            (InvalidInstructionData as u32, 0),
            (InvalidTreeAccounts as u32, 1),
            (NullifierTreeUpdateFailed as u32, 2),
            (UnauthorizedCaller as u32, 3),
            (StateAppendFailed as u32, 4),
            (ExpiredTransaction as u32, 5),
            (InvalidTransactShape as u32, 6),
            (InvalidTransactProofEncoding as u32, 7),
            (TransactProofVerificationFailed as u32, 8),
            (InvalidSettlementAccounts as u32, 9),
            (PublicSettlementFailed as u32, 10),
            (InvalidSplAssetRegistry as u32, 11),
            (InvalidProtocolConfig as u32, 12),
            (TreePaused as u32, 13),
            (InvalidZoneConfig as u32, 14),
            (StaleNullifierRoot as u32, 15),
        ];
        for (got, want) in table {
            assert_eq!(got, want, "error code drifted");
        }
    }
}
