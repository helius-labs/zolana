#[cfg(feature = "tree")]
use rings_tree::TreeError;
use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceError {
    InvalidDiscriminator,
    Unauthorized,
    /// Account bytes are the wrong length to be cast to the expected state
    /// struct (e.g. a client reading a fetched account whose data does not
    /// match the struct size).
    InvalidAccountData,
}

/// Program errors surfaced on-chain as `ProgramError::Custom(code)`.
///
/// The discriminants below are the on-chain error codes for this program
/// version. `error_codes_are_stable` pins the mapping so intentional ABI
/// changes are explicit.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum ShieldedPoolError {
    #[error("invalid instruction data")]
    InvalidInstructionData = 7000,
    #[error("pool tree accounts are invalid")]
    InvalidTreeAccounts = 7001,
    #[error("nullifier tree maintenance failed")]
    NullifierTreeUpdateFailed = 7002,
    #[error("caller is not authorized")]
    UnauthorizedCaller = 7003,
    #[error("state sub-tree append failed")]
    StateAppendFailed = 7004,
    #[error("transaction has expired")]
    ExpiredTransaction = 7005,
    #[error("transact instruction shape is invalid")]
    InvalidTransactShape = 7006,
    #[error("transact proof encoding is invalid")]
    InvalidTransactProofEncoding = 7007,
    #[error("transact proof verification failed")]
    TransactProofVerificationFailed = 7008,
    #[error("transact settlement accounts are invalid")]
    InvalidSettlementAccounts = 7009,
    #[error("transact public settlement failed")]
    PublicSettlementFailed = 7010,
    #[error("SPL asset registry account is invalid")]
    InvalidSplAssetRegistry = 7011,
    #[error("protocol config account is invalid")]
    InvalidProtocolConfig = 7012,
    #[error("pool tree is paused")]
    TreePaused = 7013,
    #[error("zone config account is invalid")]
    InvalidZoneConfig = 7014,
    #[error("nullifier root index references a zeroed (stale) root-history slot")]
    StaleNullifierRoot = 7015,
    #[error("account address does not match its canonical PDA derivation")]
    InvalidPda = 7016,
    #[error("merging is not enabled for this user")]
    MergeDisabled = 7017,
    #[error("user record account is invalid")]
    InvalidUserRecord = 7018,
    #[error("merge_transact instruction shape is invalid")]
    InvalidMergeShape = 7019,
    #[error("merge output ciphertext must be verifiably encrypted")]
    InvalidMergeOutputScheme = 7020,
    #[error("transact proof rail does not match the instruction inputs")]
    MismatchedTransactProofRail = 7021,
    #[error("zone_authority_transact is disabled for this zone")]
    ZoneAuthorityTransactDisabled = 7022,
}

impl From<ShieldedPoolError> for ProgramError {
    fn from(error: ShieldedPoolError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

impl From<InterfaceError> for ShieldedPoolError {
    fn from(error: InterfaceError) -> Self {
        match error {
            InterfaceError::InvalidDiscriminator => ShieldedPoolError::InvalidProtocolConfig,
            InterfaceError::Unauthorized => ShieldedPoolError::UnauthorizedCaller,
            InterfaceError::InvalidAccountData => ShieldedPoolError::InvalidSplAssetRegistry,
        }
    }
}

#[cfg(feature = "tree")]
impl From<TreeError> for ShieldedPoolError {
    fn from(error: TreeError) -> Self {
        match error {
            TreeError::Paused => ShieldedPoolError::TreePaused,
            _ => ShieldedPoolError::InvalidTreeAccounts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ShieldedPoolError::*;

    /// Pin every on-chain error code for this program version.
    #[test]
    fn error_codes_are_stable() {
        let table = [
            (InvalidInstructionData as u32, 7000),
            (InvalidTreeAccounts as u32, 7001),
            (NullifierTreeUpdateFailed as u32, 7002),
            (UnauthorizedCaller as u32, 7003),
            (StateAppendFailed as u32, 7004),
            (ExpiredTransaction as u32, 7005),
            (InvalidTransactShape as u32, 7006),
            (InvalidTransactProofEncoding as u32, 7007),
            (TransactProofVerificationFailed as u32, 7008),
            (InvalidSettlementAccounts as u32, 7009),
            (PublicSettlementFailed as u32, 7010),
            (InvalidSplAssetRegistry as u32, 7011),
            (InvalidProtocolConfig as u32, 7012),
            (TreePaused as u32, 7013),
            (InvalidZoneConfig as u32, 7014),
            (StaleNullifierRoot as u32, 7015),
            (InvalidPda as u32, 7016),
            (MergeDisabled as u32, 7017),
            (InvalidUserRecord as u32, 7018),
            (InvalidMergeShape as u32, 7019),
            (InvalidMergeOutputScheme as u32, 7020),
            (MismatchedTransactProofRail as u32, 7021),
            (ZoneAuthorityTransactDisabled as u32, 7022),
        ];
        for (got, want) in table {
            assert_eq!(got, want, "error code drifted");
        }
    }
}
