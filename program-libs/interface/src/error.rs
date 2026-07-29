use solana_program_error::ProgramError;
use thiserror::Error;
#[cfg(feature = "tree")]
use zolana_tree::TreeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceError {
    InvalidDiscriminator,
    Unauthorized,
    /// Account bytes are the wrong length to be cast to the expected state
    /// struct (e.g. a client reading a fetched account whose data does not
    /// match the struct size).
    InvalidAccountData,
    /// Protocol-config account bytes are the wrong length/format to be cast to
    /// `ProtocolConfig`. Kept distinct from `InvalidAccountData` so the on-chain
    /// mapping reports `InvalidProtocolConfig` (7012) rather than the
    /// SPL-registry code.
    InvalidProtocolConfigData,
    AlreadyInitialized,
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
    // 7020 retired: was `InvalidMergeOutputScheme` (merge output ciphertext had
    // to be verifiably encrypted); merge outputs are now deterministically
    // derived, so there is no ciphertext scheme to check.
    // 7021 retired: was `MismatchedTransactProofVariant`; transact proofs no
    // longer have rail-specific variants.
    #[error("zone_authority_transact is disabled for this zone")]
    ZoneAuthorityTransactDisabled = 7022,
    // 7024 retired.
    #[error("output owner tag account index is out of range")]
    OwnerTagAccountMissing = 7025,
    #[error("forester fee calculation overflowed or used an invalid tree configuration")]
    InvalidForesterFee = 7026,
    #[error("tree does not contain enough fee funds to reimburse the forester")]
    InsufficientForesterFeeBalance = 7027,
    #[error("system program account is invalid")]
    InvalidSystemProgram = 7028,
    #[error("deposit batch contains no entries")]
    EmptyDepositBatch = 7029,
    #[error("deposit entry references an asset index out of range")]
    InvalidDepositAssetIndex = 7030,
    #[error("deposit settlement accounts contain a duplicate asset")]
    DuplicateDepositAsset = 7031,
    #[error("deposit batch amounts overflow for an asset")]
    DepositAmountOverflow = 7032,
    #[error("deposit settlement asset is not referenced by any entry")]
    UnreferencedDepositAsset = 7033,
    #[error("deposit batch exceeds the maximum number of assets")]
    TooManyDepositAssets = 7034,
    #[error("transact interface transfer count exceeds the u8 wire encoding")]
    TooManyInterfaceTransfers = 7035,
    #[error("transact interface transfers must have nonzero amounts")]
    ZeroInterfaceTransferAmount = 7036,
    #[error("transact exceeds the maximum number of distinct public assets")]
    TooManyPublicAssets = 7037,
    #[error("transact public settlement amounts overflow while aggregating an asset")]
    PublicAssetAmountOverflow = 7038,
    #[error("circuit selector type does not match the dispatched instruction")]
    MismatchedCircuitType = 7039,
    #[error("SPL deposit authority must sign")]
    SplDepositorMustSign = 7040,
    #[error("SPL token program is not supported")]
    UnsupportedSplTokenProgram = 7041,
    #[error("SPL token mint account is invalid")]
    InvalidSplTokenMint = 7042,
    #[error("Token-2022 mint extension is not supported")]
    UnsupportedToken2022Extension = 7043,
    #[error("nullifier tree is too full to process a merge")]
    NullifierTreeTooFullForMerge = 7044,
    #[error("SPL asset counter is already initialized")]
    SplAssetCounterAlreadyInitialized = 7045,
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
            InterfaceError::InvalidProtocolConfigData => ShieldedPoolError::InvalidProtocolConfig,
            InterfaceError::AlreadyInitialized => {
                ShieldedPoolError::SplAssetCounterAlreadyInitialized
            }
        }
    }
}

#[cfg(feature = "tree")]
impl From<TreeError> for ShieldedPoolError {
    fn from(error: TreeError) -> Self {
        match error {
            TreeError::Paused => ShieldedPoolError::TreePaused,
            TreeError::TreeIsFull => ShieldedPoolError::StateAppendFailed,
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
            (ZoneAuthorityTransactDisabled as u32, 7022),
            (OwnerTagAccountMissing as u32, 7025),
            (InvalidForesterFee as u32, 7026),
            (InsufficientForesterFeeBalance as u32, 7027),
            (InvalidSystemProgram as u32, 7028),
            (EmptyDepositBatch as u32, 7029),
            (InvalidDepositAssetIndex as u32, 7030),
            (DuplicateDepositAsset as u32, 7031),
            (DepositAmountOverflow as u32, 7032),
            (UnreferencedDepositAsset as u32, 7033),
            (TooManyDepositAssets as u32, 7034),
            (TooManyInterfaceTransfers as u32, 7035),
            (ZeroInterfaceTransferAmount as u32, 7036),
            (TooManyPublicAssets as u32, 7037),
            (PublicAssetAmountOverflow as u32, 7038),
            (MismatchedCircuitType as u32, 7039),
            (SplDepositorMustSign as u32, 7040),
            (UnsupportedSplTokenProgram as u32, 7041),
            (InvalidSplTokenMint as u32, 7042),
            (UnsupportedToken2022Extension as u32, 7043),
            (NullifierTreeTooFullForMerge as u32, 7044),
            (SplAssetCounterAlreadyInitialized as u32, 7045),
        ];
        for (got, want) in table {
            assert_eq!(got, want, "error code drifted");
        }
    }
}
