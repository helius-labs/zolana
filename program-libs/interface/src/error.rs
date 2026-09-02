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
    #[error("ring config account is invalid")]
    InvalidRingConfig = 7014,
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
    #[error("ring_authority_transact is disabled for this ring")]
    RingAuthorityTransactDisabled = 7022,
    // 7023 retired.
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
    SplTokenAuthorityMustSign = 7040,
    #[error("SPL token program is not supported")]
    UnsupportedSplTokenProgram = 7041,
    #[error("SPL token mint account is invalid")]
    InvalidSplTokenMint = 7042,
    #[error("Token-2022 mint extension is not supported")]
    UnsupportedToken2022Extension = 7043,
    // Retired (PR172): the explicit capacity gate was removed; a merge past the
    // dummy-input threshold now fails at proof verification (7008) because the
    // on-chain `allow_dummy_inputs` flag flips to false. The variant stays so
    // the wire-code table never reuses 7044.
    #[error("nullifier tree is too full to process a merge")]
    NullifierTreeTooFullForMerge = 7044,
    #[error("transact interface transfers for one asset must not net to zero")]
    ZeroNetInterfaceTransferAmount = 7045,
    #[error("SPL asset counter is already initialized")]
    SplAssetCounterAlreadyInitialized = 7046,
    #[error("ring is paused")]
    RingPaused = 7047,
    #[error("nullifier is already queued in the nullifier tree")]
    NullifierAlreadyQueued = 7048,
    #[error("tree does not hold enough lamports to fund a nullifier PDA")]
    InsufficientNullifierPdaRent = 7049,
    #[error("nullifier PDA batch is not reclaimable yet")]
    NullifierPdaNotClosable = 7050,
    #[error("nullifier PDA account is invalid")]
    InvalidNullifierPda = 7051,
    #[error("tree id does not match the protocol config's next tree id")]
    InvalidTreeId = 7052,
    #[error("nullifier PDA belongs to a different tree")]
    NullifierPdaTreeMismatch = 7053,
    #[error("tree id space is exhausted")]
    TreeIdOverflow = 7054,
    #[error("reimbursement recipient must not be a program-owned account")]
    InvalidReimbursementRecipient = 7055,
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
            TreeError::FeeOverflow => ShieldedPoolError::InvalidForesterFee,
            _ => ShieldedPoolError::InvalidTreeAccounts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ShieldedPoolError, ShieldedPoolError::*};

    /// Pin every on-chain error code for this program version.
    #[test]
    fn error_codes_are_stable() {
        /// Maps every enum variant to its pinned code with NO wildcard: a new
        /// variant makes this match non-exhaustive and fails to compile, so
        /// the pin cannot silently go stale.
        fn expected_code(error: ShieldedPoolError) -> u32 {
            match error {
                InvalidInstructionData => 7000,
                InvalidTreeAccounts => 7001,
                NullifierTreeUpdateFailed => 7002,
                UnauthorizedCaller => 7003,
                StateAppendFailed => 7004,
                ExpiredTransaction => 7005,
                InvalidTransactShape => 7006,
                InvalidTransactProofEncoding => 7007,
                TransactProofVerificationFailed => 7008,
                InvalidSettlementAccounts => 7009,
                PublicSettlementFailed => 7010,
                InvalidSplAssetRegistry => 7011,
                InvalidProtocolConfig => 7012,
                TreePaused => 7013,
                InvalidRingConfig => 7014,
                StaleNullifierRoot => 7015,
                InvalidPda => 7016,
                MergeDisabled => 7017,
                InvalidUserRecord => 7018,
                InvalidMergeShape => 7019,
                RingAuthorityTransactDisabled => 7022,
                OwnerTagAccountMissing => 7025,
                InvalidForesterFee => 7026,
                InsufficientForesterFeeBalance => 7027,
                InvalidSystemProgram => 7028,
                EmptyDepositBatch => 7029,
                InvalidDepositAssetIndex => 7030,
                DuplicateDepositAsset => 7031,
                DepositAmountOverflow => 7032,
                UnreferencedDepositAsset => 7033,
                TooManyDepositAssets => 7034,
                TooManyInterfaceTransfers => 7035,
                ZeroInterfaceTransferAmount => 7036,
                TooManyPublicAssets => 7037,
                PublicAssetAmountOverflow => 7038,
                MismatchedCircuitType => 7039,
                SplTokenAuthorityMustSign => 7040,
                UnsupportedSplTokenProgram => 7041,
                InvalidSplTokenMint => 7042,
                UnsupportedToken2022Extension => 7043,
                NullifierTreeTooFullForMerge => 7044,
                ZeroNetInterfaceTransferAmount => 7045,
                SplAssetCounterAlreadyInitialized => 7046,
                RingPaused => 7047,
                NullifierAlreadyQueued => 7048,
                InsufficientNullifierPdaRent => 7049,
                NullifierPdaNotClosable => 7050,
                InvalidNullifierPda => 7051,
                InvalidTreeId => 7052,
                NullifierPdaTreeMismatch => 7053,
                TreeIdOverflow => 7054,
                InvalidReimbursementRecipient => 7055,
            }
        }

        // Every live wire variant, in code order. The exhaustive match above
        // fails to compile if a variant is missing here.
        let variants = [
            InvalidInstructionData,
            InvalidTreeAccounts,
            NullifierTreeUpdateFailed,
            UnauthorizedCaller,
            StateAppendFailed,
            ExpiredTransaction,
            InvalidTransactShape,
            InvalidTransactProofEncoding,
            TransactProofVerificationFailed,
            InvalidSettlementAccounts,
            PublicSettlementFailed,
            InvalidSplAssetRegistry,
            InvalidProtocolConfig,
            TreePaused,
            InvalidRingConfig,
            StaleNullifierRoot,
            InvalidPda,
            MergeDisabled,
            InvalidUserRecord,
            InvalidMergeShape,
            RingAuthorityTransactDisabled,
            OwnerTagAccountMissing,
            InvalidForesterFee,
            InsufficientForesterFeeBalance,
            InvalidSystemProgram,
            EmptyDepositBatch,
            InvalidDepositAssetIndex,
            DuplicateDepositAsset,
            DepositAmountOverflow,
            UnreferencedDepositAsset,
            TooManyDepositAssets,
            TooManyInterfaceTransfers,
            ZeroInterfaceTransferAmount,
            TooManyPublicAssets,
            PublicAssetAmountOverflow,
            MismatchedCircuitType,
            SplTokenAuthorityMustSign,
            UnsupportedSplTokenProgram,
            InvalidSplTokenMint,
            UnsupportedToken2022Extension,
            NullifierTreeTooFullForMerge,
            ZeroNetInterfaceTransferAmount,
            SplAssetCounterAlreadyInitialized,
            RingPaused,
            NullifierAlreadyQueued,
            InsufficientNullifierPdaRent,
            NullifierPdaNotClosable,
            InvalidNullifierPda,
            InvalidTreeId,
            NullifierPdaTreeMismatch,
            TreeIdOverflow,
            InvalidReimbursementRecipient,
        ];
        for variant in variants {
            assert_eq!(
                variant as u32,
                expected_code(variant),
                "error code drifted: {variant:?}"
            );
        }
        // The live wire surface is exactly 52 variants on this branch.
        assert_eq!(variants.len(), 52, "variant count drifted");
    }
}
