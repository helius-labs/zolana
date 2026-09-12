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
    #[error("ring_authority_transact is disabled for this ring")]
    RingAuthorityTransactDisabled = 7020,
    #[error("output owner tag account index is out of range")]
    OwnerTagAccountMissing = 7021,
    #[error("forester fee calculation overflowed or used an invalid tree configuration")]
    InvalidForesterFee = 7022,
    #[error("tree does not contain enough fee funds to reimburse the forester")]
    InsufficientForesterFeeBalance = 7023,
    #[error("system program account is invalid")]
    InvalidSystemProgram = 7024,
    #[error("deposit batch contains no entries")]
    EmptyDepositBatch = 7025,
    #[error("deposit entry references an asset index out of range")]
    InvalidDepositAssetIndex = 7026,
    #[error("deposit settlement accounts contain a duplicate asset")]
    DuplicateDepositAsset = 7027,
    #[error("deposit batch amounts overflow for an asset")]
    DepositAmountOverflow = 7028,
    #[error("deposit settlement asset is not referenced by any entry")]
    UnreferencedDepositAsset = 7029,
    #[error("deposit batch exceeds the maximum number of assets")]
    TooManyDepositAssets = 7030,
    #[error("transact interface transfer count exceeds the u8 wire encoding")]
    TooManyInterfaceTransfers = 7031,
    #[error("transact interface transfers must have nonzero amounts")]
    ZeroInterfaceTransferAmount = 7032,
    #[error("transact exceeds the maximum number of distinct public assets")]
    TooManyPublicAssets = 7033,
    #[error("transact public settlement amounts overflow while aggregating an asset")]
    PublicAssetAmountOverflow = 7034,
    #[error("circuit selector type does not match the dispatched instruction")]
    MismatchedCircuitType = 7035,
    #[error("SPL deposit authority must sign")]
    SplTokenAuthorityMustSign = 7036,
    #[error("SPL token program is not supported")]
    UnsupportedSplTokenProgram = 7037,
    #[error("SPL token mint account is invalid")]
    InvalidSplTokenMint = 7038,
    #[error("Token-2022 mint extension is not supported")]
    UnsupportedToken2022Extension = 7039,
    #[error("transact interface transfers for one asset must not net to zero")]
    ZeroNetInterfaceTransferAmount = 7040,
    #[error("SPL asset counter is already initialized")]
    SplAssetCounterAlreadyInitialized = 7041,
    #[error("ring is paused")]
    RingPaused = 7042,
    #[error("nullifier is already queued in the nullifier tree")]
    NullifierAlreadyQueued = 7043,
    #[error("tree does not hold enough lamports to fund a nullifier PDA")]
    InsufficientNullifierPdaRent = 7044,
    #[error("nullifier PDA batch is not reclaimable yet")]
    NullifierPdaNotClosable = 7045,
    #[error("nullifier PDA account is invalid")]
    InvalidNullifierPda = 7046,
    #[error("tree id does not match the protocol config's next tree id")]
    InvalidTreeId = 7047,
    #[error("nullifier PDA belongs to a different tree")]
    NullifierPdaTreeMismatch = 7048,
    #[error("tree id space is exhausted")]
    TreeIdOverflow = 7049,
    #[error("reimbursement recipient must not be a program-owned account")]
    InvalidReimbursementRecipient = 7050,
    #[error("output utxo hash is not a canonical BN254 field element")]
    NonCanonicalOutputUtxoHash = 7051,
    #[error("input nullifier is not a canonical BN254 field element")]
    NonCanonicalInputNullifier = 7052,
    #[error("private tx hash is not a canonical BN254 field element")]
    NonCanonicalPrivateTxHash = 7053,
    #[error("ring data hash is not a canonical BN254 field element")]
    NonCanonicalRingDataHash = 7054,
    #[error("deposit entry field is not a canonical BN254 field element")]
    NonCanonicalDepositField = 7055,
    #[error("nullifier tree root is not a canonical BN254 field element")]
    NonCanonicalRoot = 7056,
    #[error("tree holds no lamports above its rent, fee balance, and working capital")]
    NoClaimableTreeLamports = 7057,
    #[error("deposit blinding derivation failed")]
    DepositBlindingDerivationFailed = 7058,
    #[error("ring is not activated by governance")]
    RingNotActivated = 7059,
    #[error("external data hash preimage exceeds the supported slice count")]
    TooManyExternalDataHashSlices = 7060,
    #[error("transact must declare between one and MAX_INPUT_TREES input trees")]
    InvalidTreeContextCount = 7061,
    #[error("input references a tree index beyond the declared input trees")]
    InputTreeIndexOutOfRange = 7062,
    #[error("inputs must be grouped by tree in non-decreasing tree-index order")]
    InputsNotGroupedByTree = 7063,
    #[error("a declared input tree is referenced by no input")]
    UnreferencedTreeContext = 7064,
    #[error("the same input tree account is passed twice")]
    DuplicateInputTree = 7065,
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
                RingAuthorityTransactDisabled => 7020,
                OwnerTagAccountMissing => 7021,
                InvalidForesterFee => 7022,
                InsufficientForesterFeeBalance => 7023,
                InvalidSystemProgram => 7024,
                EmptyDepositBatch => 7025,
                InvalidDepositAssetIndex => 7026,
                DuplicateDepositAsset => 7027,
                DepositAmountOverflow => 7028,
                UnreferencedDepositAsset => 7029,
                TooManyDepositAssets => 7030,
                TooManyInterfaceTransfers => 7031,
                ZeroInterfaceTransferAmount => 7032,
                TooManyPublicAssets => 7033,
                PublicAssetAmountOverflow => 7034,
                MismatchedCircuitType => 7035,
                SplTokenAuthorityMustSign => 7036,
                UnsupportedSplTokenProgram => 7037,
                InvalidSplTokenMint => 7038,
                UnsupportedToken2022Extension => 7039,
                ZeroNetInterfaceTransferAmount => 7040,
                SplAssetCounterAlreadyInitialized => 7041,
                RingPaused => 7042,
                NullifierAlreadyQueued => 7043,
                InsufficientNullifierPdaRent => 7044,
                NullifierPdaNotClosable => 7045,
                InvalidNullifierPda => 7046,
                InvalidTreeId => 7047,
                NullifierPdaTreeMismatch => 7048,
                TreeIdOverflow => 7049,
                InvalidReimbursementRecipient => 7050,
                NonCanonicalOutputUtxoHash => 7051,
                NonCanonicalInputNullifier => 7052,
                NonCanonicalPrivateTxHash => 7053,
                NonCanonicalRingDataHash => 7054,
                NonCanonicalDepositField => 7055,
                NonCanonicalRoot => 7056,
                NoClaimableTreeLamports => 7057,
                DepositBlindingDerivationFailed => 7058,
                RingNotActivated => 7059,
                TooManyExternalDataHashSlices => 7060,
                InvalidTreeContextCount => 7061,
                InputTreeIndexOutOfRange => 7062,
                InputsNotGroupedByTree => 7063,
                UnreferencedTreeContext => 7064,
                DuplicateInputTree => 7065,
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
            NonCanonicalOutputUtxoHash,
            NonCanonicalInputNullifier,
            NonCanonicalPrivateTxHash,
            NonCanonicalRingDataHash,
            NonCanonicalDepositField,
            NonCanonicalRoot,
            NoClaimableTreeLamports,
            DepositBlindingDerivationFailed,
            RingNotActivated,
            TooManyExternalDataHashSlices,
            InvalidTreeContextCount,
            InputTreeIndexOutOfRange,
            InputsNotGroupedByTree,
            UnreferencedTreeContext,
            DuplicateInputTree,
        ];
        for (variant, code) in variants.into_iter().zip(7000_u32..) {
            assert_eq!(
                variant as u32,
                expected_code(variant),
                "error code drifted: {variant:?}"
            );
            assert_eq!(variant as u32, code, "error codes must be contiguous");
        }
        // The list above must contain every live variant.
        assert_eq!(variants.len(), 66, "variant count drifted");

        let expected: std::collections::BTreeMap<String, u32> = serde_json::from_str(include_str!(
            "../../../test-vectors/shielded_pool_errors.json"
        ))
        .unwrap();
        let actual = variants
            .into_iter()
            .map(|variant| (format!("{variant:?}"), variant as u32))
            .collect();
        assert_eq!(expected, actual, "shared error-code fixture drifted");
    }
}
