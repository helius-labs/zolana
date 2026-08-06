//! Squads zone program errors. Shared by the program (which raises them) and
//! clients (which decode `ProgramError::Custom(code)`). Codes live in the 8000
//! space, distinct from the SPP's 7000 space. `error_codes_are_stable` pins the
//! mapping so intentional ABI changes are explicit.

use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum SquadsZoneError {
    // Instruction data / serialization.
    #[error("invalid instruction data")]
    InvalidInstructionData = 8000,
    #[error("failed to deserialize account or instruction data")]
    Deserialization = 8001,

    // Account validation.
    #[error("zone config account is invalid")]
    InvalidZoneConfig = 8002,
    #[error("viewing key account is invalid")]
    InvalidViewingKeyAccount = 8003,
    #[error("proposal account is invalid")]
    InvalidProposal = 8004,
    #[error("key update proposal account is invalid")]
    InvalidKeyUpdateProposal = 8005,
    #[error("account discriminator does not match")]
    InvalidDiscriminator = 8006,
    #[error("account size does not match its layout")]
    InvalidAccountSize = 8007,
    #[error("account is not owned by this program")]
    InvalidAccountOwner = 8009,

    // PDA derivation.
    #[error("account address does not match its canonical PDA derivation")]
    InvalidPda = 8010,
    #[error("zone auth account is not the canonical ring_auth PDA")]
    InvalidZoneAuth = 8011,

    // Required signatures.
    #[error("authority signature is missing")]
    MissingAuthoritySignature = 8012,
    #[error("owner signature is missing")]
    MissingOwnerSignature = 8013,
    #[error("executor signature is missing")]
    MissingExecutorSignature = 8014,
    #[error("co-signer signature is missing")]
    MissingCoSignerSignature = 8015,
    #[error("merge authority signature is missing")]
    MissingMergeAuthoritySignature = 8016,

    // Identity / authority mismatches.
    #[error("authority does not match zone config")]
    AuthorityMismatch = 8017,
    #[error("owner does not match the account owner")]
    OwnerMismatch = 8018,
    #[error("executor does not match the proposal executor")]
    ExecutorMismatch = 8019,
    #[error("co-signer does not match zone config")]
    CoSignerMismatch = 8020,
    #[error("merge authority is not in the zone config allowlist")]
    MergeAuthorityNotWhitelisted = 8021,

    // State / policy.
    #[error("viewing key account is blocked")]
    ViewingKeyAccountBlocked = 8022,
    #[error("unsupported encryption scheme")]
    InvalidEncryptionScheme = 8023,
    #[error("invalid viewing key account state value")]
    InvalidViewingKeyState = 8024,
    #[error("zone config is frozen")]
    ConfigFrozen = 8025,
    #[error("zone config must declare exactly one auditor key")]
    InvalidAuditorKeyCount = 8026,
    #[error("recovery-key and auditor-update operations cannot be mixed")]
    MixedKeyOperationTypes = 8027,
    #[error("auditor update does not change the auditor keys")]
    AuditorNotChanged = 8028,
    #[error("unknown key operation")]
    InvalidKeyOperation = 8029,
    #[error("ciphertext count does not match key count")]
    CiphertextCountMismatch = 8031,
    #[error("key update buffer is not fully filled")]
    KeyBufferNotFull = 8032,
    #[error("key update buffer overflow")]
    KeyBufferOverflow = 8033,

    // Lifecycle.
    #[error("proposal has expired")]
    ProposalExpired = 8034,
    #[error("transaction has expired")]
    TransactionExpired = 8035,
    #[error("proposal owner does not match the viewing key account")]
    ProposalOwnershipMismatch = 8036,
    #[error("key update proposal target does not match")]
    ProposalTargetMismatch = 8037,
    #[error("rent recipient does not match the recorded rent payer")]
    RentRecipientMismatch = 8038,

    // Proofs.
    #[error("proof encoding is invalid")]
    InvalidProofEncoding = 8039,
    #[error("zone proof verification failed")]
    ZoneProofVerificationFailed = 8040,
    #[error("key encryption proof verification failed")]
    KeyEncryptionProofVerificationFailed = 8041,
    #[error("failed to hash public inputs")]
    ProofHashingFailed = 8043,

    // CPI / SPP.
    #[error("SPP program account does not match the shielded-pool program id")]
    InvalidSppProgram = 8044,
    #[error("SPP CPI failed")]
    SppCpiFailed = 8045,

    // Arithmetic.
    #[error("arithmetic overflow")]
    ArithmeticOverflow = 8046,

    // Settlement scope.
    #[error("deposit settlement accounts are malformed")]
    InvalidDepositAccounts = 8049,
    #[error("withdrawal settlement accounts are malformed")]
    InvalidWithdrawalAccounts = 8050,
    #[error("owner kind is not a known variant")]
    InvalidOwnerKind = 8051,
    #[error("zone config creator is not the program deploy upgrade authority")]
    InvalidInitializationAuthority = 8052,
    #[error("proposal recipient does not match the execution destination")]
    ProposalRecipientMismatch = 8053,
    #[error("proposal asset does not match the withdrawal settlement asset")]
    ProposalAssetMismatch = 8054,
    #[error("proposal expiry exceeds the configured maximum lifetime")]
    ProposalLifetimeExceeded = 8055,
    #[error("proposal fee payer must be the proposal owner")]
    ProposalPayerMismatch = 8056,
    #[error("recovery-key updates require an authenticated owner approval scheme")]
    RecoveryKeyUpdateUnsupported = 8057,
    #[error("no verifying key covers this input and output count")]
    UnsupportedProofShape = 8058,
    #[error("no verifying key covers this recipient key count")]
    UnsupportedKeyCount = 8059,
    #[error("account state serialization failed")]
    Serialization = 8060,
    #[error("the folded run carries more legs than the chain holds")]
    FoldLegCountOverflow = 8061,
    #[error("program account does not match the squads zone program id")]
    InvalidZoneProgram = 8062,
    #[error("a key rotation must keep the account's nullifier public key")]
    NullifierPubkeyRotationUnsupported = 8063,
    #[error("key update proposal was opened at an earlier key nonce")]
    StaleKeyUpdateProposal = 8064,
    #[error("input and output counts do not match the operation's proof shape")]
    ProofShapeMismatch = 8065,
    #[error("merge output ring data hash does not index the supplied owner account")]
    MergeOutputTagMismatch = 8066,
}

impl From<SquadsZoneError> for ProgramError {
    fn from(error: SquadsZoneError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
