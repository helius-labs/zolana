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
    #[error("account is already initialized")]
    AccountAlreadyInitialized = 8008,
    #[error("account is not owned by this program")]
    InvalidAccountOwner = 8009,

    // PDA derivation.
    #[error("account address does not match its canonical PDA derivation")]
    InvalidPda = 8010,
    #[error("zone auth account is not the canonical zone_auth PDA")]
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
    #[error("key operation index is out of bounds")]
    InvalidKeyOperationIndex = 8030,
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
    #[error("merge proof verification failed")]
    MergeProofVerificationFailed = 8042,
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
    #[error("invalid amount")]
    InvalidAmount = 8047,

    // Settlement scope.
    #[error("this settlement path is not yet implemented")]
    ZoneSettlementNotImplemented = 8048,
    #[error("deposit settlement accounts are malformed")]
    InvalidDepositAccounts = 8049,
    #[error("withdrawal settlement accounts are malformed")]
    InvalidWithdrawalAccounts = 8050,
    #[error("owner kind is not a known variant")]
    InvalidOwnerKind = 8051,
}

impl From<SquadsZoneError> for ProgramError {
    fn from(error: SquadsZoneError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
