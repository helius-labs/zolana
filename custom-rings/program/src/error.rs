use solana_program_error::ProgramError;
use thiserror::Error;

/// Errors of the custom ring program.
///
/// The 8100..8113 range is reserved for this program and is collision-free
/// against SPP (7000..7047) and the other programs (zk-program-swap
/// 8005..8016, the rest 9xxx). Every code is pinned by
/// `tests/error_codes.rs::error_codes_are_stable`; clients observe them, so they
/// are never renumbered.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum CustomRingError {
    #[error("instruction data is invalid")]
    InvalidInstructionData = 8100,
    #[error("proof verification failed")]
    ProofVerificationFailed = 8101,
    #[error("hashing failed")]
    HashingFailed = 8102,
    #[error("shielded pool program account is invalid")]
    InvalidShieldedPoolProgram = 8103,
    #[error("ring auth account is missing from the forwarded account list")]
    MissingRingAuth = 8104,
    #[error("ring config account is already initialized")]
    ConfigAlreadyInitialized = 8105,
    #[error("ring config account is not initialized")]
    ConfigNotInitialized = 8106,
    #[error("signer is not the configured ring authority")]
    UnauthorizedAuthority = 8107,
    #[error("auditor public key is not allowed")]
    InvalidAuditorPubkey = 8108,
    #[error("transact carries no auditor message")]
    MissingAuditorMessage = 8109,
    #[error("auditor message is malformed")]
    InvalidAuditorMessage = 8110,
    #[error("system program account is invalid")]
    InvalidSystemProgram = 8111,
    #[error("config account is not the canonical config PDA")]
    InvalidConfigPda = 8112,
    #[error("circuit selector is not supported by the ring")]
    UnsupportedCircuit = 8113,
    #[error("authority is not the program upgrade authority")]
    UnauthorizedInitializer = 8114,
    #[error("forwarded account list exceeds the CPI account limit")]
    TooManyAccounts = 8115,
    #[error("read access record already exists")]
    ReadAccessRecordAlreadyExists = 8116,
    #[error("read access record account is invalid")]
    InvalidReadAccessRecord = 8117,
    #[error("reader key cannot authorize reads")]
    InvalidReaderKey = 8118,
    #[error("output data must use confidential framing")]
    UnsupportedOutputScheme = 8119,
}

impl From<CustomRingError> for ProgramError {
    fn from(error: CustomRingError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
