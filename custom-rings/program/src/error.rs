use solana_program_error::ProgramError;
use thiserror::Error;

/// Errors of the custom ring program.
///
/// The 8100..8176 range is reserved for the ring program and is collision-free
/// against SPP (7000..7065) and the other programs (zk-program-swap
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
    #[error("policy config account is already initialized")]
    PolicyConfigAlreadyInitialized = 8120,
    #[error("policy config account is not initialized")]
    PolicyConfigNotInitialized = 8121,
    #[error("policy config account is not the canonical policy PDA")]
    InvalidPolicyConfigPda = 8122,
    // 8123 retired.
    #[error("policy member is invalid")]
    InvalidPolicyMember = 8124,
    #[error("signer may not mutate entries of the list")]
    UnauthorizedNamespaceSigner = 8125,
    #[error("list is unknown")]
    InvalidListId = 8126,
    #[error("entry state is unknown")]
    InvalidEntryState = 8127,
    // 8128 retired, an empty policy table is valid.
    #[error("the tree must be the policy entries tree")]
    InvalidPolicyTree = 8129,
    #[error("entry version overflows")]
    EntryVersionOverflow = 8130,
    #[error("entries account is not the canonical namespace PDA")]
    InvalidNamespacePda = 8131,
    #[error("entries tree account is not a shielded pool tree")]
    InvalidEntriesTree = 8132,
    #[error("policy root index is outside the window the statement admits")]
    StalePolicyRoot = 8133,
    #[error("policy sources do not match the lists the compiled table references")]
    InvalidSource = 8134,
    #[error("curator policy config account is not a canonical initialized policy config")]
    InvalidCuratorPolicyConfig = 8135,
    #[error("curator entries live in a different tree")]
    CuratorTreeMismatch = 8136,
    #[error("curator has no source for the list")]
    CuratorSourceMissing = 8137,
    #[error("the list is served by a curator's entries, mutate it on the curator ring")]
    ForeignSource = 8138,
    #[error("entry content does not fit the list")]
    InvalidEntryContent = 8139,
    #[error("policy rules do not decode to a table the circuit enforces")]
    InvalidPolicyRules = 8140,
    #[error("policy generation overflows")]
    PolicyGenerationOverflow = 8141,
    #[error("an audit-only ring takes no policy")]
    PolicyOnAuditOnlyRing = 8142,
    #[error("the operation needs the co-signer's signature")]
    MissingCoSigner = 8143,
    #[error("the signer is not the ring's co-signer")]
    UnauthorizedCoSigner = 8144,
    #[error("co-signer scope must be a nonzero subset of the scope bits")]
    InvalidCoSignerScope = 8145,
    #[error("co-signer account is invalid")]
    InvalidCoSigner = 8146,
    #[error("co-signer thresholds exceed the table or repeat a mint")]
    InvalidCoSignerThresholds = 8147,
    #[error("the public legs exceed a spend window cap")]
    SpendWindowExceeded = 8148,
    #[error("spend window account is invalid")]
    InvalidSpendWindow = 8149,
    #[error("the ring has no delegate")]
    DelegateDisabled = 8150,
    #[error("the delegate must sign")]
    UnauthorizedDelegate = 8151,
    #[error("a delegate move settles no public leg")]
    DelegatePublicLeg = 8152,
    #[error("the delegate is permanent")]
    DelegateAlreadySet = 8153,
    #[error("delegate account is invalid")]
    InvalidDelegate = 8154,
    #[error("a velocity transfer settles no deposit leg")]
    VelocityDepositLeg = 8155,
    #[error("the spend record output does not match its plaintext")]
    InvalidSpendRecord = 8156,
    // 8157 retired.
    #[error("dual control needs a configured co-signer")]
    ApprovalWithoutCoSigner = 8158,
    #[error("the ring has no velocity window")]
    VelocityDisabled = 8159,
    // 8160..8163 retired.
    #[error("the velocity window duration cannot change once set")]
    VelocityWindowImmutable = 8164,
    #[error("head map root account is invalid")]
    InvalidHeadMapRoot = 8165,
    #[error("head map root changed")]
    StaleHeadMapRoot = 8166,
    #[error("head map append cursor is invalid or exhausted")]
    InvalidHeadMapCursor = 8167,
    #[error("key registry root account is invalid")]
    InvalidKeyRegistryRoot = 8168,
    #[error("key registry root changed")]
    StaleKeyRegistryRoot = 8169,
    #[error("key registry append cursor is invalid or exhausted")]
    InvalidKeyRegistryCursor = 8170,
    #[error("head map root already exists")]
    HeadMapRootAlreadyExists = 8171,
    #[error("key registry root already exists")]
    KeyRegistryRootAlreadyExists = 8172,
    #[error("invalid deposit audit setting")]
    InvalidDepositAudit = 8173,
    #[error("verified deposit disclosure required")]
    DepositAuditRequired = 8174,
    #[error("invalid deposit disclosure")]
    InvalidDepositDisclosure = 8175,
    #[error("invalid spend counters disclosure")]
    InvalidSpendCountersDisclosure = 8176,
}

impl From<CustomRingError> for ProgramError {
    fn from(error: CustomRingError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
