use solana_program_error::ProgramError;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_ring_policy::{PolicyHashError, RuleTableError};

macro_rules! ring_errors {
    ($($variant:ident = $code:literal => $message:literal,)*) => {
        /// Ring program errors in 8100..8199, clear of SPP (7000..7065) and the other programs.
        /// Clients observe every code, `error_codes_are_stable` pins them.
        #[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
        #[repr(u32)]
        pub enum CustomRingError {
            $(#[error($message)] $variant = $code,)*
        }
    };
}

ring_errors! {
    InvalidInstructionData = 8100 => "instruction data is invalid",
    ProofVerificationFailed = 8101 => "proof verification failed",
    HashingFailed = 8102 => "hashing failed",
    InvalidShieldedPoolProgram = 8103 => "shielded pool program account is invalid",
    MissingRingAuth = 8104 => "ring auth account is missing from the forwarded account list",
    ConfigAlreadyInitialized = 8105 => "ring config account is already initialized",
    ConfigNotInitialized = 8106 => "ring config account is not initialized",
    UnauthorizedAuthority = 8107 => "signer is not the configured ring authority",
    InvalidAuditorPubkey = 8108 => "auditor public key is not allowed",
    MissingAuditorMessage = 8109 => "transact carries no auditor message",
    InvalidAuditorMessage = 8110 => "auditor message is malformed",
    InvalidSystemProgram = 8111 => "system program account is invalid",
    InvalidConfigPda = 8112 => "config account is not the canonical config PDA",
    UnsupportedCircuit = 8113 => "circuit selector is not supported by the ring",
    UnauthorizedInitializer = 8114 => "authority is not the program upgrade authority",
    TooManyAccounts = 8115 => "forwarded account list exceeds the CPI account limit",
    ReadAccessRecordAlreadyExists = 8116 => "read access record already exists",
    InvalidReadAccessRecord = 8117 => "read access record account is invalid",
    InvalidReaderKey = 8118 => "reader key cannot authorize reads",
    UnsupportedOutputScheme = 8119 => "output data must use confidential framing",
    PolicyConfigAlreadyInitialized = 8120 => "policy config account is already initialized",
    PolicyConfigNotInitialized = 8121 => "policy config account is not initialized",
    InvalidPolicyConfigPda = 8122 => "policy config account is not the canonical policy PDA",
    // 8123 retired.
    InvalidPolicyMember = 8124 => "policy member is invalid",
    UnauthorizedNamespaceSigner = 8125 => "signer may not mutate entries of the list",
    InvalidListId = 8126 => "list is unknown",
    InvalidEntryState = 8127 => "entry state is unknown",
    // 8128 retired, an empty policy table is valid.
    // 8129 retired.
    EntryVersionOverflow = 8130 => "entry version overflows",
    InvalidNamespacePda = 8131 => "entries account is not the canonical namespace PDA",
    InvalidAddressTree = 8132 => "address tree account is invalid",
    StalePolicyRoot = 8133 => "policy root index is outside the window the statement admits",
    InvalidSource = 8134 => "policy sources do not match the lists the compiled table references",
    InvalidCuratorPolicyConfig = 8135 =>
        "curator policy config account is not a canonical initialized policy config",
    CuratorTreeMismatch = 8136 => "curator pins a different address tree",
    CuratorSourceMissing = 8137 => "curator has no source for the list",
    ForeignSource = 8138 =>
        "the list is served by a curator's entries, mutate it on the curator ring",
    InvalidEntryContent = 8139 => "entry content does not fit the list",
    InvalidPolicyRules = 8140 => "policy rules do not decode to a table the circuit enforces",
    PolicyGenerationOverflow = 8141 => "policy generation overflows",
    PolicyOnAuditOnlyRing = 8142 => "an audit-only ring takes no policy",
    MissingCoSigner = 8143 => "the operation needs the co-signer's signature",
    UnauthorizedCoSigner = 8144 => "the signer is not the ring's co-signer",
    InvalidCoSignerScope = 8145 => "co-signer scope must be a nonzero subset of the scope bits",
    InvalidCoSigner = 8146 => "co-signer account is invalid",
    InvalidCoSignerThresholds = 8147 => "co-signer thresholds exceed the table or repeat a mint",
    // 8148 and 8149 retired with the public spend windows.
    DelegateDisabled = 8150 => "the ring has no delegate",
    UnauthorizedDelegate = 8151 => "the delegate must sign",
    DelegatePublicLeg = 8152 => "a delegate move settles no public leg",
    DelegateAlreadySet = 8153 => "the delegate is permanent",
    InvalidDelegate = 8154 => "delegate account is invalid",
    // 8155 and 8156 retired with the windowed spend records.
    ApprovalWithoutCoSigner = 8157 => "dual control needs a configured co-signer",
    // 8158 and 8159 retired with the windowed spend records.
    InvalidKeyRegistryRoot = 8160 => "key registry root account is invalid",
    StaleKeyRegistryRoot = 8161 => "key registry root changed",
    InvalidKeyRegistryCursor = 8162 => "key registry append cursor is invalid or exhausted",
    KeyRegistryRootAlreadyExists = 8163 => "key registry root already exists",
    InvalidDepositAudit = 8164 => "invalid deposit audit setting",
    DepositAuditRequired = 8165 => "verified deposit disclosure required",
    InvalidDepositDisclosure = 8166 => "invalid deposit disclosure",
    // 8167 retired with the counters disclosure.
    InvalidRevocationTarget = 8168 => "revocation target account is invalid",
    PolicyFactRevoked = 8169 => "policy fact changed after proof creation",
    DelegateRequiresPolicy = 8170 => "a delegate needs a policy ring",
    InvalidRevocationTreeIndex = 8171 => "revocation tree index is invalid",
    InvalidPolicyTrees = 8172 => "policy tree accounts are invalid",
    // 8173 and 8174 retired with the window index.
    UnexpectedKeyRegistryRoot = 8175 => "a ring without key escrow takes no key registry root",
    UnexpectedApproval = 8176 => "approval needs a member transfer under outflow limits",
    InvalidSettlementAccounts = 8177 => "settlement accounts do not match the public legs",
    TooManyPublicLegs = 8178 => "too many public legs",
    InvalidAuditedDeposit = 8179 => "audited deposit does not wrap an SPP deposit",
    InvalidDepositData = 8180 => "forwarded deposit data is invalid",
    UnexpectedRevocationTarget = 8181 => "an audit-only statement takes no revocation target",
    // 8182 retired with the public spend windows.
}

impl From<CustomRingError> for ProgramError {
    fn from(error: CustomRingError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

impl From<HasherError> for CustomRingError {
    fn from(_: HasherError) -> Self {
        Self::HashingFailed
    }
}

impl From<RuleTableError> for CustomRingError {
    fn from(_: RuleTableError) -> Self {
        Self::InvalidPolicyRules
    }
}

impl From<PolicyHashError> for CustomRingError {
    fn from(error: PolicyHashError) -> Self {
        match error {
            PolicyHashError::Table(_) => Self::InvalidPolicyRules,
            PolicyHashError::MissingSource(_) => Self::InvalidSource,
            PolicyHashError::Hashing => Self::HashingFailed,
        }
    }
}
