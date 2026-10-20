use solana_program_error::ProgramError;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_ring_policy::{PolicyHashError, RuleTableError, SourceMapError};

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
    UnauthorizedListWrite = 8125 => "signer may not write the list for the member",
    InvalidListId = 8126 => "list is unknown",
    // 8127 retired with the list entries.
    // 8128 retired, an empty policy table is valid.
    // 8129 and 8130 retired with the list entries.
    InvalidNamespacePda = 8131 => "namespace PDA cannot be derived",
    InvalidAddressTree = 8132 => "address tree account is invalid",
    StalePolicyRoot = 8133 => "policy root index is outside the window the statement admits",
    InvalidSource = 8134 =>
        "policy sources do not match the referenced lists or name a second curator",
    InvalidCuratorRegistry = 8135 =>
        "curator member registry root account is not an initialized member registry root",
    // 8136 to 8139 retired with the list entries.
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
    InvalidMemberRegistryRoot = 8160 => "member registry root account is invalid",
    StaleMemberRegistryRoot = 8161 => "member registry root changed",
    InvalidMemberRegistryCursor = 8162 =>
        "member registry append index is not the next free slot or the registry is full",
    MemberRegistryRootAlreadyExists = 8163 => "member registry root already exists",
    InvalidDepositAudit = 8164 => "invalid deposit audit setting",
    DepositAuditRequired = 8165 => "verified deposit disclosure required",
    InvalidDepositDisclosure = 8166 => "invalid deposit disclosure",
    // 8167 retired with the counters disclosure.
    // 8168 and 8169 retired with the revocation targets.
    DelegateRequiresPolicy = 8170 => "a delegate needs a policy ring",
    // 8171 retired with the revocation targets.
    InvalidPolicyTrees = 8172 => "policy tree accounts are invalid",
    MissingFundingSigner = 8173 => "forwarded funding account must sign on entry",
    // 8174 retired with the window index.
    UnexpectedMemberRegistryRoot = 8175 => "the statement binds no member registry root",
    UnexpectedApproval = 8176 => "approval needs a member transfer under outflow limits",
    InvalidSettlementAccounts = 8177 => "settlement accounts do not match the public legs",
    TooManyPublicLegs = 8178 => "too many public legs",
    InvalidAuditedDeposit = 8179 => "audited deposit does not wrap an SPP deposit",
    InvalidDepositData = 8180 => "forwarded deposit data is invalid",
    // 8181 retired with the revocation targets.
    // 8182 retired with the public spend windows.
    // 8183 retired with the P-256 auditor keys.
    InvalidRingMode = 8184 => "the ring mode is unknown",
    AnonymousRingRefused = 8185 => "an anonymous ring refuses this operation",
    InvalidAnonymousOutput = 8186 => "an anonymous ring output must carry a zero owner tag",
    InvalidAnonymousSigner = 8187 => "an anonymous ring transaction takes no owner signer",
    InvalidMergeDisclosure = 8188 =>
        "the merge disclosure does not match the ring mode or the auditor key",
    MemberBatchOrder = 8189 => "member batch is not strictly ascending by member",
    MemberBatchTooLarge = 8190 => "member batch is empty or exceeds the proof width",
    MemberRecordMismatch = 8191 => "member record does not match the signer or the sealed key",
    MissingOwnerSigner = 8192 => "forwarded owner signer must sign on entry",
    InvalidAnonymousOutputBody = 8193 => "an anonymous output body is not one framed scheme-9 body",
    InvalidAnonymousTag = 8194 =>
        "an anonymous output tag must be inline, nonzero and start with a zero byte",
    DuplicateAnonymousTag = 8195 => "two anonymous outputs publish one tag",
    InvalidAnonymousOutputHash = 8196 => "an anonymous output hash is zero",
    AnonymousOutputCount = 8197 => "an anonymous transaction publishes every output slot of its shape",
    MissingMergeDisclosure = 8198 => "an anonymous ring merge carries its disclosure proof",
    MergeDisclosureWidth = 8199 => "the merge disclosure field count does not match the merge width",
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

impl From<SourceMapError> for CustomRingError {
    fn from(_: SourceMapError) -> Self {
        Self::InvalidSource
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
