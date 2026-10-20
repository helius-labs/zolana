use custom_ring_interface::CustomRingError;
use solana_address::Address;
use solana_signature::Signature;
use thiserror::Error;
use zolana_client::{BlockingInsideRuntime, ClientError};
use zolana_hasher::HasherError;
use zolana_keypair::KeypairError;
use zolana_program::instruction::DepositBuildError;
use zolana_ring_policy::{ListId, Member, MemberError, PolicyHashError, RuleTableError};
use zolana_transaction::TransactionError;
use zolana_tree::TreeError;

#[derive(Debug, Error)]
pub enum RingError {
    #[error(transparent)]
    Client(ClientError),
    #[error(transparent)]
    Program(#[from] CustomRingError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Rules(#[from] RuleTableError),
    #[error(transparent)]
    PolicyHash(#[from] PolicyHashError),
    #[error(transparent)]
    Audit(#[from] zolana_ring_client::AuditError),
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    DepositBuild(#[from] DepositBuildError),
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error(transparent)]
    Pool(#[from] zolana_interface::error::ShieldedPoolError),
    #[error(transparent)]
    Blocking(#[from] BlockingInsideRuntime),
    #[error("custom ring account {address} is invalid")]
    InvalidAccount { address: Address },
    #[error("custom ring config does not exist")]
    MissingRingConfig,
    #[error("the ring has no policy config")]
    MissingPolicyConfig,
    #[error("the ring has no member registry")]
    MissingMemberRegistry,
    #[error("the ring has no delegate")]
    MissingDelegate,
    #[error("the ring's delegate is {0}")]
    UnauthorizedDelegate(Address),
    #[error("the delegate moves notes on escrowed rings only")]
    DelegateRequiresEscrow,
    #[error("asset registry is required")]
    MissingAssetRegistry,
    #[error("the compiled table differs from the stored rows")]
    TableMismatch,
    #[error("the rule table does not reproduce the pinned policy hash")]
    HashMismatch,
    #[error("the stored source map breaks the positional layout")]
    InvalidSources,
    #[error("the table does not reference the list {0:?}")]
    UnreferencedList(ListId),
    #[error("the list {0:?} is both set and cleared")]
    ConflictingListWrite(ListId),
    #[error("the batch changes no record")]
    EmptyMemberBatch,
    #[error("{member:?} already registered a key")]
    KeyAlreadyRegistered { member: Member },
    #[error("curator registry {address} is not an initialized member registry root")]
    InvalidCuratorRegistry { address: Address },
    #[error("the transaction takes {bytes} bytes, a v1 transaction carries {limit}")]
    TransactionTooLarge { bytes: usize, limit: usize },
    #[error("tree account {address} is missing")]
    MissingTree { address: Address },
    #[error("tree account {address} is not a shielded pool tree")]
    InvalidTree { address: Address },
    #[error("tree {tree} has id {expected}, the transfer was prepared for {found}")]
    TreeIdMismatch {
        tree: Address,
        expected: u16,
        found: u16,
    },
    #[error("indexer returned an incomplete proof set")]
    IncompleteProofSet,
    #[error("the transfer needs more policy slots than the circuit holds")]
    PolicyShapeUnsupported,
    #[error("a policy rule refuses the transfer")]
    PolicyRuleUnsatisfied,
    #[error("the transfer uses an asset without a configured policy limit")]
    PolicyAssetUnsupported,
    #[error("dummy output framing is invalid")]
    InvalidDummyOutput,
    #[error("transfer references another ring {0}")]
    ForeignRing(Address),
    #[error("a default-ring note carries ring data")]
    RingDataOutsideRing,
    #[error("the input with nullifier {nullifier:?} is spent twice")]
    DuplicateInput { nullifier: [u8; 32] },
    #[error("inputs and outputs of {0} differ")]
    UnbalancedMove(Address),
    #[error("a delegate move settles no public leg")]
    DelegatePublicLeg,
    #[error("the transfer needs approval but names no co-signer")]
    ApprovalWithoutCoSigner,
    #[error("the outflow {outflow} of {asset:?} exceeds the cap {cap}")]
    OutflowCapExceeded {
        asset: [u8; 32],
        cap: u64,
        outflow: u64,
    },
    #[error("an outflow sum overflows")]
    OutflowOverflow,
    #[error("change of {asset:?} exceeds the mint's inputs")]
    ChangeExceedsInflow { asset: [u8; 32] },
    #[error("an escrowed ring accepts audited deposits only")]
    AuditRequired,
    #[error("an anonymous ring refuses this operation")]
    AnonymousRingRefused,
    #[error("an anonymous transfer requires the hidden Ed25519 signing key")]
    MissingAnonymousSigner,
    #[error("the ring is not anonymous, its owners sign in public")]
    NotAnonymousRing,
    #[error("the hidden signer does not match the sender")]
    AnonymousSignerMismatch,
    #[error("public transaction signers must differ from the hidden owner")]
    AnonymousPublicSignerLinksOwner,
    #[error("the hidden owner's signer refused the ring spend message")]
    AnonymousSpendSignature,
    #[error("anonymous transfers require uncached Ed25519 ring notes and noncompact inputs")]
    InvalidAnonymousSlot,
    #[error("the anonymous rail has no keys for this transaction shape")]
    AnonymousShapeUnsupported,
    #[error("anonymous outputs carry no data or ring data")]
    AnonymousOutputData,
    #[error("the anonymous disclosure does not match the transaction shape")]
    AnonymousDisclosureShape,
    #[error("an anonymous ring requires an Ed25519 recipient")]
    AnonymousRecipient,
    #[error("a published anonymous output is not a scheme-9 body of the proven length")]
    InvalidAnonymousBody,
    #[error("merge inputs belong to another tree")]
    InputTreeMismatch,
    #[error("the member's nullifier key does not derive its address")]
    NullifierKeyMismatch,
    #[error("the member record is not included under the requested root")]
    InvalidRecordOpening,
    #[error("{owner:?} enrolled no matching nullifier key")]
    UnregisteredOutputKey { owner: Member },
    #[error("hash is not below the BN254 scalar modulus")]
    NonCanonicalHash,
    #[error("the auditor key encryption proof is missing its BSB22 commitment")]
    MissingCommitment,
    #[error("a plain Groth16 proof carries a BSB22 commitment")]
    UnexpectedCommitment,
    #[error("proof is not a transact proof")]
    InvalidProof,
    #[error("{signature} failed with {error}")]
    Rejected {
        signature: Signature,
        error: solana_transaction_error::TransactionError,
    },
}

/// The prover names an unenrolled member as a registry miss.
impl From<ClientError> for RingError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::RegistryMemberMissing { member } => match Member::from_bytes(member) {
                Ok(owner) => Self::UnregisteredOutputKey { owner },
                Err(_) => Self::Client(error),
            },
            error => Self::Client(error),
        }
    }
}

impl RingError {
    /// Photon trails or passed the chain state the read was asked under.
    pub fn is_projection_lag(&self) -> bool {
        matches!(
            self,
            Self::Client(
                ClientError::IndexerProofDataNotReady
                    | ClientError::RingRegistryOutOfSync
                    | ClientError::RingRegistryRootChanged
            )
        )
    }
}
