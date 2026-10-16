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
    #[error("the ring has no key registry")]
    MissingKeyRegistry,
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
    #[error("no content of the list {0:?} recovers the commitment")]
    InvalidContent(ListId),
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
    #[error("the indexer proved one tree's entries against more than one root")]
    PolicyRootMismatch,
    #[error("the entries live in {count} trees, a statement reads at most {max}", max = zolana_interface::INPUT_TREES)]
    TooManyPolicyTrees { count: usize },
    #[error("the transfer needs more policy slots than the circuit holds")]
    PolicyShapeUnsupported,
    #[error("a policy rule refuses the transfer")]
    PolicyRuleUnsatisfied,
    #[error("the transfer uses an asset without a configured policy limit")]
    PolicyAssetUnsupported,
    #[error("no policy source serves the list")]
    MissingSourceOwner,
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
    #[error("entry version overflows")]
    VersionOverflow,
    #[error("indexer returned no proof for the entry")]
    MissingProof,
    #[error("the spend of the {list_id:?} entry published no version {version}")]
    BrokenLineage {
        list_id: ListId,
        member: [u8; 32],
        version: u64,
    },
    #[error("a lineage walk passed its version or page bound")]
    LineageBound,
    #[error("a lineage revisits a spent version")]
    LineageCycle,
    #[error("a lineage published version {version} out of order")]
    LineageStalled { version: u64 },
    #[error("revocation slot {slot} names policy tree {index}, the statement reads {trees} trees")]
    RevocationTree {
        slot: usize,
        index: u8,
        trees: usize,
    },
    #[error("an escrowed ring accepts audited deposits only")]
    AuditRequired,
    #[error("merge inputs belong to another tree")]
    InputTreeMismatch,
    #[error("the member's nullifier key does not derive its address")]
    NullifierKeyMismatch,
    #[error("the key-registry response does not match the requested root or member")]
    InvalidRegisterProof,
    #[error("the key-registry entry is not included under the requested root")]
    InvalidEntryProof,
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
                    | ClientError::RingKeyRegistryOutOfSync
                    | ClientError::RingKeyRegistryRootChanged
            )
        )
    }
}
