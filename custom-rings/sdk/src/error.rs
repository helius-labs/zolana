use custom_ring_interface::{key_catalog::RingCircuit, CustomRingError, RingRail};
use solana_address::Address;
use solana_signature::Signature;
use thiserror::Error;
use zolana_client::{BlockingInsideRuntime, ClientError};
use zolana_hasher::HasherError;
use zolana_interface::error::ShieldedPoolError;
use zolana_interface::instruction::instruction_data::PublicSlotError;
use zolana_keypair::{KeypairError, X25519Pubkey};
use zolana_program::instruction::DepositBuildError;
use zolana_ring_member_registry::RecordTreeError;
use zolana_ring_policy::{
    ListId, Member, MemberError, PolicyTableError, RuleRefusal, RuleTableError, SourceMapError,
    Writer,
};
use zolana_transaction::TransactionError;
use zolana_tree::TreeError;

#[derive(Debug, Error)]
pub enum RingError {
    #[error(transparent)]
    Client(#[from] ClientError),
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
    PolicyTable(#[from] PolicyTableError),
    #[error(transparent)]
    SourceMap(#[from] SourceMapError),
    #[error(transparent)]
    PublicSlots(#[from] PublicSlotError),
    #[error(transparent)]
    Records(#[from] RecordTreeError),
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
    Pool(#[from] ShieldedPoolError),
    #[error(transparent)]
    Blocking(#[from] BlockingInsideRuntime),
    #[error("custom ring account {address} is invalid")]
    InvalidAccount { address: Address },
    #[error("custom ring config does not exist")]
    MissingRingConfig,
    #[error("the ring has no member registry")]
    MissingMemberRegistry,
    #[error("the ring has no record queue")]
    MissingRecordQueue,
    #[error("the ring is not registered with the shielded pool, run InitSppRingConfig")]
    RingNotRegistered,
    #[error("the shielded pool has not activated the ring, governance runs set_ring_activation")]
    RingNotActivated,
    #[error("the ring is paused")]
    RingPaused,
    #[error("the ring has no delegate")]
    MissingDelegate,
    #[error("the delegate moves notes on escrowed policy rings only")]
    DelegateRequiresEscrow,
    #[error("asset registry is required")]
    MissingAssetRegistry,
    #[error("the compiled table differs from the stored rows")]
    TableMismatch,
    #[error("the rule table does not reproduce the pinned policy hash")]
    HashMismatch,
    #[error("the table does not reference the list {0:?}")]
    UnreferencedList(ListId),
    #[error("curator registry {address} is not an initialized member registry")]
    InvalidCuratorRegistry { address: Address },
    #[error("the write names member {member:?} twice")]
    DuplicateListWrite { member: Member },
    #[error("the write changes no list")]
    EmptyListWrite,
    #[error("the {writer:?} writer may not write the list {list:?}")]
    ListNotWritable { list: ListId, writer: Writer },
    #[error("{writes} authority writes take {batches} batches beside {pending} pending, prove each batch after the one before lands")]
    AuthorityBatchSplit {
        writes: usize,
        pending: u64,
        batches: usize,
    },
    #[error("no application of the record queue is due")]
    ApplicationNotDue,
    #[error(
        "the indexer's record queue or registry differs from the chain's, the projection lags"
    )]
    RecordProjectionStale,
    #[error("{member:?} already registered a key")]
    KeyAlreadyRegistered { member: Member },
    #[error("the transaction takes {bytes} bytes, a v1 transaction carries {limit}")]
    TransactionTooLarge { bytes: usize, limit: usize },
    #[error("the transaction names {addresses} addresses, a v1 transaction carries {limit}")]
    TooManyAddresses { addresses: usize, limit: usize },
    #[error("no tree holds {amount} of {mint} in {max_inputs} inputs")]
    Unfunded {
        mint: Address,
        amount: u64,
        max_inputs: usize,
    },
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
    #[error("the indexer's root of first-contact tree {tree} at {root_index} is not the chain's")]
    FirstContactRootStale { tree: Address, root_index: u16 },
    #[error(
        "the indexer gives no valid proof of the pinned leaves of first-contact tree {tree}, retire the first contact"
    )]
    FirstContactLeavesRefused {
        tree: Address,
        recipient: X25519Pubkey,
    },
    #[error("the transfer needs a shape no {rail:?} key serves")]
    ShapeUnkeyed { rail: RingRail },
    #[error("ring output {slot} names no key its body opens under")]
    UndeliveredRingOutput { slot: usize },
    #[error("the policy refuses the transfer, {0}")]
    PolicyRuleUnsatisfied(#[from] RuleRefusal),
    #[error("transfer references another ring {0}")]
    ForeignRing(Address),
    #[error("a default-ring note carries ring data")]
    RingDataOutsideRing,
    #[error("the input with nullifier {nullifier:?} is spent twice")]
    DuplicateInput { nullifier: [u8; 32] },
    #[error("the transfer spends one owner's notes, input {index} has another owner")]
    MixedOwners { index: usize },
    #[error("the outflow {outflow} of {asset:?} exceeds the cap {cap}")]
    OutflowCapExceeded {
        asset: [u8; 32],
        cap: u64,
        outflow: u64,
    },
    #[error("an outflow sum overflows")]
    OutflowOverflow,
    #[error("a public deposit of {asset:?} exceeds what leaves the sender")]
    DepositAboveOutflow { asset: [u8; 32] },
    #[error("the compact transfer expands to external data the SPP proof does not bind")]
    ExternalDataMismatch,
    #[error("the proof binds epoch {proof_epoch}, the chain is at epoch {current_epoch}")]
    EpochPassed {
        proof_epoch: u64,
        current_epoch: u64,
    },
    #[error("an anonymous merge of {width} slots does not fit a v1 transaction")]
    AnonymousMergeTooWide { width: usize },
    #[error("the ring is not anonymous, its owners sign in public")]
    NotAnonymousRing,
    #[error("an anonymous ring spends only through the hidden owner's proof")]
    MissingAnonymousSigner,
    #[error("a default-ring spend of {inputs} inputs fits no entry key, split the transfer")]
    DefaultRingSpendTooWide { inputs: usize },
    #[error("a default-ring spend opens every input in full, input {index} carries data")]
    EntryInputData { index: usize },
    #[error("the hidden signer does not match the sender")]
    AnonymousSignerMismatch,
    #[error("public transaction signers must differ from the hidden owner")]
    AnonymousPublicSignerLinksOwner,
    #[error("withdrawal destination {0} names the hidden owner")]
    AnonymousExitLinksOwner(Address),
    #[error("withdrawal token account {0} has a delegate or a close authority")]
    AnonymousExitTokenAccountShared(Address),
    #[error("withdrawal token account {0} is at a keypair address, SPP takes an ATA or a PDA")]
    AnonymousExitTokenAccountOnCurve(Address),
    #[error("withdrawal destination {0} is not a system account without data")]
    AnonymousExitAccountHasData(Address),
    #[error("withdrawal token account {0} is missing or not an initialized account of its mint")]
    AnonymousExitTokenAccountInvalid(Address),
    #[error(
        "withdrawal token account {token_account} is owned by {owner}, the transfer names {named}"
    )]
    AnonymousExitNamedOwnerMismatch {
        token_account: Address,
        named: Address,
        owner: Address,
    },
    #[error("withdrawal destination {destination} is refused, {refusal}")]
    AnonymousExitRefused {
        destination: Address,
        refusal: ShieldedPoolError,
    },
    #[error("the hidden owner's signer refused the ring spend message")]
    AnonymousSpendSignature,
    #[error("anonymous transfers require uncached Ed25519 ring notes and noncompact inputs")]
    InvalidAnonymousSlot,
    #[error("an anonymous ring requires an Ed25519 recipient")]
    AnonymousRecipient,
    #[error("ring address {address} pays into ring {ring}, the transfer runs in another")]
    ForeignRingAddress { address: Address, ring: Address },
    #[error("the anonymous ring state tracks ring {state}, the deposit pays ring {ring}")]
    ForeignRingState { state: Address, ring: Address },
    #[error("merge inputs belong to another tree")]
    InputTreeMismatch,
    #[error("the member's nullifier key does not derive its address")]
    NullifierKeyMismatch,
    #[error("the member record is not included under the requested root")]
    InvalidRecordOpening,
    #[error("{owner:?} enrolled no matching nullifier key")]
    UnregisteredOutputKey { owner: Member },
    #[error("the ring key set has no verifying key for {0:?}")]
    MissingVerifyingKey(RingCircuit),
    #[error("no ring key serves {0:?}")]
    UncataloguedCircuit(RingCircuit),
    #[error("no pinned proving key for {0:?}")]
    UnpinnedProvingKey(RingCircuit),
    #[error("the auditor key encryption proof is missing its BSB22 commitment")]
    MissingCommitment,
    #[error("{signature} failed with {error}")]
    Rejected {
        signature: Signature,
        error: solana_transaction_error::TransactionError,
    },
}

impl From<custom_ring_interface::stream::StreamError> for RingError {
    fn from(error: custom_ring_interface::stream::StreamError) -> Self {
        Self::Transaction(error.into())
    }
}

impl RingError {
    /// Photon trails or passed the chain state the read was asked under.
    pub fn is_projection_lag(&self) -> bool {
        matches!(
            self,
            Self::RecordProjectionStale
                | Self::FirstContactRootStale { .. }
                | Self::Client(
                    ClientError::IndexerProofDataNotReady
                        | ClientError::RingRegistryOutOfSync
                        | ClientError::RingRegistryRootChanged
                        | ClientError::RingRecordQueueChanged
                )
        )
    }
}
