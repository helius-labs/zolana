use solana_address::Address;
use thiserror::Error;
use zolana_keypair::KeypairError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionError {
    #[error("unexpected discriminator: {0}")]
    BadDiscriminator(u8),

    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("serialization failed: {0}")]
    Serialize(String),

    #[error("deserialization failed: {0}")]
    Deserialize(String),

    #[error("unknown asset id: {0}")]
    UnknownAsset(u64),

    #[error("unknown mint: {0}")]
    UnknownMint(Address),

    #[error("reserved asset id: {0}")]
    ReservedAssetId(u64),

    #[error("duplicate asset id: {0}")]
    DuplicateAssetId(u64),

    #[error("duplicate mint: {0}")]
    DuplicateMint(Address),

    #[error("data attached to an output with zero amount")]
    DataWithoutOutput,

    #[error("too many outputs to derive blinding positions")]
    TooManyOutputs,

    #[error("duplicate data record")]
    DuplicateDataRecord,

    #[error("data records out of canonical order")]
    NonCanonicalDataOrder,

    #[error("ring data present without ring program id")]
    MissingRingProgramId,

    #[error("program/ring data on this output cannot be processed yet")]
    UnsupportedOutputData,

    #[error("poseidon hash failed: {0}")]
    Poseidon(String),

    #[error("hash failed: {0}")]
    Hash(String),

    #[error("transaction has no output slots")]
    MissingOutput,

    #[error("output slot count mismatch: {got} ciphertext(s) for {expected} output(s)")]
    OutputSlotCountMismatch { got: usize, expected: usize },

    #[error("plaintext output {index} has an out-of-order, duplicate or gapped slot {position}")]
    InvalidPlaintextOutputPosition { index: usize, position: u32 },

    #[error("output slot {slot_index} carries no owner address to encrypt to")]
    OutputWithoutOwner { slot_index: usize },

    #[error("output slot {slot_index} is encrypted to an owner other than the one it publishes")]
    OwnerTagMismatch { slot_index: usize },

    #[error("missing encryption context for scheme")]
    MissingEncryptionContext,

    #[error("output blinding derivation requires the transaction's first nullifier")]
    MissingFirstNullifier,

    #[error("transaction has no inputs")]
    NoInputs,

    #[error("input {index} has UTXO data without a data hash")]
    MissingInputDataHash { index: usize },

    #[error("input {index} has ring data without a ring data hash")]
    MissingInputRingDataHash { index: usize },

    #[error("input {index} does not match its published commitment")]
    InputCommitmentMismatch { index: usize },

    /// The input slots are final at construction, so a caller that has not
    /// padded to the shape's input count is refused rather than padded for.
    #[error("shape declares {expected} input slot(s), got {got}")]
    InputCountMismatch { got: usize, expected: usize },

    /// Slot 0's nullifier seeds every output blinding, the private-transaction
    /// blinding and the transaction viewing key, so a dummy there moves all of
    /// them consistently and nothing fails until the circuit disagrees.
    #[error("input slot 0 must be a real input utxo, not padding")]
    DummyInFirstInputSlot,

    /// Padding is hashed under a declared input tree. A dummy naming any other
    /// tree is a caller mistake: its commitment and nullifier both fold the tree
    /// id in, so it cannot be relabelled after the fact.
    #[error("input padding at slot {index} names tree {tree_id}, which no real input declares")]
    PaddingInUndeclaredTree { index: usize, tree_id: u16 },

    /// The shielded side and the public side do not cancel for one asset once
    /// the change slots exist.
    #[error("transaction does not balance for asset {asset}")]
    TransactionDoesNotBalance { asset: Address },

    #[error("output slots are already padded to the shape")]
    OutputUtxosAlreadyPadded,

    #[error("cache slot {slot} is out of range, a cache holds slots 0..36")]
    CacheSlotOutOfRange { slot: u8 },

    #[error("a padding input cannot be read from a cache")]
    CachedDummyInput,

    #[error("a padding output cannot be written to a cache")]
    CachedDummyOutput,

    #[error("inputs span {got} trees, a proof resolves roots for at most {max}")]
    TooManyInputTrees { got: usize, max: usize },

    #[error("input {index} returns to tree {tree_id}; group inputs by tree before signing")]
    InterleavedInputTrees { index: usize, tree_id: u16 },

    #[error("too many interface transfers: got {got}, max {max}")]
    TooManyInterfaceTransfers { got: usize, max: usize },

    #[error("public settlement requires at least one interface transfer")]
    NoInterfaceTransfers,

    #[error("interface transfer amount must be nonzero")]
    ZeroInterfaceTransferAmount,

    #[error("interface transfers for asset {asset} must not net to zero")]
    ZeroNetInterfaceTransferAmount { asset: Address },

    #[error("settlement target type does not match asset {asset}")]
    SettlementTargetMismatch { asset: Address },

    #[error("expected an SPL mint; use the SOL-specific method for SOL")]
    ExpectedSplMint,

    #[error("public transfer sum overflow for asset {asset}")]
    PublicTransferOverflow { asset: Address },

    #[error("too many active public assets: got {got}, max {max}")]
    TooManyPublicAssets { got: usize, max: usize },

    #[error("ring hashes already set")]
    RingHashesAlreadySet,

    #[error("too many transaction assets: got {got}, max {max}")]
    TooManyAssets { got: usize, max: usize },

    #[error("default transact supports Ed25519 owners only")]
    P256TransactUnsupported,

    #[error("insufficient balance: requested {requested}, available {available}")]
    InsufficientBalance { requested: u64, available: u64 },

    #[error("unsupported proof shape: {n_in} input(s), {n_out} output(s)")]
    UnsupportedShape { n_in: usize, n_out: usize },

    #[error("too many inputs: got {got}, max {max}")]
    TooManyInputs { got: usize, max: usize },

    #[error("too many outputs: got {got}, max {max}")]
    TooManyOutputsForShape { got: usize, max: usize },

    #[error("merge input {index} has a different owner rail")]
    MergeInputRailMismatch { index: usize },

    #[error("merge input {index} has a different owner than the merging keypair")]
    MergeInputOwnerMismatch { index: usize },

    #[error("merge input {index} has a different nullifier key than the merging keypair")]
    MergeInputNullifierKeyMismatch { index: usize },

    #[error("merge input {index} has a different asset")]
    MergeInputAssetMismatch { index: usize },

    #[error("merge input {index} has a different ring program id")]
    MergeInputRingMismatch { index: usize },

    #[error("selected balance overflow")]
    SelectedBalanceOverflow,

    #[error("merge input {index} carries program or ring data, which is not supported")]
    MergeInputHasData { index: usize },

    #[error("p256 error: {0}")]
    P256(String),

    #[error("keypair error: {0}")]
    Keypair(#[from] KeypairError),

    #[error("wallet authority identity does not match the wallet")]
    WalletAuthorityMismatch,

    #[error("wallet authority did not provide its current viewing key")]
    MissingCurrentViewingKey,

    /// Raised when the authority is built, not when it is used, so it is
    /// distinct from [`Self::MissingCurrentViewingKey`]: that one means a scan
    /// was handed a snapshot without the current key.
    #[error("viewing keys do not include the keypair's own, so this authority would encrypt to one key and scan with another")]
    AuthorityViewingKeyMismatch,

    /// A request named a viewing key this holder does not have. Distinct from
    /// [`Self::AuthorityViewingKeyMismatch`], which is raised when the holder is
    /// built rather than when it is asked for something.
    #[error("no viewing key held matches the one the request names")]
    UnknownViewingKey,

    /// The seed is the right width but is not a valid signature over the
    /// canonical derivation message for this key, so it cannot be the seed this
    /// wallet's roles expand from. Distinct from
    /// [`zolana_keypair::KeypairError::InvalidDerivationSeed`], which is a
    /// wrong-width seed.
    #[error("derivation seed is not a valid signature over the derivation message for this key")]
    InvalidDerivationSeed,

    /// A key holder answered a derivation batch with fewer values than it was
    /// asked for. Keys held in this process answer one per request; only a
    /// remote holder can come up short.
    #[error("key holder answered {got} of {want} derivation request(s)")]
    IncompleteDerivation { got: usize, want: usize },

    #[error("key holder returned {got} plaintext(s), expected {want}")]
    IncompleteDecryption { got: usize, want: usize },

    #[error("wallet authority error: {0}")]
    Authority(String),
}

impl From<zolana_hasher::HasherError> for TransactionError {
    fn from(e: zolana_hasher::HasherError) -> Self {
        TransactionError::Keypair(KeypairError::Poseidon(e.into()))
    }
}

impl From<wincode::WriteError> for TransactionError {
    fn from(e: wincode::WriteError) -> Self {
        TransactionError::Serialize(e.to_string())
    }
}

impl From<wincode::ReadError> for TransactionError {
    fn from(e: wincode::ReadError) -> Self {
        TransactionError::Deserialize(e.to_string())
    }
}
