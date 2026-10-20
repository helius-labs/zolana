use solana_address::Address;
use thiserror::Error;
use zolana_keypair::KeypairError;

/// Why an address input was refused. An address slot carries only a Solana
/// signing owner and a canonical seed (its blinding), hashed under the address
/// domain with a zero nullifier key; every other field must be empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AddressInputError {
    #[error("the slot is not an address input")]
    NotAnAddress,
    #[error("the address has no owner")]
    MissingOwner,
    #[error("the seed is not a canonical BN254 scalar")]
    NonCanonicalSeed,
    #[error("the nullifier pubkey is not the zero nullifier key's")]
    NonZeroNullifierKey,
    #[error("the amount is not zero")]
    NonZeroAmount,
    #[error("the asset is not the zero (SOL) mint")]
    NonZeroAsset,
    #[error("the address carries data")]
    CarriesData,
    #[error("the address carries a ring binding")]
    CarriesRing,
    #[error("an address cannot be compact padding")]
    Compact,
    #[error("an address cannot be read from a cache slot")]
    CacheSlot,
    #[error("the leaf index is not zero")]
    NonZeroLeafIndex,
    #[error("the UTXO hash does not match the address derivation")]
    HashMismatch,
    #[error("the nullifier does not match the address derivation")]
    NullifierMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionError {
    #[error("invalid address input: {0}")]
    InvalidAddressInput(AddressInputError),
    #[error(
        "no owner signer or real output owner can name the padding outputs, and the outputs are fixed"
    )]
    NoDummyOwnerTagParticipant,
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

    #[error("dummy output slot {slot_index} carries no owner tag to publish")]
    DummyOutputWithoutOwnerTag { slot_index: usize },

    #[error("output slot {slot_index} is encrypted to an owner other than the one it publishes")]
    OwnerTagMismatch { slot_index: usize },

    #[error("anonymous output slot {slot_index} pays a recipient with no view tag and pair key")]
    UnknownAnonymousRecipient { slot_index: usize },

    #[error("anonymous payment slot {slot_index} holds no ring output")]
    AnonymousPaymentSlot { slot_index: usize },

    #[error(
        "ring transfer output {index} has an encryption marker incompatible with its ring binding"
    )]
    RingOutputMarkerMismatch { index: usize },

    #[error("non-canonical BN254 scalar encoding")]
    NonCanonicalField,
    #[error("owner tag count mismatch: {got} owner tag(s) for {expected} output(s)")]
    OwnerTagCountMismatch { got: usize, expected: usize },

    #[error("the keys do not hold the sender the transaction was finalized for")]
    SenderAddressMismatch,

    #[error("missing encryption context for scheme")]
    MissingEncryptionContext,

    #[error("merge output ciphertext element {index} is not canonical")]
    NonCanonicalMergeCiphertext { index: usize },

    #[error("merge output plaintext element {index} is out of range")]
    InvalidMergeOutputPlaintext { index: usize },

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

    #[error("input slot {index} is real but follows padding; padding inputs must come last")]
    RealInputAfterDummy { index: usize },

    #[error("output slot {index} is real but follows a dummy; dummy outputs must come last")]
    RealOutputAfterDummy { index: usize },

    #[error("input slot {index} follows compact padding; compact padding must come last")]
    InputAfterCompactPadding { index: usize },

    #[error("output slot {index} follows compact padding; compact padding must come last")]
    OutputAfterCompactPadding { index: usize },

    #[error("{sent} sent merge inputs select a different circuit than the {width}-input merge")]
    CompactMergeWidthMismatch { sent: usize, width: usize },

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

    #[error("output {index} is the cache write beyond the {max} a transact holds")]
    TooManyCacheWrites { index: usize, max: usize },

    #[error("output {index} writes cache slot {slot}, which an earlier output already writes")]
    DuplicateCacheWriteSlot { index: usize, slot: u8 },

    #[error("output {index} names a cache slot, but the transaction writes no cache")]
    CachedOutputWithoutWriteCache { index: usize },

    #[error("the transaction names a write cache, but no output is written to it")]
    UnusedWriteCache,

    #[error("inputs span {got} trees, a proof resolves roots for at most {max}")]
    TooManyInputTrees { got: usize, max: usize },

    #[error("a spend needs a positive amount")]
    ZeroSpendAmount,

    #[error("no spendable balance of {asset}")]
    NoSpendableBalance { asset: Address },

    #[error("{amount} needs more than {max_inputs} UTXOs; merge first")]
    SpendNeedsMerge { amount: u64, max_inputs: usize },

    #[error("{amount} needs UTXOs that are excluded from this spend")]
    SpendNeedsExcludedUtxos { amount: u64 },

    #[error("nothing to merge for asset {asset}: fewer than two plain UTXOs on one tree")]
    NothingToMerge { asset: Address },

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

    #[error("SPL mint {mint} needs its token program")]
    MissingSplTokenProgram { mint: Address },

    #[error("SOL has no token program, got {token_program}")]
    UnexpectedSolTokenProgram { token_program: Address },

    #[error("public transfer sum overflow for asset {asset}")]
    PublicTransferOverflow { asset: Address },

    #[error("too many active public assets: got {got}, max {max}")]
    TooManyPublicAssets { got: usize, max: usize },

    #[error("ring hashes already set")]
    RingHashesAlreadySet,

    #[error("too many transaction assets: got {got}, max {max}")]
    TooManyAssets { got: usize, max: usize },

    #[error("recipient owner key is the zero dummy marker")]
    ZeroRecipientOwner,

    #[error("insufficient balance: requested {requested}, available {available}")]
    InsufficientBalance { requested: u64, available: u64 },

    #[error("unsupported proof shape: {n_in} input(s), {n_out} output(s)")]
    UnsupportedShape { n_in: usize, n_out: usize },

    #[error("too many inputs: got {got}, max {max}")]
    TooManyInputs { got: usize, max: usize },

    #[error("too many outputs: got {got}, max {max}")]
    TooManyOutputsForShape { got: usize, max: usize },

    #[error("merge input {index} has a different owner than the merging keypair")]
    MergeInputOwnerMismatch { index: usize },

    #[error("merge input {index} has a different nullifier key than the merging keypair")]
    MergeInputNullifierKeyMismatch { index: usize },

    #[error("merge input {index} has a different asset")]
    MergeInputAssetMismatch { index: usize },

    #[error("merge input {index} is on another tree; a merge spends the UTXOs of one tree")]
    MergeInputTreeMismatch { index: usize },

    #[error("merge input {index} has a different ring program id")]
    MergeInputRingMismatch { index: usize },

    #[error("merge input {index} has a different committed ring data hash")]
    MergeInputRingDataMismatch { index: usize },

    #[error("merge output must preserve the inputs' committed ring data hash")]
    MergeOutputRingDataMismatch,

    #[error("merge asset identity must be nonzero")]
    ZeroMergeAsset,

    #[error("selected balance overflow")]
    SelectedBalanceOverflow,

    #[error("merge input {index} carries data unsupported by this merge rail")]
    MergeInputHasData { index: usize },

    #[error("keypair error: {0}")]
    Keypair(#[from] KeypairError),

    #[error("wallet authority identity does not match the wallet")]
    WalletAuthorityMismatch,

    #[error("wallet authority did not provide its current viewing key")]
    MissingCurrentViewingKey,

    #[error("the first input has no synced transaction viewing key")]
    MissingSyncedTransactionKey,

    /// Raised when the authority is built, not when it is used, so it is
    /// distinct from [`Self::MissingCurrentViewingKey`]: that one means a scan
    /// was handed a snapshot without the current key.
    #[error("viewing keys do not include the keypair's own, so this authority would encrypt to one key and scan with another")]
    AuthorityViewingKeyMismatch,

    #[error("anonymous view tags were derived from another wallet's viewing key")]
    AnonymousViewTagsSenderMismatch,

    #[error("anonymous output {slot_index} carries data records, the fixed body has no room")]
    AnonymousOutputData { slot_index: usize },

    #[error(
        "anonymous output {slot_index} is compact padding, every slot of the shape is published"
    )]
    AnonymousCompactPadding { slot_index: usize },

    #[error("anonymous outputs {first} and {second} publish one tag")]
    DuplicateAnonymousTag { first: usize, second: usize },

    #[error("the transaction key already sealed other anonymous outputs in this session")]
    AnonymousStreamReuse,

    #[error("anonymous slot {slot_index} exceeds the 255 slots a change tag indexes")]
    AnonymousSlotIndex { slot_index: usize },

    #[error(transparent)]
    AnonymousOutput(#[from] custom_ring_interface::AnonymousOutputError),

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

impl From<AddressInputError> for TransactionError {
    fn from(e: AddressInputError) -> Self {
        Self::InvalidAddressInput(e)
    }
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
