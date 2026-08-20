use solana_pubkey::Pubkey;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_interface::instruction::DepositBuildError;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("deposit builder error: {0}")]
    DepositBuild(#[from] DepositBuildError),

    #[error("keypair error: {0}")]
    Keypair(#[from] KeypairError),

    #[error("transaction error: {0}")]
    Transaction(#[from] TransactionError),

    #[error("hasher error: {0}")]
    Hasher(#[from] HasherError),

    /// A service URL that would carry shielded material in plaintext.
    ///
    /// The indexer's response says which UTXOs an identity owns and the
    /// prover's request carries the witness, so over plain http both are
    /// readable by anyone on the path -- that is the protocol's privacy, not a
    /// hardening detail. Use `from_urls_allowing_insecure_http` where the
    /// transport is already private.
    #[error("{field} must use https (or http to loopback): {url}")]
    InsecureServiceUrl { field: &'static str, url: String },

    #[error("no supported circuit shape holds {n_in} inputs and {n_out} outputs")]
    UnsupportedShape { n_in: usize, n_out: usize },

    #[error("spend amount must be greater than zero")]
    ZeroSpendAmount,

    #[error("too many inputs: got {got}, shape holds at most {max}")]
    TooManyInputs { got: usize, max: usize },

    #[error("too many outputs: got {got}, shape holds at most {max}")]
    TooManyOutputs { got: usize, max: usize },

    #[error("insufficient balance for asset: requested {requested}, available {available}")]
    InsufficientBalance { requested: u64, available: u64 },

    #[error("selected balance overflow")]
    SelectedBalanceOverflow,

    #[error("unsigned input {index} is no longer available in the wallet")]
    UnsignedInputUnavailable { index: usize },

    #[error("fee payer does not match the payer bound into the private transaction")]
    FeePayerMismatch,

    #[error("native Solana transaction signing failed: {0}")]
    SolanaTransactionSigning(String),

    #[error(
        "tree is required: wallet holds unspent asset {asset:?} across {tree_count} pool trees"
    )]
    AmbiguousTree {
        asset: solana_address::Address,
        tree_count: usize,
    },

    #[error("SPL token account is required for mint {mint}")]
    MissingSplTokenAccount { mint: Pubkey },

    #[error("SPL token program is required for mint {mint}")]
    MissingSplTokenProgram { mint: Pubkey },

    #[error("mint {mint} is owned by unsupported SPL token program {owner}")]
    UnsupportedSplTokenProgram { mint: Pubkey, owner: Pubkey },

    #[error("address resolution error: {0}")]
    AddressResolution(String),

    #[error(
        "interface transfers and settlement account groups must have equal lengths: {interface_transfers} transfers, {account_groups} account groups"
    )]
    SettlementTransferCountMismatch {
        interface_transfers: usize,
        account_groups: usize,
    },

    #[error("interface transfer {index} does not match its settlement account group type")]
    SettlementTransferTypeMismatch { index: usize },

    #[error("user registry record not found for {owner}: {record}")]
    UserRegistryRecordNotFound { owner: Pubkey, record: Pubkey },

    #[error("a transaction supports a single public SPL asset; got a second distinct asset")]
    MultiplePublicSplAssets,

    #[error("a transaction supports a single withdrawal")]
    WithdrawalAlreadySet,

    #[error("a transaction must spend at least one input")]
    NoInputs,

    #[error("the current tree capacity does not allow dummy input slots")]
    DummyInputsNotAllowed,

    #[error(
        "input {index} is not Solana-owned; the transfer-eddsa rail rejects P256-owned inputs"
    )]
    EddsaInputNotSolanaOwned { index: usize },

    #[error("the P256 rail requires an owner signature but none was supplied")]
    MissingP256Signature,

    #[error("a P256 registry key binding proof is required")]
    MissingRegistryP256Proof,

    #[error("a P256 registry key binding proof was supplied for an Ed25519 owner")]
    UnexpectedRegistryP256Proof,

    #[error("the P256 ring proof requires at least one real P256-owned input")]
    P256ProofWithoutP256Input,

    #[error(
        "outputs and resolved owner tags must have equal lengths: {outputs} outputs, {owner_tags} owner tags"
    )]
    OutputOwnerTagCountMismatch { outputs: usize, owner_tags: usize },

    #[error("output {index} blinding does not match the transaction seed and first nullifier")]
    OutputBlindingMismatch { index: usize },

    #[error("P256 input {index} is not owned by the supplied authorization key")]
    P256AuthorizationOwnerMismatch { index: usize },

    #[error("invalid P256 authorization: {0}")]
    InvalidP256Authorization(String),

    #[error("merge input {index} has a different signing rail than the owner; merge requires all inputs share one owner")]
    MergeInputRailMismatch { index: usize },

    #[error("merge input {index} has a different asset; merge requires a single shared asset")]
    MergeInputAssetMismatch { index: usize },

    #[error("owner {owner} has not enabled the merge service on its user-registry record")]
    MergeDisabled { owner: Pubkey },

    #[error("nothing to merge for asset {asset:?}: fewer than two plain utxos are available")]
    NothingToMerge { asset: solana_address::Address },

    #[error("merge input utxo {hash:?} was named more than once")]
    DuplicateInputUtxo { hash: [u8; 32] },

    #[error("merging keypair signing key does not match the owner's registry record")]
    MergeSigningKeyMismatch,

    #[error("merging keypair nullifier key does not match the owner's registry record")]
    MergeNullifierKeyMismatch,

    #[error("merging keypair viewing key does not match the registry record for {owner}")]
    MergeViewingKeyMismatch { owner: Pubkey },

    #[error(
        "merge proof was fetched for tree {proof_tree:?}, but the input tree is {input_tree:?}"
    )]
    MergeInputTreeMismatch {
        proof_tree: [u8; 32],
        input_tree: [u8; 32],
    },

    #[error("split amount {amount} is not divisible into {parts} equal parts")]
    SplitNotDivisible { amount: u64, parts: u8 },

    #[error("split input utxo {hash:?} is not available in the wallet")]
    InputUtxoUnavailable { hash: [u8; 32] },

    #[error(
        "input utxo {hash:?} is on tree {utxo_tree:?}, not the resolved spend tree {spend_tree:?}"
    )]
    InputUtxoTreeMismatch {
        hash: [u8; 32],
        utxo_tree: solana_address::Address,
        spend_tree: solana_address::Address,
    },

    #[error("split input utxo {hash:?} carries program or utxo data, which is not supported")]
    SplitInputHasData { hash: [u8; 32] },

    #[error("split input utxo {hash:?} is bound to a ring, which is not supported")]
    SplitInputRingMismatch { hash: [u8; 32] },

    #[error("P256-owned inputs are unsupported by transact")]
    P256TransactUnsupported,

    #[error("value exceeds 32 bytes")]
    ValueTooLong,

    #[error("prover server error: {0}")]
    ProverServer(String),

    #[error("proof parse error: {0}")]
    ProofParse(String),

    #[error("proof verification failed: {0}")]
    ProofVerification(String),

    #[error("prover process error: {0}")]
    Prover(String),

    #[error("missing input merkle proof for input {index}")]
    MissingInputMerkleProof { index: usize },

    #[error(
        "indexer returned incomplete input proofs: expected {expected}, got {state} state and {nullifier} nullifier proofs"
    )]
    IncompleteInputProofs {
        expected: usize,
        state: usize,
        nullifier: usize,
    },

    #[error("state proof {index} does not match its requested UTXO commitment")]
    StateProofLeafMismatch { index: usize },

    #[error("state proof {index} targets a different tree")]
    StateProofTreeMismatch { index: usize },

    #[error("nullifier proof {index} does not match its requested nullifier")]
    NullifierProofLeafMismatch { index: usize },

    #[error("nullifier proof {index} targets a different tree")]
    NullifierProofTreeMismatch { index: usize },

    #[error("expected {expected} input tree-index entries, got {actual}")]
    InputTreeIndexCountMismatch { expected: usize, actual: usize },

    #[error("transaction has no output slots")]
    MissingOutput,

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("Solana RPC transaction failed during {operation}: {source}")]
    SolanaRpcTransaction {
        operation: &'static str,
        #[source]
        source: solana_rpc_client_api::client_error::Error,
    },

    #[error("indexer error: {0}")]
    Indexer(String),

    /// The indexer answered with a rate-limit or internal JSON-RPC error.
    /// Acted on by `Rpc::should_retry` during the confirmation poll.
    #[error("indexer temporarily unavailable: {0}")]
    IndexerUnavailable(String),

    #[error("rpc backend does not implement method `{0}`")]
    UnsupportedRpcMethod(&'static str),

    #[error("indexer did not observe the transaction before the poll timeout")]
    IndexerTimeout,

    #[error("indexer did not reach slot {required} within {attempts} attempts; highest indexed slot is {indexed}")]
    IndexerNotCaughtUp {
        required: u64,
        indexed: u64,
        attempts: u32,
    },

    #[error("poll gave up after {attempts} attempts; last transient error: {last_error:?}")]
    PollTimedOut {
        attempts: u32,
        last_error: Option<String>,
    },

    #[error("proof path has {got} elements, expected {expected}")]
    ProofPathLength { got: usize, expected: usize },

    #[error("assembled witness has {got} input slots, expected {expected}")]
    WitnessInputCountMismatch { got: usize, expected: usize },

    #[error("deposit funding account not found: {address:?}")]
    AccountNotFound { address: [u8; 32] },

    #[error("SOL deposit funding account {sender:?} must be the signing authority")]
    DepositSenderNotSigner { sender: [u8; 32] },
}

impl ClientError {
    pub fn for_signature(self, signature: &solana_signature::Signature) -> Self {
        match self {
            Self::Rpc(message) => Self::Rpc(format!("{signature}: {message}")),
            other => other,
        }
    }
}
