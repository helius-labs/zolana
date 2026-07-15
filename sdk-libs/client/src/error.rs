use solana_pubkey::Pubkey;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("keypair error: {0}")]
    Keypair(#[from] KeypairError),

    #[error("transaction error: {0}")]
    Transaction(#[from] TransactionError),

    #[error("hasher error: {0}")]
    Hasher(#[from] HasherError),

    #[error("no supported circuit shape holds {n_in} inputs and {n_out} outputs")]
    UnsupportedShape { n_in: usize, n_out: usize },

    #[error("too many inputs: got {got}, shape holds at most {max}")]
    TooManyInputs { got: usize, max: usize },

    #[error("too many outputs: got {got}, shape holds at most {max}")]
    TooManyOutputs { got: usize, max: usize },

    #[error("insufficient balance for asset: requested {requested}, available {available}")]
    InsufficientBalance { requested: u64, available: u64 },

    #[error("transaction amount must be greater than zero")]
    InvalidAmount,

    #[error(
        "private transaction authorization expired at {expiry_unix_ts}; current time is {now_unix_ts}"
    )]
    PrivateTransactionExpired {
        expiry_unix_ts: u64,
        now_unix_ts: u64,
    },

    #[error("system clock error: {0}")]
    Clock(String),

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

    #[error("private transaction targets tree {transaction_tree:?}, but the client uses {client_tree:?}")]
    TreeMismatch {
        transaction_tree: [u8; 32],
        client_tree: [u8; 32],
    },

    #[error("SPL token account is required for mint {mint}")]
    MissingSplTokenAccount { mint: Pubkey },

    #[error("address resolution error: {0}")]
    AddressResolution(String),

    #[error("user registry record not found for {owner}: {record}")]
    UserRegistryRecordNotFound { owner: Pubkey, record: Pubkey },

    #[error("a transaction supports a single public SPL asset; got a second distinct asset")]
    MultiplePublicSplAssets,

    #[error("a transaction supports a single withdrawal")]
    WithdrawalAlreadySet,

    #[error("a transaction must spend at least one input")]
    NoInputs,

    #[error(
        "input {index} is not Solana-owned; the transfer-eddsa rail rejects P256-owned inputs"
    )]
    EddsaInputNotSolanaOwned { index: usize },

    #[error("the P256 rail requires an owner signature but none was supplied")]
    MissingP256Signature,

    #[error("merge input {index} has a different signing rail than the owner; merge requires all inputs share one owner")]
    MergeInputRailMismatch { index: usize },

    #[error("merge input {index} has a different asset; merge requires a single shared asset")]
    MergeInputAssetMismatch { index: usize },

    #[error("p256 signature error: {0}")]
    P256Signature(String),

    #[error("field element exceeds 32 bytes")]
    FieldTooLong,

    #[error("prover server error: {0}")]
    ProverServer(String),

    #[error("proof parse error: {0}")]
    ProofParse(String),

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

    #[error("indexer error: {0}")]
    Indexer(String),

    #[error("rpc backend does not implement method `{0}`")]
    UnsupportedRpcMethod(&'static str),

    #[error("indexer did not observe the transaction before the poll timeout")]
    IndexerTimeout,

    #[error("indexer did not reach block_time {target} within {attempts} attempts; latest indexed block_time is {latest}")]
    IndexerNotCaughtUp {
        target: i64,
        latest: i64,
        attempts: u32,
    },

    #[error("Solana signature {signature} did not reach the requested commitment before timeout")]
    RpcConfirmationTimeout {
        signature: solana_signature::Signature,
    },

    #[error("Solana transaction {signature} failed: {error}")]
    SolanaExecutionFailed {
        signature: solana_signature::Signature,
        error: String,
    },

    #[error(
        "transaction blockhash expired at block height {last_valid_block_height}; current height is {current_block_height}"
    )]
    BlockhashExpired {
        last_valid_block_height: u64,
        current_block_height: u64,
    },

    #[error("indexer pagination cursor repeated; refusing to loop")]
    PaginationCycle,

    #[error("indexer pagination exceeded the safe page limit of {max_pages}")]
    PaginationPageLimit { max_pages: usize },

    #[error("proof path has {got} elements, expected {expected}")]
    ProofPathLength { got: usize, expected: usize },

    #[error("assembled witness has {got} input slots, expected {expected}")]
    WitnessInputCountMismatch { got: usize, expected: usize },

    #[error("deposit funding account not found: {address:?}")]
    AccountNotFound { address: [u8; 32] },

    #[error("SOL deposit funding account {sender:?} must be the signing authority")]
    DepositSenderNotSigner { sender: [u8; 32] },
}
