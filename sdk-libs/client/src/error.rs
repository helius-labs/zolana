use solana_pubkey::Pubkey;
use thiserror::Error;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("keypair error: {0}")]
    Keypair(#[from] KeypairError),

    #[error("transaction error: {0}")]
    Transaction(#[from] TransactionError),

    #[error("poseidon hash error: {0}")]
    Hasher(String),

    #[error("no supported circuit shape holds {n_in} inputs and {n_out} outputs")]
    UnsupportedShape { n_in: usize, n_out: usize },

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

    #[error("proof path has {got} elements, expected {expected}")]
    ProofPathLength { got: usize, expected: usize },

    #[error("assembled witness has {got} input slots, expected {expected}")]
    WitnessInputCountMismatch { got: usize, expected: usize },

    #[error("deposit funding account not found: {address:?}")]
    AccountNotFound { address: [u8; 32] },

    #[error("SOL deposit funding account {sender:?} must be the signing authority")]
    DepositSenderNotSigner { sender: [u8; 32] },
}
