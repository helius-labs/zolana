use solana_pubkey::Pubkey;
use solana_signature::Signature;
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

    #[error("balance of {available} covers {requested} but is too fragmented: no subset of at most {max_inputs} UTXO(s) fits a supported shape")]
    ShapeExceeded {
        requested: u64,
        available: u64,
        max_inputs: usize,
    },

    #[error("selected balance overflow")]
    SelectedBalanceOverflow,

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

    #[error("expected {expected} input tree-index entries, got {actual}")]
    InputTreeIndexCountMismatch { expected: usize, actual: usize },

    #[error("transaction has no output slots")]
    MissingOutput,

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("rpc backend does not implement method `{0}`")]
    UnsupportedRpcMethod(&'static str),

    #[error("proof path has {got} elements, expected {expected}")]
    ProofPathLength { got: usize, expected: usize },

    #[error("assembled witness has {got} input slots, expected {expected}")]
    WitnessInputCountMismatch { got: usize, expected: usize },

    #[error("deposit funding account not found: {address:?}")]
    AccountNotFound { address: [u8; 32] },

    #[error("deposit {signature} confirmed but its UTXO {utxo_hash:?} was not indexed after 120s")]
    DepositNotIndexed {
        utxo_hash: [u8; 32],
        signature: Signature,
    },

    #[error(
        "transaction {signature} confirmed but was not indexed after {timeout_seconds} seconds"
    )]
    TransactionNotIndexed {
        signature: Signature,
        timeout_seconds: u64,
    },

    #[error("asset registry entry not found for mint {mint}; the mint has no SPL interface on this deployment")]
    AssetNotRegistered { mint: Pubkey },

    #[error("SOL deposit funding account {sender:?} must be the signing authority")]
    DepositSenderNotSigner { sender: [u8; 32] },
}
