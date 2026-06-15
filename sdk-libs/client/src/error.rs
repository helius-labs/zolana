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

    #[error("rpc error: {0}")]
    Rpc(String),
}
