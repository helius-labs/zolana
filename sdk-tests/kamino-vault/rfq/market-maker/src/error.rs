use kamino_vault_rfq_sdk::budget::BudgetError;
use solana_address::Address;
use solana_signer::SignerError;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;

use super::step::StepId;

#[derive(Debug, Error)]
pub enum MakerError {
    #[error("{asset} balance {available} minus queued operations cannot cover {requested}")]
    InsufficientBalance {
        asset: Address,
        available: u64,
        requested: u64,
    },

    #[error("{asset} lanes hold {available} but no {max_inputs} of them cover {requested}")]
    FragmentedInventory {
        asset: Address,
        available: u64,
        requested: u64,
        max_inputs: usize,
    },

    #[error("{asset} has no fragments to consolidate")]
    NothingToConsolidate { asset: Address },

    #[error("operation amount is zero")]
    AmountZero,

    #[error("operation failed after {attempts} attempts: {reason}")]
    OperationFailed { attempts: u32, reason: String },

    #[error("the market maker is shutting down")]
    ShuttingDown,

    #[error("the coordinator stopped")]
    CoordinatorStopped,

    #[error("signer {pubkey} failed: {source}")]
    Signer {
        pubkey: Address,
        source: SignerError,
    },

    #[error("the swap transaction names {signer} as a signer the market maker cannot sign for")]
    UnexpectedSigner { signer: Address },

    #[error("message requires {required} signatures but names {accounts} accounts")]
    MalformedMessage { required: usize, accounts: usize },

    #[error("message requires no signature")]
    UnsignedMessage,

    #[error("rpc error: {0}")]
    Rpc(ClientError),

    #[error("indexer error: {0}")]
    Indexer(ClientError),

    #[error("prover error: {0}")]
    Prover(ClientError),

    #[error("wallet sync failed: {0}")]
    Sync(ClientError),

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error(transparent)]
    Transaction(#[from] TransactionError),

    #[error(transparent)]
    Keypair(#[from] KeypairError),

    #[error(transparent)]
    Budget(#[from] BudgetError),

    #[error("the rpc rejected the transaction: {0}")]
    SendRejected(String),

    #[error("the transaction landed and failed: {0}")]
    TransactionFailed(String),

    #[error("the transaction did not land before its blockhash expired")]
    NotLanded,

    #[error("a fill preempts this upkeep step")]
    Preempted,

    #[error("a cache slot no longer holds its tracked utxo")]
    CacheSlotChanged,

    #[error("the cache expired before the step was sent")]
    CacheExpired,

    #[error("no supported shape takes {inputs} inputs and {outputs} outputs")]
    NoSupportedShape { inputs: usize, outputs: usize },

    #[error("transaction of {bytes} bytes and {addresses} addresses does not fit transaction v1")]
    TransactionTooLarge { bytes: usize, addresses: usize },

    #[error("{slots} cache slots were assigned to {outputs} own new utxos")]
    CacheSlotCountMismatch { slots: usize, outputs: usize },

    #[error("output position {position} does not fit a slot index")]
    OutputPositionOutOfRange { position: usize },

    #[error("cache account {cache} has invalid data")]
    InvalidCacheAccount { cache: Address },

    #[error("clock sysvar is missing or malformed")]
    InvalidClock,

    #[error("utxo {0:?} is reserved by another step")]
    UtxoReserved([u8; 32]),

    #[error("utxo {0:?} is not tracked")]
    UtxoNotTracked([u8; 32]),

    #[error("fill {step} is not reserved")]
    UnknownFill { step: StepId },

    #[error("fill {step} was released at its quote deadline")]
    ReservationExpired { step: StepId },

    #[error("fill {step} is already settling")]
    AlreadySettling { step: StepId },

    #[error("blocking task failed: {0}")]
    BlockingTask(String),
}
