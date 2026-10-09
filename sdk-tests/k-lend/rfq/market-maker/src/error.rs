use k_lend_rfq_sdk::swap::SwapError;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::SignerError;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;

use crate::transactions::{budget::BudgetError, steps::StepId};

#[derive(Debug, Error)]
pub enum MakerError {
    #[error("{asset} balance {available} minus queued operations cannot cover {requested}")]
    InsufficientBalance {
        asset: Address,
        available: u64,
        requested: u64,
    },

    #[error("{asset} utxos hold {available} but no {max_inputs} of them cover {requested}")]
    FragmentedInventory {
        asset: Address,
        available: u64,
        requested: u64,
        max_inputs: usize,
    },

    #[error("own outputs of {planned} do not add up to the {own_value} the transfer keeps")]
    OwnPartsMismatch { planned: u64, own_value: u64 },

    #[error("{asset} has no fragments to consolidate")]
    NothingToConsolidate { asset: Address },

    #[error("vault {vault} does not exist")]
    VaultMissing { vault: Address },

    #[error("vault {vault} state does not parse: {reason}")]
    VaultState { vault: Address, reason: String },

    #[error("vault {vault} cannot price the rebalance: {reason}")]
    VaultMath { vault: Address, reason: String },

    #[error("shield instruction could not be built: {0}")]
    ShieldInstruction(String),

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

    #[error("no supported shape takes {inputs} inputs and {outputs} outputs")]
    NoSupportedShape { inputs: usize, outputs: usize },

    #[error("transaction of {bytes} bytes and {addresses} addresses does not fit transaction v1")]
    TransactionTooLarge { bytes: usize, addresses: usize },

    #[error("output position {position} does not fit a slot index")]
    OutputPositionOutOfRange { position: usize },

    #[error("utxo {0:?} is reserved by another step")]
    UtxoReserved([u8; 32]),

    #[error("utxo {0:?} is not tracked")]
    UtxoNotTracked([u8; 32]),

    #[error("the fill is not reserved")]
    UnknownFill,

    #[error("fill {step} was released at its quote deadline")]
    ReservationExpired { step: StepId },

    #[error("fill {step} is already settling")]
    AlreadySettling { step: StepId },

    #[error("transaction {signature} was not confirmed")]
    NotConfirmed { signature: Signature },

    #[error("transaction {signature} was confirmed but not indexed")]
    NotIndexed { signature: Signature },

    #[error("mint {mint} has no shielded-pool asset registry")]
    AssetNotRegistered { mint: Address },

    #[error("asset registry of mint {mint} does not parse: {reason}")]
    AssetRegistry { mint: Address, reason: String },

    #[error("pair of vault {vault} is not served")]
    PairNotServed { vault: Address },

    #[error("pair of vault {vault} is already configured")]
    PairExists { vault: Address },

    #[error("no pair of vault {vault} is configured")]
    UnknownPair { vault: Address },

    #[error("mint {mint} belongs to no configured pair")]
    UnknownAsset { mint: Address },

    #[error("a {expected} operation returned another outcome")]
    UnexpectedOutcome { expected: &'static str },

    #[error(transparent)]
    Swap(#[from] SwapError),

    #[error("blocking task failed: {0}")]
    BlockingTask(String),
}
