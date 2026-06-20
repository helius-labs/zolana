pub mod actions;
pub mod error;
#[cfg(feature = "indexer-api")]
pub mod indexer;
pub mod private_transaction;
pub mod prover;
pub mod rpc;
#[cfg(feature = "solana-rpc")]
pub mod solana_rpc;
pub mod wallet_sync;

pub use actions::{
    create_deposit, create_transfer, create_withdrawal, AddressResolver, CreateTransfer,
    CreatedTransfer, CreatedWithdrawal, Deposit, ResolvedAddress,
};
pub use error::ClientError;
#[cfg(feature = "indexer-api")]
pub use indexer::ZolanaIndexer;
pub use private_transaction::{
    CircuitType, InputCommitment, InputTreeIndices, SignedTransaction, SpendProof, SpendUtxo,
    Transaction, WithdrawalTarget,
};
pub use prover::{
    canonical_shape, resolve_shape, spawn_prover, Commitments, CompressedCommitments, P256Owner,
    Proof, ProofCompressed, ProverClient, PublicAmounts, Shape, TransferInput, TransferInputs,
    TransferOutput, TransferP256Inputs, TransferP256ProofResult, TransferP256Prover,
    TransferProofResult, TransferProver, TransferSpendInput, UtxoInputs, SUPPORTED_SHAPES,
};
pub use rpc::{
    Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
    GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse, MerkleContext,
    MerkleProof, NonInclusionProof, NullifierNonInclusionProof, OutputSlot, ProveResult, Rpc,
    ShieldedTransaction, ShieldedTransactionStream, StateInclusionProof, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
#[cfg(feature = "solana-rpc")]
pub use solana_rpc::{ConfirmedInstructionGroups, SolanaRpc};
pub use wallet_sync::{
    sync_wallet, sync_wallet_with_config, ProoflessDepositEventSource, SyncWalletConfig,
};
