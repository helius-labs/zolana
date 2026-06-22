pub mod actions;
pub mod error;
#[cfg(feature = "indexer-api")]
pub mod indexer;
pub mod merge_service;
pub mod private_transaction;
pub mod prover;
pub mod rpc;
#[cfg(feature = "solana-rpc")]
pub mod solana_rpc;
pub mod user_registry;
pub mod wallet_authority;
pub mod wallet_sync;

pub use actions::{
    create_deposit, create_transfer, create_withdrawal, CreateDeposit, CreateTransfer,
    CreateWithdrawal, CreatedTransfer, CreatedWithdrawal, Deposit, ResolvedAddress,
    TransferRecipient,
};
pub use error::ClientError;
#[cfg(feature = "indexer-api")]
pub use indexer::ZolanaIndexer;
pub use merge_service::{
    merge_owner_tag, LocalMergeService, MergeServiceConfig, MergeServiceReport,
};
pub use private_transaction::{
    AssembledTransfer, CircuitType, InputCommitment, Merge, MergeOwner, PreparedMerge,
    ProverInputs, SignedTransaction, SpendProof, SpendUtxo, Transaction, WithdrawalTarget,
    MERGE_INPUTS,
};
pub use prover::{
    canonical_shape, resolve_shape, spawn_prover, Commitments, CompressedCommitments,
    MergeProofResult, MergeProver, P256Owner, Proof, ProofCompressed, ProverClient, PublicAmounts,
    Shape, TransferInput, TransferInputs, TransferOutput, TransferP256Inputs,
    TransferP256ProofResult, TransferP256Prover, TransferProofResult, TransferProver,
    TransferSpendInput, UtxoInputs, SUPPORTED_SHAPES,
};
pub use rpc::{
    Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
    GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse, MerkleContext,
    MerkleProof, NonInclusionProof, OutputContext, OutputSlot, ProveResult, Rpc,
    ShieldedTransaction, ShieldedTransactionStream, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
#[cfg(feature = "solana-rpc")]
pub use solana_rpc::{ConfirmedInstructionGroups, SolanaRpc};
pub use user_registry::{
    decode_user_record_account, fetch_user_record_checked, fetch_user_record_optional_checked,
    resolve_registered_address, resolved_address_from_record, try_resolve_registered_address,
    validate_registered_keypair,
};
pub use wallet_authority::{ApprovalRequest, P256Signature, WalletAuthority};
pub use wallet_sync::{sync_wallet, sync_wallet_with_config, SyncWalletConfig};
