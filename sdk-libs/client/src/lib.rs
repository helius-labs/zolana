pub mod actions;
pub mod error;
#[cfg(feature = "indexer-api")]
pub mod indexer;
pub mod prover;
pub mod rpc;
#[cfg(feature = "solana-rpc")]
pub mod solana_rpc;
pub mod user_registry;
pub mod wallet_authority;
pub mod wallet_sync;

pub use actions::{
    create_deposit, create_transfer, create_transfer_async, create_withdrawal,
    create_withdrawal_async, sign_transaction, sign_transaction_async, CreateDeposit,
    CreateTransfer, CreateWithdrawal, CreatedTransfer, CreatedWithdrawal, Deposit, ResolvedAddress,
    TransferRecipient,
};
pub use error::ClientError;
#[cfg(feature = "indexer-api")]
pub use indexer::ZolanaIndexer;
pub use prover::{
    canonical_shape,
    merge::MergeWitness,
    resolve_shape, spawn_prover,
    transact::{assemble, into_prover, AssembledTransfer, CircuitType, ProverInputs, SpendProof},
    BatchAddressAppendInputs, Commitments, CompressedCommitments, MergeProofResult, MergeProver,
    P256Owner, Proof, ProofCompressed, ProverClient, PublicAmounts, Shape, TransferInput,
    TransferInputs, TransferOutput, TransferP256Inputs, TransferP256ProofResult,
    TransferP256Prover, TransferProofResult, TransferProver, TransferSpendInput, UtxoInputs,
    SUPPORTED_SHAPES,
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
pub use wallet_authority::{
    AnonymousRecipientSlot, ApprovalRequest, AsyncWalletAuthority, ConfidentialRecipientSlot,
    EncryptedTransfer, P256Signature, WalletAuthority,
};
pub use wallet_sync::{get_private_token_balances, get_private_transactions};
pub use wallet_sync::{sync_wallet, sync_wallet_with_config, SyncWalletConfig};
pub use zolana_transaction::instructions::{
    merge::{Merge, PreparedMerge, MERGE_INPUTS},
    transact::{SignedTransaction, Transaction, WithdrawalTarget},
    types::{InputCommitment, SpendUtxo},
};
pub use zolana_transaction::{
    AssetBalance, PrivateTransaction, PrivateTransactionDirection, PrivateTransactionId,
    PrivateTransactionKind, PrivateTransactionStatus,
};
