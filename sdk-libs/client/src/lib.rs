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
    create_associated_token_account, create_deposit, create_transfer, create_transfer_sync,
    create_withdrawal, create_withdrawal_sync, sign_transaction, sign_transaction_sync,
    CreateDeposit, CreateTransfer, CreateWithdrawal, CreatedTransfer, CreatedWithdrawal, Deposit,
    ResolvedAddress, TransferRecipient,
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
    MergeZoneProofResult, MergeZoneProver, MergeZoneWitness, P256Owner, Proof, ProofCompressed,
    ProverClient, PublicAmounts, Shape, TransferInput, TransferInputs, TransferOutput,
    TransferP256Inputs, TransferP256ProofResult, TransferP256Prover, TransferProofResult,
    ProofInputUtxo, TransferProver, TransferSpendInput, ZoneAuthorityProofResult,
    ZoneAuthorityProver,
    ZoneAuthorityWitness, ZoneTransferP256ProofResult, ZoneTransferP256Prover,
    ZoneTransferProofResult, ZoneTransferProver, SUPPORTED_SHAPES,
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
    decode_user_record_account, ensure_registered, fetch_user_record_checked,
    fetch_user_record_optional_checked, resolve_registered_address, resolved_address_from_record,
    try_resolve_registered_address, validate_registered_keypair,
};
pub use wallet_authority::{
    AnonymousRecipientSlot, ApprovalRequest, ConfidentialRecipientSlot, EncryptedTransfer,
    P256Signature, SyncWalletAuthority, WalletAuthority,
};
pub use wallet_sync::{
    get_private_token_balances, get_private_transactions, sync_wallet, sync_wallet_with_config,
    SyncWalletConfig,
};
pub use zolana_transaction::{
    instructions::{
        merge::{Merge, PreparedMerge, MERGE_INPUTS},
        merge_zone::{MergeZone, PreparedMergeZone},
        transact::{SppProofInputs, Transfer, WithdrawalTarget},
        types::{InputUtxoContext, SppProofInputUtxo},
        zone_authority::PreparedZoneAuthority,
    },
    AssetBalance, PrivateTransaction, PrivateTransactionDirection, PrivateTransactionId,
    PrivateTransactionKind, PrivateTransactionStatus,
};
