//! Zolana client SDK.
//!
//! Feature flags:
//! - `(none)`: build + prove primitives (`create_*`, `sign_*`, prover)
//! - `indexer-api`: Photon sync and proving helpers
//! - `solana-rpc`: concrete Solana RPC adapters
//! - `client`: `indexer-api` + `solana-rpc`
//!
//! Typical private transfer flow:
//! 1. `sync_wallet`
//! 2. `create_transfer` / `create_withdrawal`
//! 3. `sign_private_transaction` → locally signed native `Transaction`, or
//!    `build_private_transaction` → unsigned native `Transaction` for an HSM/custodian
//! 4. `rpc.send_transaction`
//! 5. `ZolanaClient::confirm_private_transaction(signature)` for Photon indexing
//!
//! Spend tree and recipient registry resolution are inferred internally. Use
//! [`is_wallet_registered`] / [`try_resolve_registered_address_async`] when you
//! need an explicit lookup before creating a transfer.

pub mod actions;
#[cfg(feature = "indexer-api")]
pub mod client;
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

#[doc(hidden)]
pub use actions::transaction::{sign_shielded_transaction, sign_shielded_transaction_sync};
pub use actions::{
    build_deposit_transaction, build_deposit_transaction_sync, create_associated_token_account,
    create_deposit, create_transfer, create_transfer_sync, create_withdrawal, CreatedTransfer,
    CreatedWithdrawal, Deposit, DepositParams, ResolvedAddress, TransferParams, TransferRecipient,
    UnsignedPrivateTransaction, WithdrawalParams,
};
#[cfg(feature = "indexer-api")]
pub use actions::{
    build_private_transaction, build_private_transaction_sync, sign_private_transaction,
    sign_private_transaction_sync,
};
#[cfg(feature = "indexer-api")]
pub use client::{IndexerPollConfig, ZolanaClient, DEFAULT_TRANSACT_CU_LIMIT};
pub use error::ClientError;
#[cfg(feature = "indexer-api")]
pub use indexer::{AsyncZolanaIndexer, ZolanaIndexer};
pub use prover::{
    canonical_shape,
    merge::MergeWitness,
    resolve_shape, spawn_prover,
    transact::{assemble, into_prover, AssembledTransfer, CircuitType, ProverInputs, SpendProof},
    AsyncPollConfig, AsyncProverClient, BatchAddressAppendInputs, Commitments,
    CompressedCommitments, MergeProofResult, MergeProver, MergeZoneProofResult, MergeZoneProver,
    MergeZoneWitness, P256Owner, Proof, ProofCompressed, ProofInputUtxo, ProverClient,
    PublicAmounts, Shape, TransferInput, TransferInputs, TransferOutput, TransferP256Inputs,
    TransferP256ProofResult, TransferP256Prover, TransferProofResult, TransferProver,
    TransferSpendInput, ZoneAuthorityProofResult, ZoneAuthorityProver, ZoneAuthorityWitness,
    ZoneTransferP256ProofResult, ZoneTransferP256Prover, ZoneTransferProofResult,
    ZoneTransferProver, SPP_SUPPORTED_SHAPES,
};
pub use rpc::{
    AsyncRpc, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetMerkleProofsResponse, GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse,
    MerkleContext, MerkleProof, NonInclusionProof, OutputContext, OutputSlot, ProveResult, Rpc,
    ShieldedTransaction, ShieldedTransactionStream, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
#[cfg(feature = "solana-rpc")]
pub use solana_rpc::{AsyncSolanaRpc, ConfirmedInstructionGroups, SolanaRpc};
pub use user_registry::{
    build_registration_transaction, build_registration_transaction_sync,
    decode_user_record_account, ensure_registered, fetch_user_record_checked,
    fetch_user_record_optional_checked, fetch_user_record_optional_checked_async,
    is_wallet_registered, is_wallet_registered_sync, recipient_confidential_view_tag,
    recipient_confidential_view_tag_sync, resolve_registered_address, resolved_address_from_record,
    try_resolve_registered_address, try_resolve_registered_address_async,
    validate_registered_keypair,
};
pub use wallet_authority::{
    AnonymousRecipientSlot, ApprovalRequest, EncryptedTransfer, LocalWalletAuthority,
    P256Signature, SyncWalletAuthority, WalletAuthority, WalletSyncMaterial,
};
pub use wallet_sync::{
    get_private_token_balances, get_private_transactions, sync_wallet, sync_wallet_async,
    sync_wallet_with_config, sync_wallet_with_config_async, SyncWalletConfig,
};
pub use zolana_transaction::{
    instructions::{
        merge::{Merge, PreparedMerge, MERGE_INPUTS},
        merge_zone::{MergeZone, PreparedMergeZone},
        transact::{ConfidentialTransfer, SppProofInputs, WithdrawalTarget},
        types::{InputUtxoContext, SppProofInputUtxo},
        zone_authority::PreparedZoneAuthority,
    },
    AssetBalance, PrivateTransaction, PrivateTransactionDirection, PrivateTransactionId,
    PrivateTransactionKind, PrivateTransactionStatus,
};
