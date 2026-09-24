//! Use [`ZolanaClient`] by default: it wraps Solana RPC, the indexer, and the prover.
//! Use `SolanaRpc`, `ZolanaIndexer`, or `ProverClient` (or their async counterparts)
//! when you need direct access to an individual service.
//!
//! Wallet state, syncing, transaction-building actions, and the user registry
//! live in the `zolana-wallet` crate, which builds on this one.
//!
//! `ZOLANA_TIMING=1` prints per-phase timings to stderr; see [`timing`]. The
//! `let _t = Phase::start(..)` guards through this crate are that, timing until
//! they drop, and inert otherwise.
//!
//! Feature flags:
//! - `(none)`: prover client + RPC traits
//! - `indexer-api`: Photon indexer adapter and [`ZolanaClient`]
//! - `solana-rpc`: concrete Solana RPC adapters
//! - `client`: `indexer-api` + `solana-rpc`

pub mod authority;
#[cfg(feature = "indexer-api")]
pub mod client;
pub mod error;
#[cfg(feature = "indexer-api")]
pub mod indexer;
pub mod prover;
pub mod rpc;

pub use authority::ProofAuthority;
#[cfg(feature = "indexer-api")]
pub use client::{SignedPrivateTransaction, ZolanaClient, DEFAULT_TRANSACT_CU_LIMIT};
pub use error::ClientError;
#[cfg(feature = "indexer-api")]
pub use indexer::{AsyncZolanaIndexer, ZolanaIndexer};
pub use prover::timing;
#[cfg(feature = "indexer-api")]
pub use prover::witness::{AsyncWitnessReader, InputWitnesses, WitnessReader};
pub use prover::{
    attach_input_proofs, input_utxos_from_nullifiers, spawn_prover, spawn_prover_with_artifacts,
    transact::{assemble, assemble_with_dummy_policy, AssembledTransfer, SpendProof},
    verify_confidential_transfer_inputs, verify_confidential_transfer_proof, AsyncPollConfig,
    AsyncProverClient, BatchAddressAppendInputs, CacheReadInputs, Commitments,
    CompressedCommitments, Delivery, MergeProofResult, MergeProver, Proof, ProofCompressed,
    ProofInputUtxo, ProveRequest, ProverClient, PublicInputs, PublicTransfers,
    RingAuthorityProofResult, RingAuthorityProver, RingTransferP256ProofResult,
    RingTransferP256Prover, RingTransferProofResult, RingTransferProver, Shape, TransferInput,
    TransferInputUtxo, TransferInputs, TransferOutput, TransferP256Inputs, TransferProofResult,
    TransferProver, TreeSlotFields, SPP_SUPPORTED_SHAPES,
};
#[cfg(feature = "solana-rpc")]
pub use rpc::solana_rpc::{
    AsyncSolanaRpc, ConfirmedInstructionGroups, ProgramAccountsFilter, SolanaRpc,
};
pub use rpc::SettlementAccountValidation;
pub use rpc::{compile_message, sign_transaction, ComputeBudgetConfig};
pub use rpc::{transaction_size, TransactionSize};
pub use rpc::{
    AsyncRpc, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetMerkleProofsResponse, GetNonInclusionProofsResponse, GetRingKeyRegistryEntryResponse,
    GetRingKeyRegistryRegisterProofResponse, GetRingSpendRecordResponse,
    GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
    IndexedShieldedTransaction, MerkleContext, MerkleProof, NonInclusionProof, OutputContext,
    OutputSlot, ProveResult, RingHistoryOptions, RingMemberProofRequest, RingSpendRecord,
    RingSpendRecordRequest, Rpc, ShieldedTransaction, ShieldedTransactionStream,
    MAX_LOADED_ACCOUNTS_DATA_SIZE, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
pub use rpc::{IndexerPollConfig, IndexerRpcConfig};
// `SolanaRpc::send_transaction_with_config` is public but names this type,
// so callers outside the crate need it to call the method at all.
pub use solana_rpc_client_api::config::RpcSendTransactionConfig;
