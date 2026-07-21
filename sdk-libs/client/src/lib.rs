//! Zolana client SDK: RPC traits, concrete Solana RPC adapters, the prover
//! client, and the high-level [`ZolanaClient`] that owns RPC, Photon, and the
//! prover.
//!
//! Wallet state, syncing, transaction-building actions, and the user registry
//! live in the `zolana-wallet` crate, which builds on this one.
//!
//! Feature flags:
//! - `(none)`: prover client + RPC traits
//! - `indexer-api`: Photon indexer adapter and [`ZolanaClient`]
//! - `solana-rpc`: concrete Solana RPC adapters
//! - `client`: `indexer-api` + `solana-rpc`

#[cfg(feature = "indexer-api")]
pub mod client;
pub mod error;
#[cfg(feature = "indexer-api")]
pub mod indexer;
pub mod prover;
pub mod retry;
pub mod rpc;
#[cfg(feature = "solana-rpc")]
pub mod solana_rpc;

#[cfg(feature = "indexer-api")]
pub use client::{SignedPrivateTransaction, ZolanaClient, DEFAULT_TRANSACT_CU_LIMIT};
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
pub use retry::{IndexerPollConfig, IndexerRpcConfig};
pub use rpc::{
    AsyncRpc, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetMerkleProofsResponse, GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse,
    MerkleContext, MerkleProof, NonInclusionProof, OutputContext, OutputSlot, ProveResult, Rpc,
    ShieldedTransaction, ShieldedTransactionStream, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
#[cfg(feature = "solana-rpc")]
pub use solana_rpc::{AsyncSolanaRpc, ConfirmedInstructionGroups, SolanaRpc};
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
