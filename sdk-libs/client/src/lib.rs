pub mod error;
pub mod private_transaction;
pub mod prover;
pub mod rpc;

pub use error::ClientError;
pub use private_transaction::{
    CircuitType, InputCommitment, SignedTransaction, SpendProof, SpendUtxo, Transaction,
    WithdrawalTarget,
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
    MerkleProof, NonInclusionProof, NullifierNonInclusionProof, OutputSlot, ProveResult,
    RpcBlocking, ShieldedTransaction, ShieldedTransactionStream, StateInclusionProof,
    NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
