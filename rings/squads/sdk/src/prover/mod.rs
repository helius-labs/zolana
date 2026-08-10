//! Prover glue for the squads ring proofs (gated under the `prover` feature).
//!
//! Covers the ring and key-encryption proofs: building the
//! verifiable-encryption proof inputs, requesting a Groth16 proof from the prover
//! server, and producing the published artifacts and 192-byte compressed proof
//! the on-chain program verifies. The `*_fold` modules widen each past its
//! per-key shape by folding several legs into one proof.

pub mod error;
pub mod fold;
pub mod key_encryption;
pub mod key_encryption_fold;
pub mod merge;
pub mod proof;
pub mod server;
pub mod shared_viewing_key;
pub use shared_viewing_key::WithdrawalDestination;
pub mod ring;
pub mod ring_fold;
pub mod smart_account;
pub mod transfer;
pub mod viewing_key_account;
pub mod withdrawal;

#[cfg(test)]
mod key_encryption_fold_tests;
#[cfg(test)]
mod ring_fold_tests;
#[cfg(test)]
mod ring_tests;
#[cfg(test)]
mod split_tests;
#[cfg(test)]
mod tests;

pub use error::SquadsProverError;
pub use key_encryption::{
    scalar_secret_key, KeyEncryptionProofInputs, KeyEncryptionProofResult, RecipientCiphertext,
    KEY_ENCRYPTION_SUPPORTED_KEYS,
};
pub use key_encryption_fold::{
    key_encryption_fold_supported_keys, KeyEncryptionFoldProofInputs, KeyEncryptionFoldProofResult,
    KEY_ENCRYPTION_FOLD_KEYS_PER_LEG, KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS,
};
pub use merge::{prove_squads_merge, SquadsMergeInput, SquadsMergeProof, SquadsMergeRequest};
pub use ring::{
    decrypt_sender_change, derive_change_blinding, derive_sender_artifacts, RingProofInputs,
    RingProofResult, RingProposal, RingRecipient, RingUtxo, SenderArtifacts, RING_SUPPORTED_SHAPES,
};
pub use ring_fold::{
    prove_ring_fold, RingFoldProofResult, RING_FOLD_SUPPORTED_LEGS, RING_FOLD_SUPPORTED_SHAPES,
};
pub use smart_account::{
    prove_squads_smart_account_transfer, prove_squads_smart_account_withdrawal,
    SquadsSmartAccountIdentity, SquadsSmartAccountTransferRequest,
    SquadsSmartAccountWithdrawalRequest,
};
pub use transfer::{
    probe_squads_transfer, prove_squads_transfer, ProbedTransfer, SquadsTransferInput,
    SquadsTransferProbe, SquadsTransferProof, SquadsTransferRecipient, SquadsTransferRequest,
};
pub use viewing_key_account::{
    create_viewing_key_account_ix_data, create_viewing_key_account_ix_data_folded,
    execute_key_update_ix_data, prove_create_viewing_key_account,
    prove_create_viewing_key_account_folded, prove_execute_key_update,
};
pub use withdrawal::{
    probe_squads_withdrawal, prove_squads_withdrawal, squads_input_commitment, ProbedWithdrawal,
    SquadsIdentity, SquadsWithdrawalInput, SquadsWithdrawalProbe, SquadsWithdrawalProof,
    SquadsWithdrawalRequest,
};
