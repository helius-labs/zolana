//! Prover glue for the squads zone proofs (gated under the `prover` feature).
//!
//! Currently covers the key-encryption proof: building the verifiable-encryption
//! witness, requesting a Groth16 proof from the prover server, and producing the
//! published artifacts and 192-byte compressed proof the on-chain program
//! verifies.

pub mod error;
pub mod key_encryption;
pub mod merge;
pub mod proof;
pub mod server;
pub mod shared_viewing_key;
pub mod smart_account;
pub mod transfer;
pub mod viewing_key_account;
pub mod withdrawal;
pub mod zone;

#[cfg(test)]
mod split_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod zone_tests;

pub use error::SquadsProverError;
pub use key_encryption::{
    scalar_secret_key, KeyEncryptionProofResult, KeyEncryptionWitness, RecipientCiphertext,
    KEY_ENCRYPTION_SUPPORTED_KEYS,
};
pub use merge::{prove_squads_merge, SquadsMergeInput, SquadsMergeProof, SquadsMergeRequest};
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
    create_viewing_key_account_ix_data, execute_key_update_ix_data,
    prove_create_viewing_key_account, prove_execute_key_update,
};
pub use withdrawal::{
    probe_squads_withdrawal, prove_squads_withdrawal, squads_input_commitment, ProbedWithdrawal,
    SquadsIdentity, SquadsWithdrawalInput, SquadsWithdrawalProbe, SquadsWithdrawalProof,
    SquadsWithdrawalRequest,
};
pub use zone::{
    decrypt_sender_change, derive_change_blinding, derive_sender_artifacts, SenderArtifacts,
    ZoneProofResult, ZoneProposal, ZoneRecipient, ZoneUtxo, ZoneWitness, ZONE_SUPPORTED_SHAPES,
};
