//! Prover glue for the squads ring proofs (gated under the `prover` feature):
//! building the ring and key-encryption witnesses, proving them with
//! `squads-prover`, and producing the published artifacts and 192-byte
//! compressed proofs the on-chain program verifies.

pub mod error;
pub mod key_encryption;
pub mod merge;
pub mod ring;
pub mod shared_viewing_key;
pub mod spend;
pub mod viewing_key_account;

#[cfg(test)]
mod ring_tests;
#[cfg(test)]
mod tests;

pub use error::SquadsProverError;
pub use key_encryption::{KeyEncryptionProofResult, KeyEncryptionWitness, RecipientCiphertext};
pub use merge::{
    merge_dummy_nullifiers, merge_first_nullifier, prove_squads_merge, SquadsMergeInput,
    SquadsMergeProof, SquadsMergeRequest,
};
pub use ring::{
    decrypt_sender_change, derive_spend_secrets, RingProofResult, RingProposal, RingRecipient,
    RingUtxo, RingWitness, SpendSecrets,
};
pub use spend::{
    dummy_input, probe_squads_spend, sign_spend, ProbedSpend, SpentOutput, SquadsDummyInput,
    SquadsOwner, SquadsRecipient, SquadsSender, SquadsSpendInput, SquadsSpendOperation,
    SquadsSpendProof, SquadsSpendRequest, WithdrawalSettlement,
};
pub use viewing_key_account::{
    create_viewing_key_account_ix_data, execute_key_update_ix_data,
    prove_create_viewing_key_account, prove_execute_key_update,
};
