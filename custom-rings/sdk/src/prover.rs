//! Proving entry point for the ring's single circuit.

use custom_ring_prover::{AuditProof, AuditorKeyEncryptionProofInputs, ProofError};

#[derive(Debug, Default, Clone, Copy)]
pub struct CustomRingProverClient;

impl CustomRingProverClient {
    pub fn new() -> Self {
        Self
    }

    /// Proves that `inputs.tx_viewing_sk` is the plaintext of the auditor
    /// ciphertext committed to by `inputs.public_input_hash`.
    pub fn prove_auditor_key_encryption(
        &self,
        inputs: &AuditorKeyEncryptionProofInputs,
    ) -> Result<AuditProof, ProofError> {
        inputs.prove()
    }
}
