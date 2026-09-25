//! Local verification for proofs returned by a prover service.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use zolana_interface::{verifying_keys::CircuitId, N_PUBLIC_SLOTS};

use crate::{ClientError, Proof, TransferInputs, TransferProofResult};

/// Resolved through [`CircuitId::verifying_key`], which the on-chain verifier
/// dispatches on too. A local shape-to-key table here would be a second place
/// to update when a shape is added, and a client that verified against a
/// different key than the program would accept a proof the chain rejects.
fn confidential_verifying_key(
    n_inputs: usize,
    n_outputs: usize,
) -> Result<&'static Groth16Verifyingkey<'static>, ClientError> {
    let shape_err = || ClientError::UnsupportedShape {
        n_in: n_inputs,
        n_out: n_outputs,
    };
    let n_in = u8::try_from(n_inputs).map_err(|_| shape_err())?;
    let n_out = u8::try_from(n_outputs).map_err(|_| shape_err())?;
    let slots = u8::try_from(N_PUBLIC_SLOTS).map_err(|_| shape_err())?;
    CircuitId::ConfidentialEddsa(n_in, n_out, slots)
        .verifying_key()
        .ok_or_else(shape_err)
}

/// Verify a default-ring Ed25519 transfer proof against the committed
/// shape-specific verifying key and the locally constructed public input.
///
/// Call this before allowing an external prover response to influence a
/// signing request. Custom-ring and P-256 proofs use different public inputs
/// and verifying keys and are intentionally outside this function.
pub fn verify_confidential_transfer_proof(
    result: &TransferProofResult,
    proof: &Proof,
) -> Result<(), ClientError> {
    verify_confidential_transfer_inputs(&result.inputs, result.public_input_hash, proof)
}

/// Verify a default-ring transfer directly from the assembled witness and its
/// locally computed public input.
pub fn verify_confidential_transfer_inputs(
    inputs: &TransferInputs,
    public_input_hash: [u8; 32],
    proof: &Proof,
) -> Result<(), ClientError> {
    ConfidentialProofStatement {
        n_inputs: inputs.inputs.len(),
        n_outputs: inputs.outputs.len(),
        public_input_hash,
    }
    .verify(proof)
}

pub(crate) struct ConfidentialProofStatement {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub public_input_hash: [u8; 32],
}

impl ConfidentialProofStatement {
    pub fn verify(self, proof: &Proof) -> Result<(), ClientError> {
        StatementVerification {
            verifying_key: confidential_verifying_key(self.n_inputs, self.n_outputs)?,
            public_input_hash: self.public_input_hash,
        }
        .verify(proof)
    }
}

pub(crate) struct TransferProofStatement {
    pub circuit: CircuitId,
    pub public_input_hash: [u8; 32],
}

impl TransferProofStatement {
    pub fn verify(self, proof: &Proof) -> Result<(), ClientError> {
        StatementVerification {
            verifying_key: self
                .circuit
                .verifying_key()
                .ok_or(ClientError::UnsupportedShape {
                    n_in: usize::from(self.circuit.num_inputs()),
                    n_out: usize::from(self.circuit.num_outputs()),
                })?,
            public_input_hash: self.public_input_hash,
        }
        .verify(proof)
    }
}

pub(crate) struct MergeProofStatement {
    pub n_inputs: usize,
    pub public_input_hash: [u8; 32],
}

impl MergeProofStatement {
    pub fn verify_ring(self, proof: &Proof) -> Result<(), ClientError> {
        use zolana_interface::verifying_keys::{merge_ring_36_1, merge_ring_8_1};
        let verifying_key = match self.n_inputs {
            8 => &merge_ring_8_1::VERIFYINGKEY,
            36 => &merge_ring_36_1::VERIFYINGKEY,
            _ => {
                return Err(ClientError::UnsupportedShape {
                    n_in: self.n_inputs,
                    n_out: 1,
                })
            }
        };
        StatementVerification {
            verifying_key,
            public_input_hash: self.public_input_hash,
        }
        .verify(proof)
    }

    pub fn verify(self, proof: &Proof) -> Result<(), ClientError> {
        use zolana_interface::verifying_keys::{merge_36_1, merge_8_1};
        let verifying_key = match self.n_inputs {
            8 => &merge_8_1::VERIFYINGKEY,
            36 => &merge_36_1::VERIFYINGKEY,
            _ => {
                return Err(ClientError::UnsupportedShape {
                    n_in: self.n_inputs,
                    n_out: 1,
                })
            }
        };
        StatementVerification {
            verifying_key,
            public_input_hash: self.public_input_hash,
        }
        .verify(proof)
    }
}

struct StatementVerification {
    verifying_key: &'static Groth16Verifyingkey<'static>,
    public_input_hash: [u8; 32],
}

impl StatementVerification {
    fn verify(self, proof: &Proof) -> Result<(), ClientError> {
        let public_inputs = [self.public_input_hash];
        let mut verifier = match (
            &proof.commitment,
            self.verifying_key.vk_commitment.is_some(),
        ) {
            (Some(commitment), true) => Groth16Verifier::new_with_commitment(
                &proof.a,
                &proof.b,
                &proof.c,
                &commitment.commitment,
                &commitment.commitment_pok,
                &public_inputs,
                self.verifying_key,
            ),
            (None, false) => Groth16Verifier::new(
                &proof.a,
                &proof.b,
                &proof.c,
                &public_inputs,
                self.verifying_key,
            ),
            _ => {
                return Err(ClientError::ProofVerification(
                    "proof commitment mismatch".to_owned(),
                ))
            }
        }
        .map_err(|error| {
            ClientError::ProofVerification(format!("invalid proof encoding {error:?}"))
        })?;
        verifier.verify().map_err(|error| {
            ClientError::ProofVerification(format!("pairing check failed: {error:?}"))
        })
    }
}
