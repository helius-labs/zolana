//! Local verification for proofs returned by a prover service.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use spr_interface::{verifying_keys::CircuitId, N_PUBLIC_SLOTS};

use crate::{
    prover::transact::ConfidentialEddsaTransferInputs, ClientError, Proof, TransferInputs,
    TransferProofResult,
};

/// Resolved through [`CircuitId::verifying_key`], which the on-chain verifier
/// dispatches on too. A local shape-to-key table here would be a second place
/// to update when a shape is added, and a client that verified against a
/// different key than the program would accept a proof the chain rejects.
pub(crate) fn confidential_verifying_key(
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
    CircuitId::ConfidentialSigner(n_in, n_out, slots)
        .verifying_key()
        .ok_or_else(shape_err)
}

/// Verify a default-ring EdDSA transfer proof against the committed
/// shape-specific verifying key and the locally constructed public input.
///
/// Call this before allowing an external prover response to influence a
/// signing request. Custom-ring proofs use different public inputs
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

/// Verify a default-ring transfer one owner authorizes in-circuit against its
/// shape's verifying key, which carries the signature gadget's commitment.
pub fn verify_confidential_eddsa_transfer_inputs(
    inputs: &ConfidentialEddsaTransferInputs,
    public_input_hash: [u8; 32],
    proof: &Proof,
) -> Result<(), ClientError> {
    let shape =
        crate::prover::Shape::new(inputs.transfer.inputs.len(), inputs.transfer.outputs.len());
    TransferProofStatement {
        circuit: inputs.authorization.circuit(shape, None),
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
        use spr_interface::verifying_keys::{merge_ring_24_1, merge_ring_52_1, merge_ring_8_1};
        let verifying_key = match self.n_inputs {
            8 => &merge_ring_8_1::VERIFYINGKEY,
            24 => &merge_ring_24_1::VERIFYINGKEY,
            52 => &merge_ring_52_1::VERIFYINGKEY,
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
        StatementVerification {
            verifying_key: merge_verifying_key(self.n_inputs)?,
            public_input_hash: self.public_input_hash,
        }
        .verify(proof)
    }
}

pub(crate) fn merge_verifying_key(
    n_inputs: usize,
) -> Result<&'static Groth16Verifyingkey<'static>, ClientError> {
    use spr_interface::verifying_keys::{merge_24_1, merge_52_1, merge_8_1};
    match n_inputs {
        8 => Ok(&merge_8_1::VERIFYINGKEY),
        24 => Ok(&merge_24_1::VERIFYINGKEY),
        52 => Ok(&merge_52_1::VERIFYINGKEY),
        _ => Err(ClientError::UnsupportedShape {
            n_in: n_inputs,
            n_out: 1,
        }),
    }
}

pub(crate) struct StatementVerification<'a> {
    pub verifying_key: &'a Groth16Verifyingkey<'a>,
    pub public_input_hash: [u8; 32],
}

impl StatementVerification<'_> {
    pub fn verify(self, proof: &Proof) -> Result<(), ClientError> {
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

pub fn verify_proof_statement(
    proof: &Proof,
    public_input_hash: [u8; 32],
    verifying_key: &'static Groth16Verifyingkey<'static>,
) -> Result<(), ClientError> {
    StatementVerification {
        verifying_key,
        public_input_hash,
    }
    .verify(proof)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use spr_interface::verifying_keys::{
        merge_8_1, merge_ring_8_1, transfer_confidential_eddsa_2_8, transfer_eddsa_ring_2_2,
        transfer_eddsa_ring_2_4,
    };

    use super::*;

    /// The proofs a real prover made that the TypeScript SDK verifies too.
    #[test]
    fn the_shared_proofs_verify_against_the_compiled_keys() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/proof_verification.json"
        ))
        .unwrap();
        for vector in vectors["proofs"].as_array().unwrap() {
            let name = vector["key"].as_str().unwrap();
            let (key, other) = match name {
                "transfer_confidential_eddsa_2_8.key" => (
                    &transfer_confidential_eddsa_2_8::VERIFYINGKEY,
                    &transfer_eddsa_ring_2_2::VERIFYINGKEY,
                ),
                "transfer_eddsa_ring_2_2.key" => (
                    &transfer_eddsa_ring_2_2::VERIFYINGKEY,
                    &transfer_eddsa_ring_2_4::VERIFYINGKEY,
                ),
                "merge_8_1.key" => (&merge_8_1::VERIFYINGKEY, &merge_ring_8_1::VERIFYINGKEY),
                _ => panic!("unexpected vector {name}"),
            };
            let proof = Proof::from_gnark_json(&vector["proof"].to_string()).unwrap();
            let digits = vector["publicInputHash"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x");
            let public_input: [u8; 32] = hex::decode(format!("{digits:0>64}"))
                .unwrap()
                .try_into()
                .unwrap();
            verify_proof_statement(&proof, public_input, key).unwrap();

            let mut other_statement = public_input;
            other_statement[31] ^= 1;
            assert!(verify_proof_statement(&proof, other_statement, key).is_err());
            assert!(verify_proof_statement(&proof, public_input, other).is_err());
            let mut swapped = proof;
            if let Some(commitment) = swapped.commitment.as_mut() {
                commitment.commitment = commitment.commitment_pok;
                assert!(verify_proof_statement(&swapped, public_input, key).is_err());
            }
        }
    }
}
