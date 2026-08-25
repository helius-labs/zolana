//! Local verification for proofs returned by a prover service.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use zolana_interface::verifying_keys::{
    transfer_confidential_1_1, transfer_confidential_1_2, transfer_confidential_1_8,
    transfer_confidential_2_2, transfer_confidential_2_3, transfer_confidential_3_3,
    transfer_confidential_4_3, transfer_confidential_4_4, transfer_confidential_5_3,
    transfer_confidential_5_4,
};

use crate::{ClientError, Proof, TransferInputs, TransferProofResult};

fn confidential_verifying_key(
    n_inputs: usize,
    n_outputs: usize,
) -> Result<&'static Groth16Verifyingkey<'static>, ClientError> {
    match (n_inputs, n_outputs) {
        (1, 1) => Ok(&transfer_confidential_1_1::VERIFYINGKEY),
        (1, 2) => Ok(&transfer_confidential_1_2::VERIFYINGKEY),
        (1, 8) => Ok(&transfer_confidential_1_8::VERIFYINGKEY),
        (2, 2) => Ok(&transfer_confidential_2_2::VERIFYINGKEY),
        (2, 3) => Ok(&transfer_confidential_2_3::VERIFYINGKEY),
        (3, 3) => Ok(&transfer_confidential_3_3::VERIFYINGKEY),
        (4, 3) => Ok(&transfer_confidential_4_3::VERIFYINGKEY),
        (4, 4) => Ok(&transfer_confidential_4_4::VERIFYINGKEY),
        (5, 3) => Ok(&transfer_confidential_5_3::VERIFYINGKEY),
        (5, 4) => Ok(&transfer_confidential_5_4::VERIFYINGKEY),
        (n_in, n_out) => Err(ClientError::UnsupportedShape { n_in, n_out }),
    }
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
    if proof.commitment.is_some() {
        return Err(ClientError::ProofVerification(
            "default-ring Ed25519 proof carries an unexpected commitment".to_owned(),
        ));
    }

    let verifying_key = confidential_verifying_key(inputs.inputs.len(), inputs.outputs.len())?;
    let public_inputs = [public_input_hash];
    let mut verifier =
        Groth16Verifier::new(&proof.a, &proof.b, &proof.c, &public_inputs, verifying_key).map_err(
            |error| ClientError::ProofVerification(format!("invalid proof encoding: {error:?}")),
        )?;
    verifier
        .verify()
        .map_err(|error| ClientError::ProofVerification(format!("pairing check failed: {error:?}")))
}
