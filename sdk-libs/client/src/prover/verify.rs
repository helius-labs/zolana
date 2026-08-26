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
