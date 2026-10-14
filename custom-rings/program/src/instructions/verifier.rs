use custom_ring_interface::{CustomRingError, CustomRingProof};
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::ProgramResult;

/// Every ring key carries the BSB22 commitment, so the Pedersen pairing always
/// runs and a proof without the commitment never verifies.
#[inline(never)]
pub(crate) fn verify_groth16(
    proof: &CustomRingProof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> ProgramResult {
    let points = &proof.groth16;
    Groth16Verifier::new_with_commitment(
        &decompress_g1(&points.proof_a).map_err(failed)?,
        &decompress_g2(&points.proof_b).map_err(failed)?,
        &decompress_g1(&points.proof_c).map_err(failed)?,
        &decompress_g1(&proof.commitment).map_err(failed)?,
        &decompress_g1(&proof.commitment_pok).map_err(failed)?,
        &[public_input_hash],
        verifying_key,
    )
    .map_err(failed)?
    .verify()
    .map_err(failed)?;
    Ok(())
}

fn failed<E>(_: E) -> CustomRingError {
    CustomRingError::ProofVerificationFailed
}
