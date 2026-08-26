use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use pinocchio::ProgramResult;

use crate::error::CustomRingError;

const PROOF_ERR: CustomRingError = CustomRingError::ProofVerificationFailed;

pub(crate) struct CompressedGroth16Proof<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
}

/// Verify a proof over the single public input `public_input_hash`.
///
/// The proof and the key must agree on whether a BSB22 commitment is present:
/// a commitment-carrying key requires the Pedersen proof-of-knowledge pairing,
/// so accepting a commitment-less proof against it would skip a constraint the
/// circuit relies on. The mismatched combinations are therefore rejected rather
/// than coerced. The custom-ring circuit's emulated P256 arithmetic always produces
/// a commitment, so this program only ever takes the first arm; the second is
/// kept so the helper stays a faithful copy of the shared pattern.
#[inline(never)]
pub(crate) fn verify_groth16(
    proof: CompressedGroth16Proof,
    public_input_hash: [u8; 32],
) -> ProgramResult {
    let proof_a = decompress_g1(proof.a).map_err(|_| PROOF_ERR)?;
    let proof_b = decompress_g2(proof.b).map_err(|_| PROOF_ERR)?;
    let proof_c = decompress_g1(proof.c).map_err(|_| PROOF_ERR)?;
    let commitment = decompress_g1(proof.commitment).map_err(|_| PROOF_ERR)?;
    let commitment_pok = decompress_g1(proof.commitment_pok).map_err(|_| PROOF_ERR)?;
    let public_inputs = [public_input_hash];
    let verifying_key = &custom_ring_interface::verifying_key::VERIFYINGKEY;
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof_a,
        &proof_b,
        &proof_c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        verifying_key,
    )
    .map_err(|_| PROOF_ERR)?;
    verifier.verify().map_err(|_| PROOF_ERR)?;
    Ok(())
}
