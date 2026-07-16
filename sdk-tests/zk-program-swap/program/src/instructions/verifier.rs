use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::ProgramResult;

use crate::error::SwapError;

const PROOF_ERR: SwapError = SwapError::ProofVerificationFailed;

pub struct CompressedGroth16Proof<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
    pub commitment: Option<(&'a [u8; 32], &'a [u8; 32])>,
}

#[inline(never)]
pub fn verify_groth16(
    proof: CompressedGroth16Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> ProgramResult {
    let proof_a = decompress_g1(proof.a).map_err(|_| PROOF_ERR)?;
    let proof_b = decompress_g2(proof.b).map_err(|_| PROOF_ERR)?;
    let proof_c = decompress_g1(proof.c).map_err(|_| PROOF_ERR)?;
    let public_inputs = [public_input_hash];

    match (proof.commitment, verifying_key.vk_commitment.is_some()) {
        (Some((commitment, commitment_pok)), true) => {
            let commitment = decompress_g1(commitment).map_err(|_| PROOF_ERR)?;
            let commitment_pok = decompress_g1(commitment_pok).map_err(|_| PROOF_ERR)?;
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
        }
        (None, false) => {
            let mut verifier =
                Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
                    .map_err(|_| PROOF_ERR)?;
            verifier.verify().map_err(|_| PROOF_ERR)?;
        }
        _ => return Err(PROOF_ERR.into()),
    }
    Ok(())
}
