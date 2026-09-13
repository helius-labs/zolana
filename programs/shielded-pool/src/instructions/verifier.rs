//! Shared Groth16 proof verification, reused by every proof-bearing instruction
//! (`transact`, `merge_transact`). `verify_groth16` decompresses the G1 proof
//! points and runs the pairing check.

use crate::instructions::shared::caused_by;
use groth16_solana::{
    decompression::decompress_g1,
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use light_program_profiler::profile;
use pinocchio::ProgramResult;
use zolana_interface::error::ShieldedPoolError;

/// The Groth16 proof points handed to [`verify_groth16`]: the G1 points (`a`,
/// `c`, and the BSB22 pair) are compressed, `b` is the raw big-endian G2 point.
/// The pairing syscall validates `b` (curve and subgroup membership) when it
/// converts the point, so no separate decompression or check is needed.
pub struct Groth16Proof<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 128],
    pub c: &'a [u8; 32],
    pub commitment: Option<(&'a [u8; 32], &'a [u8; 32])>,
}

/// Decompress the G1 proof points and verify the proof against `verifying_key`
/// for the single `public_input_hash`.
#[inline(never)]
#[profile]
pub fn verify_groth16(
    proof: Groth16Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    let proof_a = decompress_g1(proof.a).map_err(caused_by(encoding_err))?;
    let proof_b = proof.b;
    let proof_c = decompress_g1(proof.c).map_err(caused_by(encoding_err))?;
    let public_inputs = [public_input_hash];

    match (proof.commitment, verifying_key.vk_commitment.is_some()) {
        (Some((commitment, commitment_pok)), true) => {
            let commitment = decompress_g1(commitment).map_err(caused_by(encoding_err))?;
            let commitment_pok = decompress_g1(commitment_pok).map_err(caused_by(encoding_err))?;
            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                proof_b,
                &proof_c,
                &commitment,
                &commitment_pok,
                &public_inputs,
                verifying_key,
            )
            .map_err(caused_by(verify_err))?;
            verifier.verify().map_err(caused_by(verify_err))?;
        }
        (None, false) => {
            let mut verifier =
                Groth16Verifier::new(&proof_a, proof_b, &proof_c, &public_inputs, verifying_key)
                    .map_err(caused_by(verify_err))?;
            verifier.verify().map_err(caused_by(verify_err))?;
        }
        _ => return Err(verify_err.into()),
    }
    Ok(())
}
