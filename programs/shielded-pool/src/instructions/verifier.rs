//! Shared Groth16 proof verification, reused by every proof-bearing instruction
//! (`transact`, `merge_transact`). `verify_groth16` decompresses the proof points
//! and runs the pairing check.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use light_program_profiler::profile;
use pinocchio::ProgramResult;
use zolana_interface::error::ShieldedPoolError;

/// The compressed Groth16 proof points handed to [`verify_groth16`].
pub struct CompressedGroth16Proof<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
    pub commitment: Option<(&'a [u8; 32], &'a [u8; 32])>,
}

/// Decompress the compressed proof points and verify them against `verifying_key`
/// for the single `public_input_hash`.
#[inline(never)]
#[profile]
pub fn verify_groth16(
    proof: CompressedGroth16Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    let proof_a = decompress_g1(proof.a).map_err(|_| encoding_err)?;
    let proof_b = decompress_g2(proof.b).map_err(|_| encoding_err)?;
    let proof_c = decompress_g1(proof.c).map_err(|_| encoding_err)?;
    let public_inputs = [public_input_hash];

    match (proof.commitment, verifying_key.vk_commitment.is_some()) {
        (Some((commitment, commitment_pok)), true) => {
            let commitment = decompress_g1(commitment).map_err(|_| encoding_err)?;
            let commitment_pok = decompress_g1(commitment_pok).map_err(|_| encoding_err)?;
            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                &commitment,
                &commitment_pok,
                &public_inputs,
                verifying_key,
            )
            .map_err(|_| verify_err)?;
            verifier.verify().map_err(|_| verify_err)?;
        }
        (None, false) => {
            let mut verifier =
                Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
                    .map_err(|_| verify_err)?;
            verifier.verify().map_err(|_| verify_err)?;
        }
        _ => return Err(verify_err.into()),
    }
    Ok(())
}

/// Registered verification against a finalized VK-registry account whose
/// address the caller has already matched to the circuit's spec. Borrows the
/// prepared blobs and the GT target in place; the syscalls validate their
/// encoding, the address commitment is the provenance.
#[cfg(feature = "vk-registry")]
#[inline(never)]
#[profile]
pub fn verify_groth16_registered(
    proof: CompressedGroth16Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
    registry_data: &[u8],
    spec: &zolana_interface::verifying_keys::registry_spec::VkRegistrySpec,
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    let refs = crate::instructions::vk_registry::prepared_vk_refs(registry_data, spec)?;

    let proof_a = decompress_g1(proof.a).map_err(|_| encoding_err)?;
    let proof_b = decompress_g2(proof.b).map_err(|_| encoding_err)?;
    let proof_c = decompress_g1(proof.c).map_err(|_| encoding_err)?;
    let public_inputs = [public_input_hash];

    match (proof.commitment, verifying_key.vk_commitment.is_some()) {
        (Some((commitment, commitment_pok)), true) => {
            let commitment = decompress_g1(commitment).map_err(|_| encoding_err)?;
            let commitment_pok = decompress_g1(commitment_pok).map_err(|_| encoding_err)?;
            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                &commitment,
                &commitment_pok,
                &public_inputs,
                verifying_key,
            )
            .map_err(|_| verify_err)?;
            verifier.verify_prepared(&refs).map_err(|_| verify_err)?;
        }
        (None, false) => {
            let mut verifier =
                Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
                    .map_err(|_| verify_err)?;
            verifier.verify_prepared(&refs).map_err(|_| verify_err)?;
        }
        _ => return Err(verify_err.into()),
    }
    Ok(())
}
