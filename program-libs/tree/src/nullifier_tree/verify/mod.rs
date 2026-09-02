//! Groth16 proof verification for batched Merkle tree operations.
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`verify_batch_update`] | Verify batch address update (10 or 250) |
//! | [`verify`] | Generic Groth16 proof verification |

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};

use crate::nullifier_tree::{
    error::NullifierTreeError, proof::CompressedProof, verify::verifying_keys::*,
};

pub mod verifying_keys;

#[inline(never)]
pub fn verify<const N: usize>(
    public_inputs: &[[u8; 32]; N],
    proof: &CompressedProof,
    vk: &Groth16Verifyingkey,
) -> Result<(), NullifierTreeError> {
    let proof_a = decompress_g1(&proof.a).map_err(|_| NullifierTreeError::DecompressG1Failed)?;
    let proof_b = decompress_g2(&proof.b).map_err(|_| NullifierTreeError::DecompressG2Failed)?;
    let proof_c = decompress_g1(&proof.c).map_err(|_| NullifierTreeError::DecompressG1Failed)?;
    let mut verifier = Groth16Verifier::new(&proof_a, &proof_b, &proof_c, public_inputs, vk)
        .map_err(|_| {
            #[cfg(feature = "log")]
            {
                use solana_msg::msg;
                msg!("Proof verification failed");
                msg!("Public inputs: {:?}", public_inputs);
                msg!("Proof A: {:?}", proof_a);
                msg!("Proof B: {:?}", proof_b);
                msg!("Proof C: {:?}", proof_c);
            }
            NullifierTreeError::CreateGroth16VerifierFailed
        })?;
    verifier.verify().map_err(|_| {
        #[cfg(feature = "log")]
        {
            use solana_msg::msg;
            msg!("Proof verification failed");
            msg!("Public inputs: {:?}", public_inputs);
            msg!("Proof A: {:?}", proof_a);
            msg!("Proof B: {:?}", proof_b);
            msg!("Proof C: {:?}", proof_c);
        }
        NullifierTreeError::ProofVerificationFailed
    })?;
    Ok(())
}

#[inline(never)]
pub fn verify_batch_update(
    batch_size: u64,
    public_input_hash: [u8; 32],
    compressed_proof: &CompressedProof,
) -> Result<(), NullifierTreeError> {
    match batch_size {
        10 => verify::<1>(
            &[public_input_hash],
            compressed_proof,
            &batch_address_append_40_10::VERIFYINGKEY,
        ),
        250 => verify::<1>(
            &[public_input_hash],
            compressed_proof,
            &batch_address_append_40_250::VERIFYINGKEY,
        ),
        _ => Err(NullifierTreeError::InvalidBatchSize),
    }
}
