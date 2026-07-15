use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};

use crate::error::SwapError;

const PROOF_ERR: SwapError = SwapError::ProofVerificationFailed;

// TODO: inline and remove this fn
pub fn poseidon2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[a.as_slice(), b.as_slice()]).map_err(|_| PROOF_ERR.into())
}

// TODO: inline and remove this fn and implement proper error conversion
pub fn poseidon3(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[a.as_slice(), b.as_slice(), c.as_slice()]).map_err(|_| PROOF_ERR.into())
}

#[inline(never)]
pub fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], ProgramError> {
    let chunks: Vec<[u8; 32]> = ciphertext.chunks(16).map(right_align_16).collect();
    let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    Poseidon::hashv(&refs).map_err(|_| PROOF_ERR.into())
}

fn right_align_16(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    if let (Some(destination), Some(source)) = (out.get_mut(32 - len..32), bytes.get(..len)) {
        destination.copy_from_slice(source);
    }
    out
}

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

    match (proof.commitment, verifying_key.vk_commitment_g2.is_some()) {
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
