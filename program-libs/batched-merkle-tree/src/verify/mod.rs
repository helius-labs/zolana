//! Groth16 proof verification for batched Merkle tree operations.
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`verify_batch_address_update`] | Verify batch address update (10 or 250) |
//! | [`verify`] | Generic Groth16 proof verification |

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use thiserror::Error;

use crate::verify::verifying_keys::*;

pub mod verifying_keys;

#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshDeserialize, borsh::BorshSerialize)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl Default for CompressedProof {
    fn default() -> Self {
        Self {
            a: [0; 32],
            b: [0; 64],
            c: [0; 32],
        }
    }
}

impl CompressedProof {
    pub fn to_array(&self) -> [u8; 128] {
        let mut result = [0u8; 128];
        result[0..32].copy_from_slice(&self.a);
        result[32..96].copy_from_slice(&self.b);
        result[96..128].copy_from_slice(&self.c);
        result
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum VerifierError {
    #[error("PublicInputsTryIntoFailed")]
    PublicInputsTryIntoFailed,
    #[error("DecompressG1Failed")]
    DecompressG1Failed,
    #[error("DecompressG2Failed")]
    DecompressG2Failed,
    #[error("InvalidPublicInputsLength")]
    InvalidPublicInputsLength,
    #[error("CreateGroth16VerifierFailed")]
    CreateGroth16VerifierFailed,
    #[error("ProofVerificationFailed")]
    ProofVerificationFailed,
    #[error("InvalidBatchSize supported batch sizes are 1, 10, 100, 500, 1000")]
    InvalidBatchSize,
    #[error("Invalid proof size: expected 128 bytes, got {0}")]
    InvalidProofSize(usize),
}

impl From<VerifierError> for u32 {
    fn from(e: VerifierError) -> u32 {
        match e {
            PublicInputsTryIntoFailed => 13001,
            DecompressG1Failed => 13002,
            DecompressG2Failed => 13003,
            InvalidPublicInputsLength => 13004,
            CreateGroth16VerifierFailed => 13005,
            ProofVerificationFailed => 13006,
            InvalidBatchSize => 13007,
            InvalidProofSize(_) => 13008,
        }
    }
}

impl From<VerifierError> for solana_program_error::ProgramError {
    fn from(e: VerifierError) -> Self {
        solana_program_error::ProgramError::Custom(e.into())
    }
}

use VerifierError::*;

impl TryFrom<&[u8]> for CompressedProof {
    type Error = VerifierError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 128 {
            return Err(InvalidProofSize(bytes.len()));
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 64];
        let mut c = [0u8; 32];
        a.copy_from_slice(&bytes[0..32]);
        b.copy_from_slice(&bytes[32..96]);
        c.copy_from_slice(&bytes[96..128]);
        Ok(Self { a, b, c })
    }
}

#[inline(never)]
pub fn verify<const N: usize>(
    public_inputs: &[[u8; 32]; N],
    proof: &CompressedProof,
    vk: &Groth16Verifyingkey,
) -> Result<(), VerifierError> {
    let proof_a = decompress_g1(&proof.a).map_err(|_| DecompressG1Failed)?;
    let proof_b = decompress_g2(&proof.b).map_err(|_| DecompressG2Failed)?;
    let proof_c = decompress_g1(&proof.c).map_err(|_| DecompressG1Failed)?;
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
            CreateGroth16VerifierFailed
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
        ProofVerificationFailed
    })?;
    Ok(())
}

#[inline(never)]
pub fn verify_batch_address_update(
    batch_size: u64,
    public_input_hash: [u8; 32],
    compressed_proof: &CompressedProof,
) -> Result<(), VerifierError> {
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
        _ => Err(InvalidPublicInputsLength),
    }
}
