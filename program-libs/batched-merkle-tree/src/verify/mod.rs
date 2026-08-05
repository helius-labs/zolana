//! Groth16 proof verification for batched Merkle tree operations.

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
    #[error("InvalidBatchSize supported batch sizes are 10 and 250")]
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

/// A fold proof and its BSB22 commitment. The recursion verifier commits
/// internally, so every fold proof carries one whether or not the folded
/// circuit uses lookups.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, borsh::BorshDeserialize, borsh::BorshSerialize,
)]
pub struct CommittedProof {
    pub proof: CompressedProof,
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

/// Verify a Groth16 proof whose verifying key carries a BSB22 Pedersen
/// commitment over private wires.
///
/// The Pedersen proof of knowledge is what binds the commitment to the prover.
/// Verifying the pairing without it would accept a commitment the prover cannot
/// open, so the two must be checked together.
pub fn verify_committed<const N: usize>(
    public_inputs: &[[u8; 32]; N],
    proof: &CommittedProof,
    vk: &Groth16Verifyingkey,
) -> Result<(), VerifierError> {
    if vk.vk_commitment.is_none() {
        return Err(CreateGroth16VerifierFailed);
    }
    let proof_a = decompress_g1(&proof.proof.a).map_err(|_| DecompressG1Failed)?;
    let proof_b = decompress_g2(&proof.proof.b).map_err(|_| DecompressG2Failed)?;
    let proof_c = decompress_g1(&proof.proof.c).map_err(|_| DecompressG1Failed)?;
    let commitment = decompress_g1(&proof.commitment).map_err(|_| DecompressG1Failed)?;
    let commitment_pok = decompress_g1(&proof.commitment_pok).map_err(|_| DecompressG1Failed)?;

    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof_a,
        &proof_b,
        &proof_c,
        &commitment,
        &commitment_pok,
        public_inputs,
        vk,
    )
    .map_err(|_| CreateGroth16VerifierFailed)?;
    verifier.verify().map_err(|_| ProofVerificationFailed)
}

/// Whether a fold verifying key exists for this (tree height, batch size, run).
pub const fn is_supported_batch_address_fold(tree_height: u32, batch_size: u64, run: u32) -> bool {
    matches!((tree_height, batch_size, run), (40, 10, 2))
}

/// Verify a folded run of address appends.
///
/// One fold key exists per (tree height, batch size, run) triple, because the
/// fold compiles in the append verifying key and the run is a compile-time
/// width, so a caller cannot fold a run the key was not built for.
#[inline(never)]
pub fn verify_batch_address_fold(
    tree_height: u32,
    batch_size: u64,
    run: u32,
    public_input_hash: [u8; 32],
    proof: &CommittedProof,
) -> Result<(), VerifierError> {
    match (tree_height, batch_size, run) {
        (40, 10, 2) => verify_committed::<1>(
            &[public_input_hash],
            proof,
            &nullifier_fold_40_10_r2::VERIFYINGKEY,
        ),
        _ => Err(InvalidBatchSize),
    }
}

#[inline(never)]
pub fn verify_batch_address_update(
    batch_size: u64,
    public_input_hash: [u8; 32],
    compressed_proof: &CompressedProof,
) -> Result<(), VerifierError> {
    verify::<1>(
        &[public_input_hash],
        compressed_proof,
        address_append_vk(batch_size)?,
    )
}

fn address_append_vk(
    batch_size: u64,
) -> Result<&'static Groth16Verifyingkey<'static>, VerifierError> {
    match batch_size {
        10 => Ok(&batch_address_append_40_10::VERIFYINGKEY),
        250 => Ok(&batch_address_append_40_250::VERIFYINGKEY),
        _ => Err(InvalidBatchSize),
    }
}
