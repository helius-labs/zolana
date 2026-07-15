use light_program_profiler::profile;
use pinocchio::{error::ProgramError, ProgramResult};

use crate::{
    instructions::{
        fill::FillProof,
        shared::u64_to_field,
        verifier::{poseidon2, verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::fill,
};

pub struct FillPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub expiry: u64,
}

impl FillPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        fill_public_input_hash(self)
    }

    pub fn verify(&self, proof: &FillProof) -> ProgramResult {
        verify_fill_zk_proof(proof, self.hash()?)
    }
}
// TODO: inline and remove this fn
#[profile]
pub fn fill_public_input_hash(input: &FillPublicInput<'_>) -> Result<[u8; 32], ProgramError> {
    poseidon2(input.private_tx_hash, &u64_to_field(input.expiry))
}

// TODO: inline and remove this fn
#[profile]
pub fn verify_fill_zk_proof(proof: &FillProof, public_input_hash: [u8; 32]) -> ProgramResult {
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        public_input_hash,
        &fill::VERIFYINGKEY,
    )
}
