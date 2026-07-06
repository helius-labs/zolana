use light_program_profiler::profile;
use pinocchio::{error::ProgramError, ProgramResult};

use crate::{
    instructions::{
        cancel::CancelProof,
        shared::u64_to_field,
        verifier::{poseidon3, verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::cancel,
};

pub struct CancelPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub expiry: u64,
    pub maker_owner_pk_field: &'a [u8; 32],
}

impl CancelPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        cancel_public_input_hash(self)
    }

    pub fn verify(&self, proof: &CancelProof) -> ProgramResult {
        verify_cancel_zk_proof(proof, self.hash()?)
    }
}

#[profile]
pub fn cancel_public_input_hash(input: &CancelPublicInput<'_>) -> Result<[u8; 32], ProgramError> {
    poseidon3(
        input.private_tx_hash,
        &u64_to_field(input.expiry),
        input.maker_owner_pk_field,
    )
}

#[profile]
pub fn verify_cancel_zk_proof(proof: &CancelProof, public_input_hash: [u8; 32]) -> ProgramResult {
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        public_input_hash,
        &cancel::VERIFYINGKEY,
    )
}
