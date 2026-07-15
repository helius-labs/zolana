use light_program_profiler::profile;
use pinocchio::ProgramResult;

use crate::{
    instructions::{
        create_swap::CreateProof,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::create,
};
// TODO: inline and remove this file
#[profile]
pub fn verify_create_zk_proof(proof: &CreateProof, private_tx_hash: [u8; 32]) -> ProgramResult {
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        private_tx_hash,
        &create::VERIFYINGKEY,
    )
}
