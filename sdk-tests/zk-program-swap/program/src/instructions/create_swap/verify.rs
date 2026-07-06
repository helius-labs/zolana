use light_program_profiler::profile;
use pinocchio::{error::ProgramError, ProgramResult};

use crate::{
    instructions::{
        create_swap::CreateProof,
        shared::{maker_address_fe, u64_to_field},
        verifier::{poseidon3, verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::create,
};

pub struct CreatePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub source_asset_id: u64,
    pub maker_address: &'a [u8; 65],
}

impl CreatePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        create_public_input_hash(self)
    }

    pub fn verify(&self, proof: &CreateProof) -> ProgramResult {
        verify_create_zk_proof(proof, self.hash()?)
    }
}

#[profile]
pub fn create_public_input_hash(input: &CreatePublicInput<'_>) -> Result<[u8; 32], ProgramError> {
    let mut owner_hash = [0u8; 32];
    owner_hash.copy_from_slice(&input.maker_address[0..32]);
    let mut viewing_pk = [0u8; 33];
    viewing_pk.copy_from_slice(&input.maker_address[32..65]);
    let maker_fe = maker_address_fe(&owner_hash, &viewing_pk)?;
    poseidon3(
        input.private_tx_hash,
        &u64_to_field(input.source_asset_id),
        &maker_fe,
    )
}

#[profile]
pub fn verify_create_zk_proof(proof: &CreateProof, public_input_hash: [u8; 32]) -> ProgramResult {
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        public_input_hash,
        &create::VERIFYINGKEY,
    )
}
