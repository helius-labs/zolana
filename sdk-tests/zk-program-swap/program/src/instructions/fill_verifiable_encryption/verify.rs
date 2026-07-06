use light_program_profiler::profile;
use pinocchio::{error::ProgramError, ProgramResult};

use crate::{
    instructions::{
        fill_verifiable_encryption::FillVerifiableEncryptionProof,
        shared::u64_to_field,
        verifier::{ciphertext_hash, poseidon3, verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::fill_verifiable_encryption,
};

pub struct FillVerifiableEncryptionPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub expiry: u64,
    pub destination_ciphertext: &'a [u8],
}

impl FillVerifiableEncryptionPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        fill_verifiable_encryption_public_input_hash(self)
    }

    pub fn verify(&self, proof: &FillVerifiableEncryptionProof) -> ProgramResult {
        verify_fill_verifiable_encryption_zk_proof(proof, self.hash()?)
    }
}

#[profile]
pub fn fill_verifiable_encryption_public_input_hash(
    input: &FillVerifiableEncryptionPublicInput<'_>,
) -> Result<[u8; 32], ProgramError> {
    let ct_hash = ciphertext_hash(input.destination_ciphertext)?;
    poseidon3(input.private_tx_hash, &u64_to_field(input.expiry), &ct_hash)
}

#[profile]
pub fn verify_fill_verifiable_encryption_zk_proof(
    proof: &FillVerifiableEncryptionProof,
    public_input_hash: [u8; 32],
) -> ProgramResult {
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: Some((&proof.commitment, &proof.commitment_pok)),
        },
        public_input_hash,
        &fill_verifiable_encryption::VERIFYINGKEY,
    )
}
