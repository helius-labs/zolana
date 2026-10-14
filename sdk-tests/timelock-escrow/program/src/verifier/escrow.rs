use zolana_program::{
    verifier::{groth16_solana, public_hash, verify_groth16, Field, VerifyError},
    CompressedProof,
};

include!("escrow.vk.rs");

pub struct PublicInputs {
    pub escrow_owner: [u8; 32],
    pub creator_identity: [u8; 32],
}

impl PublicInputs {
    pub fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
        public_hash(
            &[
                Field::Hash(&self.escrow_owner),
                Field::Hash(&self.creator_identity),
            ],
            private_tx_hash,
        )
    }
}

pub fn verify(
    proof: &CompressedProof,
    public_inputs: &PublicInputs,
    private_tx_hash: &[u8; 32],
) -> Result<(), VerifyError> {
    verify_groth16(proof, public_inputs.hash(private_tx_hash)?, &VERIFYINGKEY)
}
