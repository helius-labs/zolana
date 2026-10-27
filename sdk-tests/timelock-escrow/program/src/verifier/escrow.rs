use zolana_program::{verifier::{groth16_solana, public_hash, verify_groth16, Field, VerifyError}, transaction_hash, CompressedProof, PublicTransfer};

include!("escrow.vk.rs");

pub struct PublicInputs {
    pub escrow_owner: [u8; 32],
    pub creator_identity: [u8; 32],
}

impl PublicInputs {
    pub fn hash(&self, transaction_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
        public_hash(&[Field::Hash(&self.escrow_owner), Field::Hash(&self.creator_identity)], transaction_hash)
    }
}

pub struct Verifier<'a> {
    pub proof: &'a CompressedProof,
    pub public_inputs: PublicInputs,
    pub private_tx_hash: &'a [u8; 32],
    pub transfers: &'a [PublicTransfer],
}

impl Verifier<'_> {
    pub fn verify(&self) -> Result<(), VerifyError> {
        let transaction_hash = transaction_hash(self.private_tx_hash, self.transfers)
            .map_err(|_| VerifyError::PublicInputs)?;
        verify_groth16(self.proof, self.public_inputs.hash(&transaction_hash)?, &VERIFYINGKEY)
    }
}
