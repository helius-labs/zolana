use zolana_program::{
    transaction_hash,
    verifier::{groth16_solana, public_hash, verify_groth16, Field, VerifyError},
    CompressedProof, PublicTransfer,
};

include!("escrow_open.vk.rs");

pub struct PublicInputs {
    pub escrow_authority_owner_hash: [u8; 32],
    pub source_asset: [u8; 32],
    pub public_price_floor: u64,
    pub price_tolerance: u64,
    pub min_order_amount: u64,
    pub max_order_size: u64,
}

impl PublicInputs {
    pub fn hash(&self, transaction_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
        public_hash(
            &[
                Field::Hash(&self.escrow_authority_owner_hash),
                Field::Hash(&self.source_asset),
                Field::Integer(u128::from(self.public_price_floor)),
                Field::Integer(u128::from(self.price_tolerance)),
                Field::Integer(u128::from(self.min_order_amount)),
                Field::Integer(u128::from(self.max_order_size)),
            ],
            transaction_hash,
        )
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
        verify_groth16(
            self.proof,
            self.public_inputs.hash(&transaction_hash)?,
            &VERIFYINGKEY,
        )
    }
}
