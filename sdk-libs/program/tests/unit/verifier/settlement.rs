use zolana_program::{
    verifier::{groth16_solana, public_hash, verify_groth16, Field, VerifyError},
    CompressedProof,
};

include!("settlement.vk.rs");

pub struct PublicInputs {
    pub amount: u64,
    pub paid: bool,
    pub recipient: [u8; 32],
    pub signers: [[u8; 32]; 2],
    pub limits: [[u32; 2]; 2],
}

impl PublicInputs {
    pub fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
        let [signers_0, signers_1] = &self.signers;
        let [[limits_0, limits_1], [limits_2, limits_3]] = &self.limits;
        public_hash(
            &[
                Field::Integer(u128::from(self.amount)),
                Field::Bool(self.paid),
                Field::Hash(&self.recipient),
                Field::Array(&[Field::Hash(signers_0), Field::Hash(signers_1)]),
                Field::Array(&[
                    Field::Array(&[
                        Field::Integer(u128::from(*limits_0)),
                        Field::Integer(u128::from(*limits_1)),
                    ]),
                    Field::Array(&[
                        Field::Integer(u128::from(*limits_2)),
                        Field::Integer(u128::from(*limits_3)),
                    ]),
                ]),
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
