use spr_program::{
    verifier::{groth16_solana, integer, pack_be, verify_groth16, VerifyError},
    CompressedProof,
};

include!("withdrawal.vk.rs");

pub struct PublicInputs {
    pub commitment: [u8; 32],
    pub amount: u64,
    pub destination: [u8; 32],
}

impl PublicInputs {
    pub fn public_inputs(&self) -> [[u8; 32]; 4] {
        let [destination_0, destination_1] = pack_be::<32, 2>(&self.destination);
        [
            self.commitment,
            integer(u128::from(self.amount)),
            destination_0,
            destination_1,
        ]
    }
}

pub fn verify(proof: &CompressedProof, public_inputs: &PublicInputs) -> Result<(), VerifyError> {
    verify_groth16(proof, &public_inputs.public_inputs(), &VERIFYINGKEY)
}
