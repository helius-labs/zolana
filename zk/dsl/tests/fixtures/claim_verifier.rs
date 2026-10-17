use zolana_program::{
    verifier::{boolean, groth16_solana, integer, pack_be, verify_groth16, VerifyError},
    CompressedProof,
};

include!("claim.vk.rs");

pub struct PublicInputs {
    pub amount: u64,
    pub paid: bool,
    pub root: [u8; 32],
    pub destination: [u8; 32],
    pub limits: [u16; 2],
}

impl PublicInputs {
    pub fn public_inputs(&self) -> [[u8; 32]; 7] {
        let [destination_0, destination_1] = pack_be::<32, 2>(&self.destination);
        let [limits_0, limits_1] = &self.limits;
        [
            integer(u128::from(self.amount)),
            boolean(self.paid),
            self.root,
            destination_0,
            destination_1,
            integer(u128::from(*limits_0)),
            integer(u128::from(*limits_1)),
        ]
    }
}

pub fn verify(proof: &CompressedProof, public_inputs: &PublicInputs) -> Result<(), VerifyError> {
    verify_groth16(proof, &public_inputs.public_inputs(), &VERIFYINGKEY)
}
