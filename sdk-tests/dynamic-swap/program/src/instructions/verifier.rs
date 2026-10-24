use wincode::{SchemaRead, SchemaWrite};
use zolana_program::CompressedProof;

/// The compressed Groth16 proof carried by a dynamic-swap instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Groth16ProofBytes {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

impl Groth16ProofBytes {
    pub fn to_compressed(&self) -> CompressedProof {
        CompressedProof {
            a: self.proof_a,
            b: self.proof_b,
            c: self.proof_c,
        }
    }
}
