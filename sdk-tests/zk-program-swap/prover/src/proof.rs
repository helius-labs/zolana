use swap_program::instructions::{
    cancel::CancelProof, make::MakeProof, take::TakeProof,
    take_verifiable_encryption::TakeVerifiableEncryptionProof,
};
use zolana_gnark_ffi_prover::CompressedProof;

#[derive(Debug, Clone, Copy)]
pub struct OrderProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    /// The BSB22 commitment and its proof of knowledge. Only
    /// take_verifiable_encryption is registered with one.
    pub commitment: Option<([u8; 32], [u8; 32])>,
}

impl From<CompressedProof> for OrderProof {
    fn from(proof: CompressedProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
            commitment: proof.commitment,
        }
    }
}

impl From<OrderProof> for MakeProof {
    fn from(proof: OrderProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

impl From<OrderProof> for TakeProof {
    fn from(proof: OrderProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

impl From<OrderProof> for CancelProof {
    fn from(proof: OrderProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

impl TryFrom<OrderProof> for TakeVerifiableEncryptionProof {
    type Error = zolana_gnark_ffi_prover::Error;

    fn try_from(proof: OrderProof) -> Result<Self, Self::Error> {
        let (commitment, commitment_pok) = proof
            .commitment
            .ok_or(zolana_gnark_ffi_prover::Error::MissingCommitment)?;
        Ok(Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
            commitment,
            commitment_pok,
        })
    }
}
