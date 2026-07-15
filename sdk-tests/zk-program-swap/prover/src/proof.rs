use groth16_solana::groth16::negate_g1_be;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use swap_program::instructions::{
    cancel::CancelProof, make::MakeProof, take::TakeProof,
    take_verifiable_encryption::TakeVerifiableEncryptionProof,
};

use crate::ffi::{self, ProveOutput};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("ffi error: {0}")]
    Ffi(#[from] ffi::Error),
    #[error("compress G1 failed: {0}")]
    CompressG1(String),
    #[error("compress G2 failed: {0}")]
    CompressG2(String),
    #[error("take_verifiable_encryption proof is missing its BSB22 commitment")]
    MissingCommitment,
}

#[derive(Debug, Clone, Copy)]
pub struct OrderProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: Option<([u8; 32], [u8; 32])>,
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
    type Error = ProofError;

    fn try_from(proof: OrderProof) -> Result<Self, Self::Error> {
        let (commitment, commitment_pok) = proof.commitment.ok_or(ProofError::MissingCommitment)?;
        Ok(Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
            commitment,
            commitment_pok,
        })
    }
}

pub(crate) fn negate_and_compress_proof(out: &ProveOutput) -> Result<OrderProof, ProofError> {
    let neg_a = negate_g1_be(&out.proof_a);

    let proof_a =
        alt_bn128_g1_compress_be(&neg_a).map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
    let proof_b = alt_bn128_g2_compress_be(&out.proof_b)
        .map_err(|e| ProofError::CompressG2(format!("{e:?}")))?;
    let proof_c = alt_bn128_g1_compress_be(&out.proof_c)
        .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;

    Ok(OrderProof {
        proof_a,
        proof_b,
        proof_c,
        commitment: None,
    })
}

pub(crate) fn negate_and_compress_proof_with_commitment(
    out: &ProveOutput,
) -> Result<OrderProof, ProofError> {
    let mut proof = negate_and_compress_proof(out)?;
    let commitment = alt_bn128_g1_compress_be(&out.proof_commitment)
        .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
    let commitment_pok = alt_bn128_g1_compress_be(&out.proof_commitment_pok)
        .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
    proof.commitment = Some((commitment, commitment_pok));
    Ok(proof)
}
