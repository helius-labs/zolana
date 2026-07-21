use groth16_solana::groth16::negate_g1_be;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};

use crate::ffi::{self, ProveOutput};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("ffi error: {0}")]
    Ffi(#[from] ffi::Error),
    #[error("compress G1 failed: {0}")]
    CompressG1(String),
    #[error("compress G2 failed: {0}")]
    CompressG2(String),
}

// Compressed, negated Groth16 proof ready for the on-chain verifier. All four
// dynamic-swap circuits are standard Groth16 (no BSB22 commitment), so the
// verifier uses `Groth16Verifier::new`; the SDK reads only `proof_a`/`proof_b`/
// `proof_c` into the program's `*Proof` instruction-data types.
#[derive(Debug, Clone, Copy)]
pub struct OrderProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
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
    })
}
