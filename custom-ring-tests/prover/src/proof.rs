//! Turns a raw gnark proof into the on-chain proof encoding.

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
    #[error("the auditor_key_encryption proof is missing its BSB22 commitment")]
    MissingCommitment,
}

/// The five fields the program's wincode `AuditProof` reads, in that order.
///
/// `proof_a` is already negated, every point is compressed big-endian. The
/// commitment pair is not optional: the emulated P-256 arithmetic in the circuit
/// always emits exactly one BSB22 commitment, so a proof without one cannot
/// verify against this circuit's verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

pub(crate) fn negate_and_compress_proof_with_commitment(
    out: &ProveOutput,
) -> Result<AuditProof, ProofError> {
    // The Go side zeroes the whole result struct and only fills the commitment
    // fields when the proof carries one, so all-zero bytes mean "no commitment"
    // rather than a valid point at infinity.
    if out.proof_commitment.iter().all(|b| *b == 0) {
        return Err(ProofError::MissingCommitment);
    }

    let neg_a = negate_g1_be(&out.proof_a);

    let proof_a =
        alt_bn128_g1_compress_be(&neg_a).map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
    let proof_b = alt_bn128_g2_compress_be(&out.proof_b)
        .map_err(|e| ProofError::CompressG2(format!("{e:?}")))?;
    let proof_c = alt_bn128_g1_compress_be(&out.proof_c)
        .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
    let commitment = alt_bn128_g1_compress_be(&out.proof_commitment)
        .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
    let commitment_pok = alt_bn128_g1_compress_be(&out.proof_commitment_pok)
        .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;

    Ok(AuditProof {
        proof_a,
        proof_b,
        proof_c,
        commitment,
        commitment_pok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uncompressed big-endian G1 encoding of small coordinates. The
    /// compression path deserializes without curve validation, so the point does
    /// not have to be on the curve for these encoding assertions.
    fn g1_be(x: u8, y: u8) -> [u8; 64] {
        let mut out = [0u8; 64];
        if let Some(byte) = out.get_mut(31) {
            *byte = x;
        }
        if let Some(byte) = out.get_mut(63) {
            *byte = y;
        }
        out
    }

    fn g2_be(x0: u8, y0: u8) -> [u8; 128] {
        let mut out = [0u8; 128];
        if let Some(byte) = out.get_mut(63) {
            *byte = x0;
        }
        if let Some(byte) = out.get_mut(127) {
            *byte = y0;
        }
        out
    }

    fn prove_output() -> ProveOutput {
        ProveOutput {
            proof_a: g1_be(1, 2),
            proof_b: g2_be(1, 2),
            proof_c: g1_be(3, 4),
            public_input_hash: [9u8; 32],
            proof_commitment: g1_be(5, 6),
            proof_commitment_pok: g1_be(7, 8),
        }
    }

    fn compress(point: &[u8; 64]) -> [u8; 32] {
        alt_bn128_g1_compress_be(point).expect("compression of a small-coordinate point")
    }

    #[test]
    fn only_proof_a_is_negated() {
        let out = prove_output();
        let proof = negate_and_compress_proof_with_commitment(&out).expect("conversion");

        assert_eq!(proof.proof_a, compress(&negate_g1_be(&out.proof_a)));
        assert_ne!(proof.proof_a, compress(&out.proof_a));

        for (got, raw) in [
            (proof.proof_c, out.proof_c),
            (proof.commitment, out.proof_commitment),
            (proof.commitment_pok, out.proof_commitment_pok),
        ] {
            assert_eq!(got, compress(&raw));
            assert_ne!(got, compress(&negate_g1_be(&raw)));
        }

        assert_eq!(
            proof.proof_b,
            alt_bn128_g2_compress_be(&out.proof_b).expect("g2 compression")
        );
    }

    #[test]
    fn an_absent_commitment_is_rejected() {
        let mut out = prove_output();
        out.proof_commitment = [0u8; 64];
        assert!(matches!(
            negate_and_compress_proof_with_commitment(&out),
            Err(ProofError::MissingCommitment)
        ));
    }
}
