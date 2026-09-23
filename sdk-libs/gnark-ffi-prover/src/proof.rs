use groth16_solana::groth16::negate_g1_be;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};

use crate::{Error, Result};

/// A Groth16 proof as gnark returns it: uncompressed big-endian points.
#[derive(Debug, Clone)]
pub struct ProveOutput {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub public_input_hash: [u8; 32],
    /// Present exactly when the circuit is registered with one BSB22
    /// commitment.
    pub commitment: Option<Commitment>,
}

#[derive(Debug, Clone)]
pub struct Commitment {
    pub commitment: [u8; 64],
    pub pok: [u8; 64],
}

/// A proof in the form the on-chain verifier takes: `proof_a` negated, every
/// point compressed.
#[derive(Debug, Clone, Copy)]
pub struct CompressedProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    /// The BSB22 commitment and its proof of knowledge.
    pub commitment: Option<([u8; 32], [u8; 32])>,
}

impl ProveOutput {
    pub fn compress(&self) -> Result<CompressedProof> {
        let commitment = self
            .commitment
            .as_ref()
            .map(|commitment| -> Result<_> {
                Ok((
                    compress_g1(&commitment.commitment)?,
                    compress_g1(&commitment.pok)?,
                ))
            })
            .transpose()?;
        Ok(CompressedProof {
            proof_a: compress_g1(&negate_g1_be(&self.proof_a))?,
            proof_b: alt_bn128_g2_compress_be(&self.proof_b)
                .map_err(|e| Error::CompressG2(format!("{e:?}")))?,
            proof_c: compress_g1(&self.proof_c)?,
            commitment,
        })
    }
}

fn compress_g1(point: &[u8; 64]) -> Result<[u8; 32]> {
    alt_bn128_g1_compress_be(point).map_err(|e| Error::CompressG1(format!("{e:?}")))
}
