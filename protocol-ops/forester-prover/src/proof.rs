use crate::{error::Result, key::ExpectedProvingKey, Error};
use groth16_solana::groth16::negate_g1_be;
use num_bigint::BigUint;
use serde::Deserialize;
use solana_bn254::compression::prelude::alt_bn128_g1_compress_be;
use spr_interface::instruction::NullifierTreeProof;

#[derive(Debug)]
pub struct Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}
impl Proof {
    pub fn compress(self) -> Result<NullifierTreeProof> {
        let compress = |point: &[u8; 64]| {
            alt_bn128_g1_compress_be(point)
                .map_err(|error| Error::ProofParse(format!("G1 compression: {error:?}")))
        };
        Ok(NullifierTreeProof {
            a: compress(&self.a)?,
            b: self.b,
            c: compress(&self.c)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GnarkProof {
    ar: [String; 2],
    bs: [[String; 2]; 2],
    krs: [String; 2],
    proving_key_sha256: Option<String>,
    #[serde(default)]
    proof_commitment: Vec<String>,
    #[serde(default)]
    proof_commitment_pok: Vec<String>,
}
pub(crate) fn coordinate(text: &str) -> Result<[u8; 32]> {
    let value = BigUint::parse_bytes(text.strip_prefix("0x").unwrap_or(text).as_bytes(), 16)
        .ok_or_else(|| Error::ProofParse("invalid hexadecimal coordinate".into()))?;
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(Error::ProofParse("coordinate exceeds 32 bytes".into()));
    }
    let mut coordinate_be = [0; 32];
    coordinate_be[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(coordinate_be)
}
fn point(pair: &[String; 2]) -> Result<[u8; 64]> {
    let mut point = [0; 64];
    point[..32].copy_from_slice(&coordinate(&pair[0])?);
    point[32..].copy_from_slice(&coordinate(&pair[1])?);
    Ok(point)
}
pub(crate) fn decode(value: &serde_json::Value, key: &ExpectedProvingKey) -> Result<Proof> {
    let json: GnarkProof = serde_json::from_value(value.get("proof").unwrap_or(value).clone())
        .map_err(|error| Error::ProofParse(error.to_string()))?;
    key.check(json.proving_key_sha256.as_deref())?;
    if !json.proof_commitment.is_empty() || !json.proof_commitment_pok.is_empty() {
        return Err(Error::ProofParse(
            "batch proofs must not carry commitments".into(),
        ));
    }
    let mut b = [0; 128];
    b[..64].copy_from_slice(&point(&json.bs[0])?);
    b[64..].copy_from_slice(&point(&json.bs[1])?);
    Ok(Proof {
        a: negate_g1_be(&point(&json.ar)?),
        b,
        c: point(&json.krs)?,
    })
}
pub(crate) fn verify(proof: &NullifierTreeProof, hash: [u8; 32], size: u32) -> Result<()> {
    spr_tree::nullifier_tree::verify::verify_batch_update(
        u64::from(size),
        hash,
        &spr_tree::nullifier_tree::proof::NullifierTreeProof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        },
    )
    .map_err(|error| Error::ProofVerification(format!("invalid batch proof: {error:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_coordinates_are_rejected_without_truncation() {
        for value in ["", "0x", "-1", "xyz", &format!("1{}", "00".repeat(32))] {
            assert!(
                matches!(coordinate(value), Err(Error::ProofParse(_))),
                "{value}"
            );
        }
    }
}
