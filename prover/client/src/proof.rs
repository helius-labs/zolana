use serde::{Deserialize, Serialize};

use crate::errors::ProverClientError;
type G1 = ark_bn254::g1::G1Affine;
use std::ops::Neg;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use light_verifier::CompressedProof;
use num_traits::Num;
use solana_bn254::compression::prelude::{
    alt_bn128_g1_compress_be, alt_bn128_g1_decompress_be, alt_bn128_g2_compress_be,
    alt_bn128_g2_decompress_be, convert_endianness,
};

#[derive(Debug, Clone, Copy)]
pub struct ProofCompressed {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct ProofResult {
    pub proof: ProofCompressed,
    pub proof_duration_ms: u64,
}

impl From<ProofCompressed> for CompressedProof {
    fn from(proof: ProofCompressed) -> Self {
        CompressedProof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        }
    }
}

impl ProofCompressed {
    pub fn try_decompress(&self) -> Result<Proof, ProverClientError> {
        let proof_a = alt_bn128_g1_decompress_be(&self.a)?;
        let proof_b = alt_bn128_g2_decompress_be(&self.b)?;
        let proof_c = alt_bn128_g1_decompress_be(&self.c)?;
        Ok(Proof {
            a: proof_a,
            b: proof_b,
            c: proof_c,
        })
    }
}

pub struct Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GnarkProofJson {
    pub ar: Vec<String>,
    pub bs: Vec<Vec<String>>,
    pub krs: Vec<String>,
    pub proof_commitment: Option<Vec<String>>,
    pub proof_commitment_pok: Option<Vec<String>>,
}

pub fn deserialize_gnark_proof_json(json_data: &str) -> serde_json::Result<GnarkProofJson> {
    let deserialized_data: GnarkProofJson = serde_json::from_str(json_data)?;
    Ok(deserialized_data)
}

pub fn deserialize_hex_string_to_be_bytes(hex_str: &str) -> [u8; 32] {
    let trimmed_str = hex_str.trim_start_matches("0x");
    let big_int = num_bigint::BigInt::from_str_radix(trimmed_str, 16).unwrap();
    let big_int_bytes = big_int.to_bytes_be().1;
    if big_int_bytes.len() < 32 {
        let mut result = [0u8; 32];
        result[32 - big_int_bytes.len()..].copy_from_slice(&big_int_bytes);
        result
    } else {
        big_int_bytes.try_into().unwrap()
    }
}

pub fn compress_proof(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
) -> ([u8; 32], [u8; 64], [u8; 32]) {
    let proof_a = alt_bn128_g1_compress_be(proof_a).unwrap();
    let proof_b = alt_bn128_g2_compress_be(proof_b).unwrap();
    let proof_c = alt_bn128_g1_compress_be(proof_c).unwrap();
    (proof_a, proof_b, proof_c)
}

pub fn proof_from_json_struct(json: GnarkProofJson) -> ([u8; 64], [u8; 128], [u8; 64]) {
    let proof_a_x = deserialize_hex_string_to_be_bytes(&json.ar[0]);
    let proof_a_y = deserialize_hex_string_to_be_bytes(&json.ar[1]);
    let proof_a: [u8; 64] = [proof_a_x, proof_a_y].concat().try_into().unwrap();
    let proof_a = negate_g1(&proof_a);
    let proof_b_x_0 = deserialize_hex_string_to_be_bytes(&json.bs[0][0]);
    let proof_b_x_1 = deserialize_hex_string_to_be_bytes(&json.bs[0][1]);
    let proof_b_y_0 = deserialize_hex_string_to_be_bytes(&json.bs[1][0]);
    let proof_b_y_1 = deserialize_hex_string_to_be_bytes(&json.bs[1][1]);
    let proof_b: [u8; 128] = [proof_b_x_0, proof_b_x_1, proof_b_y_0, proof_b_y_1]
        .concat()
        .try_into()
        .unwrap();

    let proof_c_x = deserialize_hex_string_to_be_bytes(&json.krs[0]);
    let proof_c_y = deserialize_hex_string_to_be_bytes(&json.krs[1]);
    let proof_c: [u8; 64] = [proof_c_x, proof_c_y].concat().try_into().unwrap();
    (proof_a, proof_b, proof_c)
}

pub fn bsb22_proof_bytes_from_json_struct(
    json: GnarkProofJson,
) -> Result<[u8; 192], ProverClientError> {
    let commitment = parse_g1_pair(json.proof_commitment.as_deref(), "proof_commitment")?;
    let commitment_pok =
        parse_g1_pair(json.proof_commitment_pok.as_deref(), "proof_commitment_pok")?;
    let (proof_a, proof_b, proof_c) = proof_from_json_struct(json);
    let (proof_a, proof_b, proof_c) = compress_proof(&proof_a, &proof_b, &proof_c);
    let proof_commitment = alt_bn128_g1_compress_be(&commitment)?;
    let proof_commitment_pok = alt_bn128_g1_compress_be(&commitment_pok)?;

    if proof_commitment == [0u8; 32] || proof_commitment_pok == [0u8; 32] {
        return Err(ProverClientError::InvalidProofData(
            "BSB22 commitment fields must be non-zero".to_string(),
        ));
    }

    let mut out = [0u8; 192];
    out[..32].copy_from_slice(&proof_a);
    out[32..96].copy_from_slice(&proof_b);
    out[96..128].copy_from_slice(&proof_c);
    out[128..160].copy_from_slice(&proof_commitment);
    out[160..192].copy_from_slice(&proof_commitment_pok);
    Ok(out)
}

fn parse_g1_pair(value: Option<&[String]>, name: &str) -> Result<[u8; 64], ProverClientError> {
    let value = value.ok_or_else(|| {
        ProverClientError::InvalidProofData(format!("{name} is required for BSB22 proof"))
    })?;
    if value.len() != 2 {
        return Err(ProverClientError::InvalidProofData(format!(
            "{name} must contain exactly two coordinates"
        )));
    }
    let x = deserialize_hex_string_to_be_bytes(&value[0]);
    let y = deserialize_hex_string_to_be_bytes(&value[1]);
    Ok([x, y].concat().try_into().unwrap())
}

pub fn negate_g1(g1_be: &[u8; 64]) -> [u8; 64] {
    let g1_le = convert_endianness::<32, 64>(g1_be);
    let g1: G1 = G1::deserialize_with_mode(g1_le.as_slice(), Compress::No, Validate::No).unwrap();

    let g1_neg = g1.neg();
    let mut g1_neg_be = [0u8; 64];
    g1_neg
        .x
        .serialize_with_mode(&mut g1_neg_be[..32], Compress::No)
        .unwrap();
    g1_neg
        .y
        .serialize_with_mode(&mut g1_neg_be[32..], Compress::No)
        .unwrap();
    let g1_neg_be: [u8; 64] = convert_endianness::<32, 64>(&g1_neg_be);
    g1_neg_be
}
