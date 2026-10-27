//! Converts Xark artifacts to the SDK's existing compressed Solana proof ABI.

use ark_bn254::Bn254;
use ark_serialize::CanonicalDeserialize;
use groth16_solana::groth16::Groth16Verifyingkey;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use sha2::{Digest, Sha256};

use crate::CompressedProof;

/// The exact proving-key bytes do not match the application's trusted digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvingKeyChecksumMismatch;

impl core::fmt::Display for ProvingKeyChecksumMismatch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("proving key SHA-256 checksum mismatch")
    }
}

impl core::error::Error for ProvingKeyChecksumMismatch {}

/// Check the complete serialized key before parsing, transcoding, or preloading it.
/// Obtain `expected_sha256` from trusted application build metadata.
pub fn check_proving_key(
    proving_key: &[u8],
    expected_sha256: &[u8; 32],
) -> Result<(), ProvingKeyChecksumMismatch> {
    let actual: [u8; 32] = Sha256::digest(proving_key).into();
    if &actual == expected_sha256 {
        Ok(())
    } else {
        Err(ProvingKeyChecksumMismatch)
    }
}

fn json_g1(point: &ark_bn254::G1Affine) -> serde_json::Value {
    serde_json::json!([point.x.to_string(), point.y.to_string(), "1"])
}
fn json_g2(point: &ark_bn254::G2Affine) -> serde_json::Value {
    serde_json::json!([[point.x.c0.to_string(), point.x.c1.to_string()],
        [point.y.c0.to_string(), point.y.c1.to_string()], ["1", "0"]])
}

pub fn snarkjs_proof(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let mut input = bytes;
    let proof = xark_groth16::Proof::<Bn254>::deserialize_compressed(&mut input).map_err(|e| e.to_string())?;
    if !input.is_empty() { return Err("trailing proof bytes".into()); }
    Ok(serde_json::json!({"protocol":"groth16", "curve":"bn128", "pi_a":json_g1(&proof.a),
        "pi_b":json_g2(&proof.b), "pi_c":json_g1(&proof.c)}))
}

pub fn snarkjs_verifying_key(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let mut input = bytes;
    let key = xark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&mut input).map_err(|e| e.to_string())?;
    if !input.is_empty() { return Err("trailing verifying key bytes".into()); }
    Ok(serde_json::json!({"protocol":"groth16", "curve":"bn128", "nPublic":key.gamma_abc_g1.len().saturating_sub(1),
        "vk_alpha_1":json_g1(&key.alpha_g1), "vk_beta_2":json_g2(&key.beta_g2),
        "vk_gamma_2":json_g2(&key.gamma_g2), "vk_delta_2":json_g2(&key.delta_g2),
        "IC":key.gamma_abc_g1.iter().map(json_g1).collect::<Vec<_>>()}))
}

fn g1(bytes: &[u8]) -> [u8; 64] {
    let mut out: [u8; 64] = bytes.try_into().expect("G1 length from Xark encoding");
    for coordinate in out.chunks_exact_mut(32) { coordinate.reverse(); }
    out
}

fn g2(bytes: &[u8]) -> [u8; 128] {
    let mut out = [0u8; 128];
    for (target, index) in out.chunks_exact_mut(32).zip([1, 0, 3, 2]) {
        target.copy_from_slice(&bytes[index * 32..(index + 1) * 32]);
        target.reverse();
    }
    out
}

pub fn compressed_proof(bytes: &[u8]) -> Result<CompressedProof, String> {
    let mut input = bytes;
    let proof = xark_groth16::Proof::<Bn254>::deserialize_compressed(&mut input).map_err(|e| e.to_string())?;
    if !input.is_empty() { return Err("trailing proof bytes".into()); }
    let le = xark_groth16::solana::assemble_proof_bytes_le(&proof);
    Ok(CompressedProof {
        a: alt_bn128_g1_compress_be(&g1(&le[..64])).map_err(|e| format!("proof A: {e:?}"))?,
        b: alt_bn128_g2_compress_be(&g2(&le[64..192])).map_err(|e| format!("proof B: {e:?}"))?,
        c: alt_bn128_g1_compress_be(&g1(&le[192..])).map_err(|e| format!("proof C: {e:?}"))?,
    })
}

pub struct SolanaVerifyingKey {
    alpha: [u8; 64], beta: [u8; 128], gamma: [u8; 128], delta: [u8; 128],
    ic: Vec<[u8; 64]>,
}

impl SolanaVerifyingKey {
    pub fn from_xark(bytes: &[u8]) -> Result<Self, String> {
        let mut input = bytes;
        let key = xark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&mut input).map_err(|e| e.to_string())?;
        if !input.is_empty() { return Err("trailing verifying key bytes".into()); }
        if key.gamma_abc_g1.is_empty() { return Err("verifying key has no constant input".into()); }
        let le = xark_groth16::solana::assemble_vk_bytes_le(&key);
        Ok(Self { alpha: g1(&le[..64]), beta: g2(&le[64..192]), gamma: g2(&le[192..320]),
            delta: g2(&le[320..448]), ic: le[448..].chunks_exact(64).map(g1).collect() })
    }

    pub fn as_key(&self) -> Groth16Verifyingkey<'_> {
        Groth16Verifyingkey { nr_pubinputs: self.ic.len() - 1, vk_alpha_g1: self.alpha, vk_beta_g2: self.beta,
            vk_gamma_g2: self.gamma, vk_delta_g2: self.delta, vk_ic: &self.ic, vk_commitment: None }
    }
}
