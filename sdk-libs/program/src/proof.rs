//! Converts Xark artifacts to the SDK's existing compressed Solana proof ABI.

use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use groth16_solana::groth16::Groth16Verifyingkey;
use sha2::{Digest, Sha256};
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};

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
    serde_json::json!([
        [point.x.c0.to_string(), point.x.c1.to_string()],
        [point.y.c0.to_string(), point.y.c1.to_string()],
        ["1", "0"]
    ])
}

/// A Groth16 proof as Xark writes `proof.bin`: arkworks-compressed `A`, `B`, `C`.
struct Proof {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
}

/// A Groth16 verifying key as Xark writes `vk.bin`: arkworks-compressed points
/// in this order, `gamma_abc_g1` with arkworks' `u64` length prefix.
struct VerifyingKey {
    alpha_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g2: G2Affine,
    gamma_abc_g1: Vec<G1Affine>,
}

/// Reads one arkworks-compressed value, validating curve and subgroup
/// membership.
fn read<T: CanonicalDeserialize>(input: &mut &[u8], name: &str) -> Result<T, String> {
    T::deserialize_compressed(input).map_err(|e| format!("{name}: {e}"))
}

fn finish(input: &[u8], name: &str) -> Result<(), String> {
    if input.is_empty() {
        Ok(())
    } else {
        Err(format!("trailing {name} bytes"))
    }
}

impl Proof {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut input = bytes;
        let proof = Self {
            a: read(&mut input, "proof A")?,
            b: read(&mut input, "proof B")?,
            c: read(&mut input, "proof C")?,
        };
        finish(input, "proof")?;
        Ok(proof)
    }
}

impl VerifyingKey {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut input = bytes;
        let key = Self {
            alpha_g1: read(&mut input, "verifying key alpha")?,
            beta_g2: read(&mut input, "verifying key beta")?,
            gamma_g2: read(&mut input, "verifying key gamma")?,
            delta_g2: read(&mut input, "verifying key delta")?,
            gamma_abc_g1: read(&mut input, "verifying key input commitments")?,
        };
        finish(input, "verifying key")?;
        Ok(key)
    }
}

pub fn snarkjs_proof(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let proof = Proof::parse(bytes)?;
    Ok(
        serde_json::json!({"protocol":"groth16", "curve":"bn128", "pi_a":json_g1(&proof.a),
        "pi_b":json_g2(&proof.b), "pi_c":json_g1(&proof.c)}),
    )
}

pub fn snarkjs_verifying_key(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let key = VerifyingKey::parse(bytes)?;
    Ok(
        serde_json::json!({"protocol":"groth16", "curve":"bn128", "nPublic":key.gamma_abc_g1.len().saturating_sub(1),
        "vk_alpha_1":json_g1(&key.alpha_g1), "vk_beta_2":json_g2(&key.beta_g2),
        "vk_gamma_2":json_g2(&key.gamma_g2), "vk_delta_2":json_g2(&key.delta_g2),
        "IC":key.gamma_abc_g1.iter().map(json_g1).collect::<Vec<_>>()}),
    )
}

/// A base field element as 32 big-endian bytes.
fn fq_be(value: &Fq) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    value
        .serialize_uncompressed(&mut out[..])
        .map_err(|e| e.to_string())?;
    out.reverse();
    Ok(out)
}

/// A G1 point as Solana's alt_bn128 syscalls take it: `x || y`, 32 bytes each,
/// big-endian. The point at infinity is all zeros.
fn g1(point: &G1Affine) -> Result<[u8; 64], String> {
    let mut out = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        let (x_out, y_out) = out.split_at_mut(32);
        x_out.copy_from_slice(&fq_be(&x)?);
        y_out.copy_from_slice(&fq_be(&y)?);
    }
    Ok(out)
}

/// A G2 point as Solana's alt_bn128 syscalls take it: `x.c1 || x.c0 || y.c1 ||
/// y.c0`, 32 bytes each, big-endian. The point at infinity is all zeros.
fn g2(point: &G2Affine) -> Result<[u8; 128], String> {
    let mut out = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        let limbs = [x.c1, x.c0, y.c1, y.c0];
        for (target, limb) in out.as_chunks_mut::<32>().0.iter_mut().zip(&limbs) {
            *target = fq_be(limb)?;
        }
    }
    Ok(out)
}

/// The on-chain proof: `A` negated, so the program feeds the pairing directly,
/// then `B` and `C`, each compressed.
pub fn compressed_proof(bytes: &[u8]) -> Result<CompressedProof, String> {
    let proof = Proof::parse(bytes)?;
    Ok(CompressedProof {
        a: alt_bn128_g1_compress_be(&g1(&-proof.a)?).map_err(|e| format!("proof A: {e:?}"))?,
        b: alt_bn128_g2_compress_be(&g2(&proof.b)?).map_err(|e| format!("proof B: {e:?}"))?,
        c: alt_bn128_g1_compress_be(&g1(&proof.c)?).map_err(|e| format!("proof C: {e:?}"))?,
    })
}

pub struct SolanaVerifyingKey {
    alpha: [u8; 64],
    beta: [u8; 128],
    gamma: [u8; 128],
    delta: [u8; 128],
    ic: Vec<[u8; 64]>,
}

impl SolanaVerifyingKey {
    pub fn from_xark(bytes: &[u8]) -> Result<Self, String> {
        let key = VerifyingKey::parse(bytes)?;
        if key.gamma_abc_g1.is_empty() {
            return Err("verifying key has no constant input".into());
        }
        Ok(Self {
            alpha: g1(&key.alpha_g1)?,
            beta: g2(&key.beta_g2)?,
            gamma: g2(&key.gamma_g2)?,
            delta: g2(&key.delta_g2)?,
            ic: key.gamma_abc_g1.iter().map(g1).collect::<Result<_, _>>()?,
        })
    }

    pub fn as_key(&self) -> Groth16Verifyingkey<'_> {
        Groth16Verifyingkey {
            nr_pubinputs: self.ic.len().saturating_sub(1),
            vk_alpha_g1: self.alpha,
            vk_beta_g2: self.beta,
            vk_gamma_g2: self.gamma,
            vk_delta_g2: self.delta,
            vk_ic: &self.ic,
            vk_commitment: None,
        }
    }
}
