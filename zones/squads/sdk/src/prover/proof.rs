//! Parse a gnark proof JSON into the on-chain 192-byte compressed form.
//!
//! Mirrors `sdk-libs/client/src/prover/proof.rs` (whose parser is crate-private):
//! gnark emits `{ar, bs, krs, proof_commitment?, proof_commitment_pok?}` as
//! decimal/hex big-integer strings. The key-encryption circuit is the BSB22 rail
//! (the VK carries `vk_commitment_g2: Some(..)`), so `proof_commitment` and
//! `proof_commitment_pok` are always present and the 192-byte layout uses all
//! six slots.

use num_bigint::BigInt;
use num_traits::Num;
use serde::Deserialize;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};

use crate::prover::error::SquadsProverError;

#[derive(Deserialize)]
struct GnarkProofJson {
    ar: Vec<String>,
    bs: Vec<Vec<String>>,
    krs: Vec<String>,
    #[serde(default)]
    proof_commitment: Vec<String>,
    #[serde(default)]
    proof_commitment_pok: Vec<String>,
}

fn hex_to_be_32(s: &str) -> [u8; 32] {
    // gnark emits decimal strings; the client parser uses radix 16 after
    // stripping `0x`. Support both: detect a `0x` prefix, else decimal.
    let (radix, body) = if let Some(stripped) = s.strip_prefix("0x") {
        (16, stripped)
    } else {
        (10, s)
    };
    let big = BigInt::from_str_radix(body, radix).unwrap_or_default();
    let bytes = big.to_bytes_be().1;
    let mut out = [0u8; 32];
    if bytes.len() <= 32 {
        out[32 - bytes.len()..].copy_from_slice(&bytes);
    } else {
        out.copy_from_slice(&bytes[bytes.len() - 32..]);
    }
    out
}

fn g1_from_pair(pair: &[String]) -> Option<[u8; 64]> {
    let [x, y] = pair else { return None };
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&hex_to_be_32(x));
    out[32..].copy_from_slice(&hex_to_be_32(y));
    Some(out)
}

/// `proof_a` is negated for the on-chain pairing check (the verifier expects
/// `-A`). Mirrors `groth16_solana::groth16::negate_g1_be`.
fn negate_g1_be(point: &[u8; 64]) -> [u8; 64] {
    groth16_solana::groth16::negate_g1_be(point)
}

fn compress_g1(point: &[u8; 64], name: &str) -> Result<[u8; 32], SquadsProverError> {
    alt_bn128_g1_compress_be(point)
        .map_err(|e| SquadsProverError::ProofCompress(format!("g1 {name}: {e:?}")))
}

/// Parse a gnark proof JSON and produce the 192-byte transact proof bytes:
/// `[a(32) || b(64) || c(32) || commitment(32) || commitment_pok(32)]`, with
/// `a` negated and every point compressed big-endian.
pub(crate) fn gnark_json_to_transact_bytes(json_str: &str) -> Result<[u8; 192], SquadsProverError> {
    let json: GnarkProofJson = serde_json::from_str(json_str)
        .map_err(|e| SquadsProverError::ProofParse(format!("invalid proof JSON: {e}")))?;

    let a_uncompressed = negate_g1_be(
        &g1_from_pair(&json.ar)
            .ok_or_else(|| SquadsProverError::ProofParse("bad ar".to_string()))?,
    );
    let c_uncompressed = g1_from_pair(&json.krs)
        .ok_or_else(|| SquadsProverError::ProofParse("bad krs".to_string()))?;

    let [bx, by] = json.bs.as_slice() else {
        return Err(SquadsProverError::ProofParse("bad bs".to_string()));
    };
    let bx =
        g1_from_pair(bx).ok_or_else(|| SquadsProverError::ProofParse("bad bs.x".to_string()))?;
    let by =
        g1_from_pair(by).ok_or_else(|| SquadsProverError::ProofParse("bad bs.y".to_string()))?;
    let mut b_uncompressed = [0u8; 128];
    b_uncompressed[..64].copy_from_slice(&bx);
    b_uncompressed[64..].copy_from_slice(&by);

    let a = compress_g1(&a_uncompressed, "a")?;
    let b = alt_bn128_g2_compress_be(&b_uncompressed)
        .map_err(|e| SquadsProverError::ProofCompress(format!("g2 b: {e:?}")))?;
    let c = compress_g1(&c_uncompressed, "c")?;

    if json.proof_commitment.is_empty() || json.proof_commitment_pok.is_empty() {
        return Err(SquadsProverError::ProofParse(
            "key-encryption proof must carry a BSB22 commitment".to_string(),
        ));
    }
    let commitment = compress_g1(
        &g1_from_pair(&json.proof_commitment)
            .ok_or_else(|| SquadsProverError::ProofParse("bad commitment".to_string()))?,
        "commitment",
    )?;
    let commitment_pok = compress_g1(
        &g1_from_pair(&json.proof_commitment_pok)
            .ok_or_else(|| SquadsProverError::ProofParse("bad commitment_pok".to_string()))?,
        "commitment_pok",
    )?;

    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&a);
    out[32..96].copy_from_slice(&b);
    out[96..128].copy_from_slice(&c);
    out[128..160].copy_from_slice(&commitment);
    out[160..192].copy_from_slice(&commitment_pok);
    Ok(out)
}
