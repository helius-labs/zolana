//! Boundary over agave `solana-bn254-groth16-batch`.
//!
//! Wire proofs store negated `a` (solo path). The agave fold expects non-negated
//! `a`; [`wire_proof_to_batch`] un-negates after decompress.

#![no_std]

extern crate alloc;

pub use solana_bn254_groth16_batch::{
    groth16_batch_verify, Groth16BatchError, PedersenKey, Proof, ProofCommitment, RandomizerMode,
    ValidatedVerifyingKey, VerifyingKey, Version,
};

use alloc::vec::Vec;
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{negate_g1_be, Groth16Verifyingkey},
};
use solana_bn254_batch_syscall::{PodG1Point, PodG2Point, PodScalar};

/// Compressed wire proof (`a` already negated).
#[derive(Clone, Copy, Debug)]
pub struct WireProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Decompress,
    Empty,
    Vk,
    Batch,
}

/// Constant VK → agave key. Uses `trust` (no curve checks) for SBF static keys.
pub fn vk_from_solana(vk: &Groth16Verifyingkey<'_>) -> Result<ValidatedVerifyingKey, WireError> {
    VerifyingKey {
        alpha_g1: PodG1Point(vk.vk_alpha_g1),
        beta_g2: PodG2Point(vk.vk_beta_g2),
        gamma_g2: PodG2Point(vk.vk_gamma_g2),
        delta_g2: PodG2Point(vk.vk_delta_g2),
        ic: vk.vk_ic.iter().copied().map(PodG1Point).collect(),
        pedersen: None,
    }
    .trust()
    .map_err(|_| WireError::Vk)
}

/// Decompress + un-negate `a` for the agave fold.
pub fn wire_proof_to_batch(
    vk_index: u16,
    wire: &WireProof,
    public_input_hash: [u8; 32],
) -> Result<Proof, WireError> {
    let a_neg = decompress_g1(&wire.a).map_err(|_| WireError::Decompress)?;
    let a = negate_g1_be(&a_neg);
    let b = decompress_g2(&wire.b).map_err(|_| WireError::Decompress)?;
    let c = decompress_g1(&wire.c).map_err(|_| WireError::Decompress)?;
    Ok(Proof {
        vk_index,
        a: PodG1Point(a),
        b: PodG2Point(b),
        c: PodG1Point(c),
        commitment: None,
        public_inputs: alloc::vec![PodScalar(public_input_hash)],
    })
}

/// Same-vk batch over wire proofs.
pub fn batch_verify_wire(
    vk: &Groth16Verifyingkey<'_>,
    items: &[(WireProof, [u8; 32])],
) -> Result<bool, WireError> {
    if items.is_empty() {
        return Err(WireError::Empty);
    }
    let validated = vk_from_solana(vk)?;
    let mut proofs = Vec::with_capacity(items.len());
    for (wire, pi) in items {
        proofs.push(wire_proof_to_batch(0, wire, *pi)?);
    }
    groth16_batch_verify(Version::V0, &[validated], &proofs, RandomizerMode::Independent)
        .map_err(|_| WireError::Batch)
}

/// Mixed-key batch over already-validated keys.
pub fn batch_verify_validated(
    vks: &[ValidatedVerifyingKey],
    items: &[(u16, WireProof, [u8; 32])],
) -> Result<bool, WireError> {
    if items.is_empty() || vks.is_empty() {
        return Err(WireError::Empty);
    }
    let mut proofs = Vec::with_capacity(items.len());
    for &(idx, ref wire, pi) in items {
        if usize::from(idx) >= vks.len() {
            return Err(WireError::Vk);
        }
        proofs.push(wire_proof_to_batch(idx, wire, pi)?);
    }
    groth16_batch_verify(Version::V0, vks, &proofs, RandomizerMode::Independent)
        .map_err(|_| WireError::Batch)
}

/// Mixed-key batch: each item is `(vk_index, wire, public_input_hash)`.
pub fn batch_verify_wire_hetero(
    vks: &[&Groth16Verifyingkey<'_>],
    items: &[(u16, WireProof, [u8; 32])],
) -> Result<bool, WireError> {
    if items.is_empty() || vks.is_empty() {
        return Err(WireError::Empty);
    }
    let mut validated = Vec::with_capacity(vks.len());
    for vk in vks {
        validated.push(vk_from_solana(vk)?);
    }
    batch_verify_validated(&validated, items)
}

/// Pack a solana VK for a foreign-vk account (compose hub).
pub fn pack_solana_vk(vk: &Groth16Verifyingkey<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 128 * 3 + 2 + vk.vk_ic.len() * 64);
    out.extend_from_slice(&vk.vk_alpha_g1);
    out.extend_from_slice(&vk.vk_beta_g2);
    out.extend_from_slice(&vk.vk_gamma_g2);
    out.extend_from_slice(&vk.vk_delta_g2);
    out.extend_from_slice(&(vk.vk_ic.len() as u16).to_le_bytes());
    for ic in vk.vk_ic {
        out.extend_from_slice(ic);
    }
    out
}

/// Unpack foreign-vk account bytes into a validated key.
pub fn unpack_vk(data: &[u8]) -> Result<ValidatedVerifyingKey, WireError> {
    const G1: usize = 64;
    const G2: usize = 128;
    if data.len() < G1 + 3 * G2 + 2 {
        return Err(WireError::Vk);
    }
    let mut off = 0usize;
    let mut take = |n: usize| -> Result<&[u8], WireError> {
        let end = off.checked_add(n).ok_or(WireError::Vk)?;
        if end > data.len() {
            return Err(WireError::Vk);
        }
        let s = &data[off..end];
        off = end;
        Ok(s)
    };
    let mut alpha = [0u8; G1];
    alpha.copy_from_slice(take(G1)?);
    let mut beta = [0u8; G2];
    beta.copy_from_slice(take(G2)?);
    let mut gamma = [0u8; G2];
    gamma.copy_from_slice(take(G2)?);
    let mut delta = [0u8; G2];
    delta.copy_from_slice(take(G2)?);
    let ic_count = u16::from_le_bytes(take(2)?.try_into().map_err(|_| WireError::Vk)?) as usize;
    let mut ic = Vec::with_capacity(ic_count);
    for _ in 0..ic_count {
        let mut p = [0u8; G1];
        p.copy_from_slice(take(G1)?);
        ic.push(PodG1Point(p));
    }
    if off != data.len() {
        return Err(WireError::Vk);
    }
    VerifyingKey {
        alpha_g1: PodG1Point(alpha),
        beta_g2: PodG2Point(beta),
        gamma_g2: PodG2Point(gamma),
        delta_g2: PodG2Point(delta),
        ic,
        pedersen: None,
    }
    .trust()
    .map_err(|_| WireError::Vk)
}
