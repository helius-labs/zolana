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
