//! On-chain Groth16 verification of a compressed proof against its public
//! inputs, plus the encodings that turn a program's typed public values into
//! those inputs. `no_std`, so a Solana program can link it.

pub use groth16_solana;
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
pub use zolana_hasher::primitives::{pack_be, pack_be_chunks};

use crate::CompressedProof;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// A public input cannot be encoded.
    PublicInputs,
    /// The proof is malformed or does not verify under the key.
    Proof,
}

/// Verifies `proof` against its `N` public inputs. The verifying key must be a
/// standard Groth16 key: one with a BSB22 commitment is rejected.
#[inline(never)]
pub fn verify_groth16<const N: usize>(
    proof: &CompressedProof,
    public_inputs: &[[u8; 32]; N],
    verifying_key: &Groth16Verifyingkey,
) -> Result<(), VerifyError> {
    if verifying_key.vk_commitment.is_some() {
        return Err(VerifyError::Proof);
    }
    let a = decompress_g1(&proof.a).map_err(|_| VerifyError::Proof)?;
    let b = decompress_g2(&proof.b).map_err(|_| VerifyError::Proof)?;
    let c = decompress_g1(&proof.c).map_err(|_| VerifyError::Proof)?;
    Groth16Verifier::new(&a, &b, &c, public_inputs, verifying_key)
        .map_err(|_| VerifyError::Proof)?
        .verify()
        .map_err(|_| VerifyError::Proof)
}

/// An unsigned integer as one public input: right-aligned big-endian.
pub fn integer(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (target, source) in bytes.iter_mut().rev().zip(value.to_le_bytes()) {
        *target = source;
    }
    bytes
}

/// A bool as one public input: 0 or 1.
pub fn boolean(value: bool) -> [u8; 32] {
    integer(u128::from(value))
}
