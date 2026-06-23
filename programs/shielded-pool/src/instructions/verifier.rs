//! Shared Groth16 public-input field math and proof verification, reused by every
//! proof-bearing instruction (`transact`, `merge_transact`). The hash helpers
//! mirror the circuits' Poseidon field encoding; `verify_groth16` decompresses the
//! 192-byte proof and runs the BSB22 or vanilla pairing depending on the VK.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::error::ShieldedPoolError;

/// `Poseidon(a, b)` of two field elements; maps a hasher failure to `verify_err`.
pub fn poseidon2(
    a: &[u8; 32],
    b: &[u8; 32],
    verify_err: ShieldedPoolError,
) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[a.as_slice(), b.as_slice()]).map_err(|_| verify_err.into())
}

/// `hash_field`: split a 32-byte value into low/high 128-bit limbs and
/// `Poseidon(low, high)`.
#[inline(never)]
pub fn hash_field(
    value: &[u8; 32],
    verify_err: ShieldedPoolError,
) -> Result<[u8; 32], ProgramError> {
    let (high_bytes, low_bytes) = value.split_at(16);
    poseidon2(
        &right_align_16(low_bytes),
        &right_align_16(high_bytes),
        verify_err,
    )
}

/// Fold `items` into a Poseidon hash chain (`acc = Poseidon(acc, next)`, empty = 0).
#[inline(never)]
pub fn hash_chain(
    items: &[[u8; 32]],
    verify_err: ShieldedPoolError,
) -> Result<[u8; 32], ProgramError> {
    let mut iter = items.iter();
    let Some(first) = iter.next() else {
        return Ok([0u8; 32]);
    };
    let mut acc = *first;
    for item in iter {
        acc = poseidon2(&acc, item, verify_err)?;
    }
    Ok(acc)
}

fn right_align_16(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(bytes);
    out
}

/// Decompress the 192-byte proof and verify it against `verifying_key` for the
/// single `public_input_hash`. Runs the BSB22 commitment pairing when the VK
/// carries a commitment, the vanilla pairing otherwise.
#[inline(never)]
#[profile]
pub fn verify_groth16(
    proof: &[u8; 192],
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    let proof_a = decompress_g1(chunk::<32>(proof, 0, encoding_err)?).map_err(|_| encoding_err)?;
    let proof_b = decompress_g2(chunk::<64>(proof, 32, encoding_err)?).map_err(|_| encoding_err)?;
    let proof_c = decompress_g1(chunk::<32>(proof, 96, encoding_err)?).map_err(|_| encoding_err)?;
    let public_inputs = [public_input_hash];

    if verifying_key.vk_commitment_g2.is_some() {
        let commitment =
            decompress_g1(chunk::<32>(proof, 128, encoding_err)?).map_err(|_| encoding_err)?;
        let commitment_pok =
            decompress_g1(chunk::<32>(proof, 160, encoding_err)?).map_err(|_| encoding_err)?;
        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof_a,
            &proof_b,
            &proof_c,
            &commitment,
            &commitment_pok,
            &public_inputs,
            verifying_key,
        )
        .map_err(|_| verify_err)?;
        verifier.verify().map_err(|_| verify_err)?;
    } else {
        let mut verifier =
            Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
                .map_err(|_| verify_err)?;
        verifier.verify().map_err(|_| verify_err)?;
    }
    Ok(())
}

fn chunk<const N: usize>(
    data: &[u8],
    start: usize,
    encoding_err: ShieldedPoolError,
) -> Result<&[u8; N], ProgramError> {
    data.get(start..start + N)
        .ok_or(encoding_err)?
        .try_into()
        .map_err(|_| encoding_err.into())
}
