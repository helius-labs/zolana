//! Shared Groth16 public-input field math and proof verification, reused by every
//! proof-bearing zone instruction. The hash helpers mirror the circuits' Poseidon
//! field encoding; `verify_groth16` decompresses the 192-byte proof and runs the
//! BSB22 or vanilla pairing depending on the VK.
//!
//! Ported from the shielded-pool `instructions/verifier.rs`, with errors mapped to
//! [`SquadsZoneError`]: encoding failures map to the caller-supplied `encoding_err`
//! (typically `InvalidProofEncoding`), Poseidon failures map to the caller-supplied
//! `verify_err` (e.g. `ProofHashingFailed`), and the verify failure maps to the
//! caller-supplied `verify_err` (e.g. `ZoneProofVerificationFailed`).

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};
use zolana_squads_interface::error::SquadsZoneError;

/// `Poseidon(a, b)` of two field elements; maps a hasher failure to `verify_err`.
pub fn poseidon2(
    a: &[u8; 32],
    b: &[u8; 32],
    verify_err: SquadsZoneError,
) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[a.as_slice(), b.as_slice()]).map_err(|_| verify_err.into())
}

/// `hash_field`: split a 32-byte value into low/high 128-bit limbs and
/// `Poseidon(low, high)`.
#[inline(never)]
pub fn hash_field(value: &[u8; 32], verify_err: SquadsZoneError) -> Result<[u8; 32], ProgramError> {
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
    verify_err: SquadsZoneError,
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

/// Maximum number of field-element inputs to a single `poseidon_hash`. The widest
/// caller is the recipient ciphertext hash (71-byte ciphertext -> 5 field
/// elements); the on-chain Poseidon supports widths up to 16 inputs.
pub const MAX_POSEIDON_INPUTS: usize = 8;

/// `poseidon_hash`: a single multi-input Poseidon over `inputs`, matching the Go
/// circuits' `gadget.PoseidonHash` (state width `t = inputs.len() + 1`). Used for
/// account hashes and ciphertext hashes. Maps a hasher failure to `verify_err`.
///
/// Mirrors `gadget.PoseidonHash` (prover/server/circuits/gadget/poseidon.go:51).
#[inline(never)]
pub fn poseidon_hash(
    inputs: &[[u8; 32]],
    verify_err: SquadsZoneError,
) -> Result<[u8; 32], ProgramError> {
    if inputs.is_empty() || inputs.len() > MAX_POSEIDON_INPUTS {
        return Err(verify_err.into());
    }
    let mut slices: [&[u8]; MAX_POSEIDON_INPUTS] = [&[]; MAX_POSEIDON_INPUTS];
    for (slot, input) in slices.iter_mut().zip(inputs.iter()) {
        *slot = input.as_slice();
    }
    let used = slices.get(..inputs.len()).ok_or(verify_err)?;
    Poseidon::hashv(used).map_err(|_| verify_err.into())
}

/// `pack33_to_2fe`: split a 33-byte compressed P-256 pubkey into two big-endian
/// field elements, mirroring `Pack33To2FECircuit`
/// (prover/server/circuits/zone-utils/poseidon_kdf.go:63).
///
/// - `lo` = big-endian integer of `key[0..31]` left-padded with one zero byte:
///   `lo[0] = 0`, `lo[1..32] = key[0..31]`.
/// - `hi` = big-endian 32-byte encoding of `key[31] * 256 + key[32]`:
///   `hi[30] = key[31]`, `hi[31] = key[32]`, all other bytes zero.
#[inline(always)]
pub fn pack33_to_2fe(key: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&key[0..31]);
    let mut hi = [0u8; 32];
    hi[30] = key[31];
    hi[31] = key[32];
    (lo, hi)
}

/// `pack_bytes_be`: split `data` into sequential 16-byte chunks (the final chunk
/// may be shorter) and encode each chunk as a big-endian 32-byte field element
/// (the chunk right-aligned, interpreted as a big-endian integer < 2^128). The
/// field elements are written into `out` and the number written is returned;
/// `data` longer than `16 * out.len()` is rejected with `verify_err`.
///
/// Mirrors `PackBytesBE(.., 16)`
/// (prover/server/circuits/zone-utils/poseidon_kdf.go:127). E.g. a 40-byte
/// ciphertext -> 3 FEs (16, 16, 8); a 71-byte ciphertext -> 5 FEs (16,16,16,16,7).
pub fn pack_bytes_be(
    data: &[u8],
    out: &mut [[u8; 32]],
    verify_err: SquadsZoneError,
) -> Result<usize, ProgramError> {
    let mut count = 0usize;
    for (slot, chunk) in out.iter_mut().zip(data.chunks(16)) {
        let mut fe = [0u8; 32];
        // Right-align the chunk: a big-endian integer < 2^128 occupies the low
        // `chunk.len()` bytes of the 32-byte field element.
        let start = 32 - chunk.len();
        fe.get_mut(start..)
            .ok_or(verify_err)?
            .copy_from_slice(chunk);
        *slot = fe;
        count += 1;
    }
    // Reject data that did not fully fit into `out`.
    if count * 16 < data.len() {
        return Err(verify_err.into());
    }
    Ok(count)
}

/// Decompress the 192-byte proof and verify it against `verifying_key` for the
/// single `public_input_hash`. Runs the BSB22 commitment pairing when the VK
/// carries a commitment, the vanilla pairing otherwise.
#[inline(never)]
pub fn verify_groth16(
    proof: &[u8; 192],
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
    encoding_err: SquadsZoneError,
    verify_err: SquadsZoneError,
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
    encoding_err: SquadsZoneError,
) -> Result<&[u8; N], ProgramError> {
    data.get(start..start + N)
        .ok_or(encoding_err)?
        .try_into()
        .map_err(|_| encoding_err.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERR: SquadsZoneError = SquadsZoneError::ProofHashingFailed;

    /// `pack33_to_2fe` of key[i] = i+1 (so key[0]=1 .. key[32]=33):
    /// lo = [0, 1, 2, .., 31]; hi = zeros except hi[30]=32, hi[31]=33.
    #[test]
    fn pack33_to_2fe_known_vector() {
        let mut key = [0u8; 33];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }

        let (lo, hi) = pack33_to_2fe(&key);

        let mut expected_lo = [0u8; 32];
        // lo[0] = 0, lo[1..32] = key[0..31] = 1..=31.
        for (i, b) in expected_lo.iter_mut().enumerate().skip(1) {
            *b = i as u8; // lo[i] = key[i-1] = i
        }
        assert_eq!(lo, expected_lo);

        let mut expected_hi = [0u8; 32];
        expected_hi[30] = 32; // key[31]
        expected_hi[31] = 33; // key[32]
        assert_eq!(hi, expected_hi);
    }

    /// `pack_bytes_be` over a 40-byte buffer -> 3 field elements (16, 16, 8),
    /// each chunk right-aligned as a big-endian integer.
    #[test]
    fn pack_bytes_be_40_bytes_three_fes() {
        let mut ciphertext = [0u8; 40];
        for (i, b) in ciphertext.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut out = [[0u8; 32]; MAX_POSEIDON_INPUTS];
        let n = pack_bytes_be(&ciphertext, &mut out, ERR).unwrap();
        assert_eq!(n, 3);

        // fe0: bytes[0..16] in out[0][16..32].
        let mut fe0 = [0u8; 32];
        fe0[16..32].copy_from_slice(&ciphertext[0..16]);
        assert_eq!(out[0], fe0);

        // fe1: bytes[16..32] in out[1][16..32].
        let mut fe1 = [0u8; 32];
        fe1[16..32].copy_from_slice(&ciphertext[16..32]);
        assert_eq!(out[1], fe1);

        // fe2: bytes[32..40] (8 bytes) right-aligned in out[2][24..32].
        let mut fe2 = [0u8; 32];
        fe2[24..32].copy_from_slice(&ciphertext[32..40]);
        assert_eq!(out[2], fe2);
    }

    /// 71-byte ciphertext -> 5 field elements (16,16,16,16,7).
    #[test]
    fn pack_bytes_be_71_bytes_five_fes() {
        let ciphertext = [7u8; 71];
        let mut out = [[0u8; 32]; MAX_POSEIDON_INPUTS];
        let n = pack_bytes_be(&ciphertext, &mut out, ERR).unwrap();
        assert_eq!(n, 5);

        // Last chunk holds 7 bytes, right-aligned in out[4][25..32].
        let mut fe4 = [0u8; 32];
        fe4[25..32].copy_from_slice(&[7u8; 7]);
        assert_eq!(out[4], fe4);
    }

    /// Data longer than the output capacity is rejected.
    #[test]
    fn pack_bytes_be_rejects_overflow() {
        let ciphertext = [0u8; 200]; // would need 13 FEs, out has 8
        let mut out = [[0u8; 32]; MAX_POSEIDON_INPUTS];
        assert!(pack_bytes_be(&ciphertext, &mut out, ERR).is_err());
    }
}
