//! Shared Groth16 public-input field math and proof verification, reused by every
//! proof-bearing ring instruction. The hash helpers mirror the circuits' Poseidon
//! field encoding; `verify_groth16` decompresses the 192-byte proof and runs the
//! BSB22 or vanilla pairing depending on the VK.
//!
//! Ported from the shielded-pool `instructions/verifier.rs`, with errors mapped to
//! [`SquadsRingError`]: encoding failures map to the caller-supplied `encoding_err`
//! (typically `InvalidProofEncoding`), Poseidon failures map to the caller-supplied
//! `verify_err` (e.g. `ProofHashingFailed`), and the verify failure maps to the
//! caller-supplied `verify_err` (e.g. `RingProofVerificationFailed`).

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::{Hasher, Poseidon};
use zolana_squads_interface::error::SquadsRingError;

/// `Poseidon(a, b)` of two field elements; maps a hasher failure to `verify_err`.
pub fn poseidon2(
    a: &[u8; 32],
    b: &[u8; 32],
    verify_err: SquadsRingError,
) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[a.as_slice(), b.as_slice()]).map_err(|_| verify_err.into())
}

/// SPP owner identity of a Solana signer (ed25519 key or PDA):
/// `solana_owner_identity(pk)`, the value a viewing key account stores as its
/// `owner`.
#[inline(never)]
pub fn solana_owner_identity(
    pk: &[u8; 32],
    verify_err: SquadsRingError,
) -> Result<[u8; 32], ProgramError> {
    zolana_hasher::primitives::solana_owner_identity(pk).map_err(|_| verify_err.into())
}

/// Fold `items` into a Poseidon hash chain (`acc = Poseidon(acc, next)`, empty = 0).
#[inline(never)]
pub fn hash_chain(
    items: &[[u8; 32]],
    verify_err: SquadsRingError,
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

/// Maximum number of field-element inputs to a single `poseidon_hash`. The widest
/// caller is the recipient ciphertext hash (72-byte ciphertext -> 3 field
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
    verify_err: SquadsRingError,
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

/// `pack33_to_2fe`: split a 33-byte tagged X25519 pubkey into two big-endian
/// field elements, mirroring `Pack33To2FECircuit`
/// (rings/squads/prover/circuits/ringutils/poseidon_kdf.go:63).
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

/// Pack sequential 31-byte chunks as right-aligned big-endian field elements,
/// matching the main prover's canonical `gadget.PackBytesBE` encoding.
pub fn pack_bytes_be(
    data: &[u8],
    out: &mut [[u8; 32]],
    verify_err: SquadsRingError,
) -> Result<usize, ProgramError> {
    let mut count = 0usize;
    for (slot, chunk) in out.iter_mut().zip(data.chunks(31)) {
        let mut fe = [0u8; 32];
        // Right-align the chunk: a big-endian integer < 2^248 occupies the low
        // `chunk.len()` bytes of the 32-byte field element.
        let start = 32 - chunk.len();
        fe.get_mut(start..)
            .ok_or(verify_err)?
            .copy_from_slice(chunk);
        *slot = fe;
        count += 1;
    }
    // Reject data that did not fully fit into `out`.
    if count * 31 < data.len() {
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
    encoding_err: SquadsRingError,
    verify_err: SquadsRingError,
) -> ProgramResult {
    let proof_a = decompress_g1(chunk::<32>(proof, 0, encoding_err)?).map_err(|_| encoding_err)?;
    let proof_b = decompress_g2(chunk::<64>(proof, 32, encoding_err)?).map_err(|_| encoding_err)?;
    let proof_c = decompress_g1(chunk::<32>(proof, 96, encoding_err)?).map_err(|_| encoding_err)?;
    let public_inputs = [public_input_hash];

    if verifying_key.vk_commitment.is_some() {
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
    encoding_err: SquadsRingError,
) -> Result<&[u8; N], ProgramError> {
    data.get(start..start + N)
        .ok_or(encoding_err)?
        .try_into()
        .map_err(|_| encoding_err.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERR: SquadsRingError = SquadsRingError::ProofHashingFailed;

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

    /// Main's canonical packing uses 31-byte chunks, with a short final chunk.
    #[test]
    fn pack_bytes_be_40_bytes_two_elements() {
        let mut ciphertext = [0u8; 40];
        for (i, b) in ciphertext.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut out = [[0u8; 32]; 2];
        let n = pack_bytes_be(&ciphertext, &mut out, ERR).unwrap();
        let mut first = [0u8; 32];
        first[1..].copy_from_slice(&ciphertext[..31]);
        let mut second = [0u8; 32];
        second[23..].copy_from_slice(&ciphertext[31..]);
        assert_eq!((n, out), (2, [first, second]));
    }

    #[test]
    fn pack_bytes_be_72_bytes_three_elements() {
        let ciphertext = [7u8; 72];
        let mut out = [[0u8; 32]; 3];
        let n = pack_bytes_be(&ciphertext, &mut out, ERR).unwrap();
        let mut full = [7u8; 32];
        full[0] = 0;
        let mut last = [0u8; 32];
        last[22..].copy_from_slice(&[7u8; 10]);
        assert_eq!((n, out), (3, [full, full, last]));
    }

    /// Data longer than the output capacity is rejected.
    #[test]
    fn pack_bytes_be_rejects_overflow() {
        let ciphertext = [0u8; 40];
        let mut out = [[0u8; 32]; 1];
        assert_eq!(pack_bytes_be(&ciphertext, &mut out, ERR), Err(ERR.into()));
    }
}
