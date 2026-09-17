//! Poseidon2 over the BN254 scalar field, width 2, 6 full and 50 partial
//! rounds, with the gnark-crypto round keys: the 2-to-1 hash of every Merkle
//! tree node and indexed leaf. The Go definition is
//! `prover/server/merkle-tree/tree_hash.go`; `round_keys.rs`, the zero table
//! and `test-vectors/tree_hash.json` are generated from it.
//!
//! There is no Solana syscall for Poseidon2, so the permutation runs in
//! plain Rust on every target.

mod round_keys;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};

use crate::{
    errors::HasherError,
    primitives::is_canonical_bn254_scalar_be,
    zero_bytes::{poseidon2::ZERO_BYTES, ZeroBytes},
    Hash, Hasher, HASH_BYTES,
};
use round_keys::{FULL_ROUND_KEYS, PARTIAL_ROUND_KEYS};

#[derive(Debug, Clone, Copy)]
pub struct Poseidon2;

impl Poseidon2 {
    /// `perm(left, right)[1] + right`; inputs are canonical big-endian field
    /// elements.
    pub fn compress(left: &[u8; 32], right: &[u8; 32]) -> Result<Hash, HasherError> {
        let mut state = [element(left)?, element(right)?];
        let feed_forward = state[1];
        permute(&mut state);
        Ok(bytes(state[1] + feed_forward))
    }
}

impl Hasher for Poseidon2 {
    const ID: u8 = 3;

    fn hash(val: &[u8]) -> Result<Hash, HasherError> {
        if val.len() != 2 * HASH_BYTES {
            return Err(HasherError::InvalidInputLength(2 * HASH_BYTES, val.len()));
        }
        Self::hashv(&[&val[..HASH_BYTES], &val[HASH_BYTES..]])
    }

    fn hashv(vals: &[&[u8]]) -> Result<Hash, HasherError> {
        let [left, right] = vals else {
            return Err(HasherError::InvalidNumFields);
        };
        Self::compress(word(left)?, word(right)?)
    }

    fn zero_bytes() -> &'static ZeroBytes {
        &ZERO_BYTES
    }
}

fn word(val: &[u8]) -> Result<&[u8; 32], HasherError> {
    val.try_into()
        .map_err(|_| HasherError::InvalidInputLength(HASH_BYTES, val.len()))
}

fn element(val: &[u8; 32]) -> Result<Fr, HasherError> {
    if !is_canonical_bn254_scalar_be(val) {
        return Err(HasherError::InputLargerThanModulus);
    }
    Ok(Fr::from_be_bytes_mod_order(val))
}

fn bytes(e: Fr) -> Hash {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(e.into_bigint().0.iter().rev()) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn sbox(x: &mut Fr) {
    let x2 = x.square();
    *x *= x2.square();
}

/// External matrix `circ(2, 1)`: `[2a + b, a + 2b]`.
fn external(s: &mut [Fr; 2]) {
    let sum = s[0] + s[1];
    s[0] += sum;
    s[1] += sum;
}

/// Internal matrix `[[2, 1], [1, 3]]`: `[2a + b, a + 3b]`.
fn internal(s: &mut [Fr; 2]) {
    let sum = s[0] + s[1];
    s[0] += sum;
    s[1].double_in_place();
    s[1] += sum;
}

fn full_round(s: &mut [Fr; 2], keys: &[Fr; 2]) {
    s[0] += keys[0];
    s[1] += keys[1];
    sbox(&mut s[0]);
    sbox(&mut s[1]);
    external(s);
}

fn permute(s: &mut [Fr; 2]) {
    let (first, last) = FULL_ROUND_KEYS.split_at(FULL_ROUND_KEYS.len() / 2);
    external(s);
    for keys in first {
        full_round(s, keys);
    }
    for key in &PARTIAL_ROUND_KEYS {
        s[0] += key;
        sbox(&mut s[0]);
        internal(s);
    }
    for keys in last {
        full_round(s, keys);
    }
}
