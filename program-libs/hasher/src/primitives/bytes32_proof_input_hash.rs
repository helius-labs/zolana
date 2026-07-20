use crate::{errors::HasherError, Hasher, Poseidon};

/// Splits a 32-byte big-endian value into right-aligned 128-bit limbs
/// `(low, high)`.
pub fn split_be_128(v: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut low = [0u8; 32];
    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&v[0..16]);
    low[16..].copy_from_slice(&v[16..32]);
    (low, high)
}

/// `Poseidon(v_low_128, v_high_128)` over the big-endian 128-bit limbs of a
/// 32-byte value. Used only for the ECDSA message digest, which must round-trip
/// through the emulated-field bit decomposition as two 128-bit limbs (spec:
/// `private_tx_hash_digest`). Byte strings hashed for their own sake use
/// [`hash_bytes`](super::hash_bytes) instead.
pub fn bytes32_proof_input_hash(value: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    let (low, high) = split_be_128(value);
    Poseidon::hashv(&[&low, &high])
}
