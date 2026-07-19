use crate::{errors::HasherError, Hasher, Poseidon};

/// Poseidon arity bound: `Poseidon::hashv` supports at most 12 inputs.
const MAX_CHUNKS: usize = 12;

/// Poseidon hash of a byte string packed into 16-byte big-endian chunks
/// right-aligned into field elements (the last chunk may be short), mirroring
/// the circuit `PoseidonHash(PackBytesBE(bytes, 16))`. The input must be
/// 1..=192 bytes (12 chunks, the Poseidon arity bound).
pub fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], HasherError> {
    if ciphertext.is_empty() {
        return Err(HasherError::EmptyInput);
    }
    let n = ciphertext.len().div_ceil(16);
    if n > MAX_CHUNKS {
        return Err(HasherError::InvalidInputLength(
            MAX_CHUNKS * 16,
            ciphertext.len(),
        ));
    }
    let mut chunks = [[0u8; 32]; MAX_CHUNKS];
    for (fe, c) in chunks.iter_mut().zip(ciphertext.chunks(16)) {
        // `chunks(16)` yields 1..=16 bytes, so the range is in bounds.
        if let Some(dst) = fe.get_mut(32 - c.len()..) {
            dst.copy_from_slice(c);
        }
    }
    let mut refs: [&[u8]; MAX_CHUNKS] = [&[]; MAX_CHUNKS];
    for (r, c) in refs.iter_mut().zip(chunks.iter()) {
        *r = c.as_slice();
    }
    let used = refs.get(..n).ok_or(HasherError::InvalidNumFields)?;
    Poseidon::hashv(used)
}
