use crate::{
    errors::HasherError,
    primitives::{pack_be_chunks, pack_be_slice, right_align},
    Hasher, Poseidon,
};

/// Max byte length for [`hash_bytes`]: Poseidon takes 12 inputs; the length field
/// leaves 11 chunks × 31 bytes.
pub const MAX_HASH_BYTES_LEN: usize = MAX_CHUNKS * super::PACK_BE_CHUNK_BYTES;

const MAX_CHUNKS: usize = 11;

/// Canonical byte commitment: `Poseidon(len_fe, chunk_0, .., chunk_{k-1})` where
/// the chunks are `pack_be(bytes)` (see [`pack_be`](super::pack_be)). Binding the
/// length makes the encoding injective across inputs of different lengths. Carries
/// no domain tag — distinct uses are separated by length and by position in the
/// enclosing hash.
///
/// `bytes` must be 1..=341 bytes.
pub fn hash_bytes(bytes: &[u8]) -> Result<[u8; 32], HasherError> {
    if bytes.is_empty() {
        return Err(HasherError::EmptyInput);
    }
    let n = pack_be_chunks(bytes.len());
    if n > MAX_CHUNKS {
        return Err(HasherError::InvalidInputLength(
            MAX_HASH_BYTES_LEN,
            bytes.len(),
        ));
    }
    let len_fe = right_align(&(bytes.len() as u64).to_be_bytes());
    let mut chunks = [[0u8; 32]; MAX_CHUNKS];
    pack_be_slice(bytes, &mut chunks)?;

    // Poseidon preimage: length, then the k chunks.
    let mut inputs: [&[u8]; 1 + MAX_CHUNKS] = [&[]; 1 + MAX_CHUNKS];
    inputs[0] = len_fe.as_slice();
    for (slot, chunk) in inputs.iter_mut().skip(1).zip(chunks.iter()) {
        *slot = chunk.as_slice();
    }
    let used = inputs.get(..1 + n).ok_or(HasherError::InvalidNumFields)?;
    Poseidon::hashv(used)
}
