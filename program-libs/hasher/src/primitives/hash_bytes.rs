use crate::{primitives::PACK_BE_CHUNK_BYTES, Hasher, HasherError, Poseidon};

/// Commits a fixed-size byte value by packing it into 31-byte big-endian field
/// elements and folding them from left to right:
///
/// `acc = chunk_0; acc = Poseidon(acc, chunk_i)`.
///
/// Empty input maps to zero. A value that fits in one chunk is its packed field
/// representation and does not invoke Poseidon. This construction is only
/// suitable when `N` is fixed by the protocol: byte strings of different
/// lengths can have the same packed representation.
pub fn hash_bytes<const N: usize>(bytes: &[u8; N]) -> Result<[u8; 32], HasherError> {
    let mut chunks = bytes.chunks(PACK_BE_CHUNK_BYTES);
    let Some(first) = chunks.next() else {
        return Ok([0u8; 32]);
    };
    let mut accumulator = pack_chunk(first);
    for chunk in chunks {
        accumulator = Poseidon::hashv(&[&accumulator, &pack_chunk(chunk)])?;
    }
    Ok(accumulator)
}

fn pack_chunk(chunk: &[u8]) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[32 - chunk.len()..].copy_from_slice(chunk);
    field
}
