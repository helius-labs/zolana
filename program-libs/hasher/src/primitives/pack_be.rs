/// Bytes per packed field element. Every 31-byte value is below `2^248` and
/// therefore below the BN254 scalar-field modulus.
pub const PACK_BE_CHUNK_BYTES: usize = 31;

/// Number of 31-byte chunks needed to encode `len` bytes.
pub const fn pack_be_chunks(len: usize) -> usize {
    len.div_ceil(PACK_BE_CHUNK_BYTES)
}

/// Packs a fixed-size byte array into consecutive 31-byte big-endian field
/// elements. Each chunk is right-aligned in its 32-byte field representation.
///
/// `K` must equal `ceil(N / 31)`.
pub fn pack_be<const N: usize, const K: usize>(bytes: &[u8; N]) -> [[u8; 32]; K] {
    const { assert!(K == N.div_ceil(PACK_BE_CHUNK_BYTES)) };
    let mut output = [[0u8; 32]; K];
    for (field, chunk) in output.iter_mut().zip(bytes.chunks(PACK_BE_CHUNK_BYTES)) {
        field[32 - chunk.len()..].copy_from_slice(chunk);
    }
    output
}
