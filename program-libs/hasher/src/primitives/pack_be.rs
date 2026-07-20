use crate::errors::HasherError;

/// Bytes per `pack_be` chunk. 31 bytes < 2^248 < the BN254 modulus, so every
/// chunk is a valid field element and the packing is lossless.
pub const PACK_BE_CHUNK_BYTES: usize = 31;

/// Number of chunks `pack_be` produces for a `len`-byte input.
pub const fn pack_be_chunks(len: usize) -> usize {
    len.div_ceil(PACK_BE_CHUNK_BYTES)
}

/// Packs `N` bytes into `K = ceil(N/31)` field elements: consecutive 31-byte
/// big-endian chunks, each right-aligned into a 32-byte field element (the final
/// chunk holds the remaining `N mod 31` bytes). Lossless — the inverse is
/// concatenating each chunk's low bytes. `K` is checked against `N` at compile
/// time.
pub fn pack_be<const N: usize, const K: usize>(bytes: &[u8; N]) -> [[u8; 32]; K] {
    const { assert!(K == N.div_ceil(PACK_BE_CHUNK_BYTES)) };
    let mut out = [[0u8; 32]; K];
    for (fe, chunk) in out.iter_mut().zip(bytes.chunks(PACK_BE_CHUNK_BYTES)) {
        // `chunks` yields 1..=31 bytes, so `32 - len` is in 1..=31.
        if let Some(dst) = fe.get_mut(32 - chunk.len()..) {
            dst.copy_from_slice(chunk);
        }
    }
    out
}

/// Runtime-length `pack_be`: writes `ceil(len/31)` chunks into `out` and returns
/// the used prefix. Errors if `out` is too short.
pub fn pack_be_slice<'a>(
    bytes: &[u8],
    out: &'a mut [[u8; 32]],
) -> Result<&'a [[u8; 32]], HasherError> {
    let k = pack_be_chunks(bytes.len());
    let out_len = out.len();
    let used = out
        .get_mut(..k)
        .ok_or(HasherError::InvalidInputLength(k, out_len))?;
    for (fe, chunk) in used.iter_mut().zip(bytes.chunks(PACK_BE_CHUNK_BYTES)) {
        *fe = [0u8; 32];
        if let Some(dst) = fe.get_mut(32 - chunk.len()..) {
            dst.copy_from_slice(chunk);
        }
    }
    Ok(used)
}
