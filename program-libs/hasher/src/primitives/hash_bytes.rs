use crate::{primitives::PACK_BE_CHUNK_BYTES, Hasher, HasherError, Poseidon};

/// Algorithm tag of a Solana owner identity (`'S'`): an ed25519 key or a PDA.
pub const SOLANA_OWNER_TAG: u8 = 0x53;
/// Algorithm tag of a P256 owner identity (`'P'`): the 32-byte x-coordinate.
pub const P256_OWNER_TAG: u8 = 0x50;

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

/// Owner identity of a Solana key: `hash_bytes_33(SOLANA_OWNER_TAG || pk)`.
///
/// Owner identities are algorithm tagged so a P256 x-coordinate and a Solana
/// key with equal bytes never share an identity, and neither collides with the
/// untagged `hash_bytes` of the same 32 bytes or with the `hash_bytes_33`
/// commitment over a SEC1-compressed key (whose first byte is 0x02..0x04).
/// Mirrors Go `gadget/owner_identity.go`.
pub fn solana_owner_identity(pk: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    tagged_identity(SOLANA_OWNER_TAG, pk)
}

/// Owner identity of a P256 key by its big-endian x-coordinate:
/// `hash_bytes_33(P256_OWNER_TAG || x)`. See [`solana_owner_identity`].
pub fn p256_owner_identity(x: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    tagged_identity(P256_OWNER_TAG, x)
}

fn tagged_identity(tag: u8, key: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    let mut tagged = [0u8; 33];
    tagged[0] = tag;
    tagged[1..].copy_from_slice(key);
    hash_bytes(&tagged)
}

fn pack_chunk(chunk: &[u8]) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[32 - chunk.len()..].copy_from_slice(chunk);
    field
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    /// The tagged identity is a two-chunk `hash_bytes_33`: chunk 0 holds the
    /// tag followed by the first 30 key bytes, chunk 1 the last two key bytes,
    /// each right-aligned in a field element, folded with one Poseidon call.
    fn expected_identity(tag: u8, key: &[u8; 32]) -> [u8; 32] {
        let mut chunk_0 = [0u8; 32];
        chunk_0[1] = tag;
        chunk_0[2..].copy_from_slice(&key[..30]);
        let mut chunk_1 = [0u8; 32];
        chunk_1[30..].copy_from_slice(&key[30..]);
        Poseidon::hashv(&[&chunk_0, &chunk_1]).unwrap()
    }

    #[test]
    fn owner_identities_are_tagged_hash_bytes_33() {
        let key = key();
        assert_eq!(
            solana_owner_identity(&key).unwrap(),
            expected_identity(SOLANA_OWNER_TAG, &key)
        );
        assert_eq!(
            p256_owner_identity(&key).unwrap(),
            expected_identity(P256_OWNER_TAG, &key)
        );
    }

    #[test]
    fn owner_identities_differ_from_each_other_and_from_untagged_hash() {
        let key = key();
        let solana = solana_owner_identity(&key).unwrap();
        let p256 = p256_owner_identity(&key).unwrap();
        let untagged = hash_bytes(&key).unwrap();
        assert_ne!(solana, p256);
        assert_ne!(solana, untagged);
        assert_ne!(p256, untagged);
    }

    #[test]
    fn owner_identity_vectors_are_pinned() {
        let key = key();
        assert_eq!(
            solana_owner_identity(&key).unwrap(),
            [
                0x27, 0x7e, 0x7b, 0x24, 0x9a, 0xd4, 0x3c, 0xf3, 0xb0, 0x90, 0xb9, 0x88, 0x08, 0xcd,
                0xd8, 0x31, 0x6a, 0xa7, 0x2f, 0x72, 0xe1, 0xfc, 0x09, 0x8d, 0xcd, 0x84, 0x53, 0x2f,
                0xa3, 0xc3, 0x55, 0x5f,
            ]
        );
        assert_eq!(
            p256_owner_identity(&key).unwrap(),
            [
                0x07, 0x20, 0xe7, 0xed, 0x52, 0x8b, 0xcd, 0xd2, 0x59, 0x07, 0xa4, 0xf2, 0xd2, 0xc9,
                0xb7, 0xe0, 0xf1, 0x2d, 0x70, 0x07, 0x96, 0xd2, 0xbf, 0x15, 0xe4, 0x27, 0xbf, 0x3f,
                0xe4, 0x65, 0x9b, 0x50,
            ]
        );
    }
}
