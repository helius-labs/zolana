use crate::{primitives::PACK_BE_CHUNK_BYTES, Hasher, HasherError, Poseidon};

/// Algorithm tag of a Solana owner identity (`'S'`): an ed25519 key or a PDA.
pub const SOLANA_OWNER_TAG: u8 = 0x53;

/// Commits a fixed-size byte value by packing it into 31-byte big-endian field
/// elements and folding them from left to right:
///
/// `acc = chunk_0; acc = Poseidon(acc, chunk_i)`.
///
/// Empty input maps to zero. A value that fits in one chunk is its packed field
/// representation and does not invoke Poseidon. This construction is only
/// suitable when `N` is fixed by the protocol: byte strings of different
/// lengths can have the same packed representation.
/// In particular, 32-byte and 33-byte values share a namespace. Keep their
/// protocol roles separate and never use equality across those roles as
/// evidence of identity or authorization.
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
/// Owner identities are algorithm tagged so they never collide with the
/// untagged `hash_bytes` of the same 32 bytes.
/// Mirrors Go `gadget/hash_bytes.go`.
pub fn solana_owner_identity(pk: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    tagged_identity(SOLANA_OWNER_TAG, pk)
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
