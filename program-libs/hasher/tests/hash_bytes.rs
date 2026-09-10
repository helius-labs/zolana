use serde::Deserialize;
use zolana_hasher::{
    primitives::{
        hash_bytes, p256_owner_identity, right_align, solana_owner_identity, P256_OWNER_TAG,
        SOLANA_OWNER_TAG,
    },
    Hasher, Poseidon,
};

#[derive(Deserialize)]
struct HashBytesVector {
    name: String,
    input: String,
    output: String,
}

#[test]
fn empty_and_single_chunk_have_identity_encoding() {
    assert_eq!(hash_bytes(&[]).unwrap(), [0u8; 32]);
    assert_eq!(hash_bytes(&[1u8]).unwrap(), right_align(&[1u8]));
    assert_eq!(
        hash_bytes(&[0u8, 1]).unwrap(),
        hash_bytes(&[1u8]).unwrap(),
        "different lengths are intentionally not bound"
    );
}

#[test]
fn shared_known_answer_vectors() {
    let vectors: Vec<HashBytesVector> =
        serde_json::from_str(include_str!("../../../test-vectors/hash_bytes.json")).unwrap();
    for vector in vectors {
        let input = hex::decode(&vector.input).unwrap();
        let expected: [u8; 32] = hex::decode(&vector.output).unwrap().try_into().unwrap();
        let actual = match input.len() {
            0 => hash_bytes(&<[u8; 0]>::try_from(input.as_slice()).unwrap()),
            1 => hash_bytes(&<[u8; 1]>::try_from(input.as_slice()).unwrap()),
            31 => hash_bytes(&<[u8; 31]>::try_from(input.as_slice()).unwrap()),
            32 => hash_bytes(&<[u8; 32]>::try_from(input.as_slice()).unwrap()),
            62 => hash_bytes(&<[u8; 62]>::try_from(input.as_slice()).unwrap()),
            63 => hash_bytes(&<[u8; 63]>::try_from(input.as_slice()).unwrap()),
            length => panic!("unsupported shared vector length {length}"),
        }
        .unwrap();
        assert_eq!(actual, expected, "vector {}", vector.name);
    }
}

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
