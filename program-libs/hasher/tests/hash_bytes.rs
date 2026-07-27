use serde::Deserialize;
use zolana_hasher::primitives::{hash_bytes, right_align};

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
