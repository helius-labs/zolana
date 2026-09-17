use serde::Deserialize;
use zolana_hasher::{primitives::BN254_SCALAR_MODULUS_BE, Hasher, HasherError, Poseidon2};

#[derive(Deserialize)]
struct Vectors {
    parameters: Parameters,
    compress: Vec<Compress>,
    zero_nodes: Vec<String>,
}

#[derive(Deserialize)]
struct Parameters {
    width: usize,
    full_rounds: usize,
    partial_rounds: usize,
}

#[derive(Deserialize)]
struct Compress {
    left: String,
    right: String,
    hash: String,
}

fn word(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../../../test-vectors/tree_hash.json")).unwrap()
}

#[test]
fn shared_known_answer_vectors() {
    let vectors = vectors();
    assert_eq!(
        (
            vectors.parameters.width,
            vectors.parameters.full_rounds,
            vectors.parameters.partial_rounds
        ),
        (2, 6, 50)
    );
    for c in &vectors.compress {
        assert_eq!(
            Poseidon2::compress(&word(&c.left), &word(&c.right)).unwrap(),
            word(&c.hash),
            "{} {}",
            c.left,
            c.right
        );
    }
}

#[test]
fn zero_table_matches_vectors_and_ladder() {
    let vectors = vectors();
    let zero = Poseidon2::zero_bytes();
    assert_eq!(vectors.zero_nodes.len(), zero.len());
    for (i, node) in vectors.zero_nodes.iter().enumerate() {
        assert_eq!(zero[i], word(node), "level {i}");
    }
    for i in 1..zero.len() {
        assert_eq!(
            zero[i],
            Poseidon2::hashv(&[&zero[i - 1], &zero[i - 1]]).unwrap()
        );
    }
}

#[test]
fn hasher_shapes() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let ab = [a, b].concat();
    assert_eq!(
        Poseidon2::hash(&ab).unwrap(),
        Poseidon2::hashv(&[&a, &b]).unwrap()
    );
    assert_ne!(
        Poseidon2::hashv(&[&a, &b]).unwrap(),
        Poseidon2::hashv(&[&b, &a]).unwrap()
    );
    assert_eq!(Poseidon2::hashv(&[&a]), Err(HasherError::InvalidNumFields));
    assert_eq!(
        Poseidon2::hashv(&[&a, &b, &a]),
        Err(HasherError::InvalidNumFields)
    );
    assert_eq!(
        Poseidon2::hashv(&[&a[..31], &b]),
        Err(HasherError::InvalidInputLength(32, 31))
    );
    assert_eq!(
        Poseidon2::hash(&a),
        Err(HasherError::InvalidInputLength(64, 32))
    );
    assert_eq!(
        Poseidon2::hashv(&[&BN254_SCALAR_MODULUS_BE, &b]),
        Err(HasherError::InputLargerThanModulus)
    );
    let mut p_minus_one = BN254_SCALAR_MODULUS_BE;
    p_minus_one[31] -= 1;
    assert!(Poseidon2::hashv(&[&p_minus_one, &p_minus_one]).is_ok());
}
