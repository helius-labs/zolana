use spr_hasher::{sha256::Sha256BE, Hasher, Keccak, Poseidon, Sha256};

/// Every hasher's empty-subtree table must be the chain its own `hashv`
/// produces from a zero leaf, or a tree using the table disagrees with a tree
/// that hashes empty subtrees directly.
fn assert_zero_bytes_match<H: Hasher>(name: &str) {
    let table = H::zero_bytes();
    let mut expected = [0u8; 32];
    for (level, actual) in table.iter().enumerate() {
        assert_eq!(*actual, expected, "{name} level {level}");
        expected = H::hashv(&[&expected, &expected]).unwrap();
    }
}

#[test]
fn zero_bytes_tables_match_their_hashers() {
    assert_zero_bytes_match::<Sha256>("Sha256");
    assert_zero_bytes_match::<Sha256BE>("Sha256BE");
    assert_zero_bytes_match::<Keccak>("Keccak");
    assert_zero_bytes_match::<Poseidon>("Poseidon");
}

#[test]
fn sha256_be_zero_bytes_clear_the_first_byte() {
    assert!(Sha256BE::zero_bytes()
        .iter()
        .all(|node| node.first() == Some(&0)));
}
