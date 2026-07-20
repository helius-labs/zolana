#![cfg(feature = "poseidon")]

use zolana_hasher::{
    primitives::{hash_bytes, MAX_HASH_BYTES_LEN},
    HasherError,
};

/// Pinned output for a fixed input. Guards against accidental drift;
/// cross-checked against the Go host (`protocol.HashBytes`).
#[test]
fn hash_bytes_matches_pinned_vector() {
    let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
    let got = hash_bytes(&bytes).unwrap();
    let expected: [u8; 32] = [
        22, 255, 108, 217, 229, 253, 159, 244, 71, 10, 238, 230, 153, 172, 160, 31, 13, 201, 200,
        82, 40, 108, 184, 5, 118, 175, 148, 215, 79, 111, 49, 122,
    ]; // cross-checked against Go host (matches protocol.HashBytes)
    assert_eq!(got, expected);
}

/// Length binding makes the encoding injective: `pack_be` alone maps
/// `[0x00, 0x01]` and `[0x01]` to the same chunk, but the `len_fe` input differs.
#[test]
fn length_binding_is_injective() {
    assert_ne!(
        hash_bytes(&[0x00, 0x01]).unwrap(),
        hash_bytes(&[0x01]).unwrap()
    );
}

/// A 32-byte and a 33-byte input never collide (distinct length field), which is
/// what separates an owner tag from a SEC1 viewing key.
#[test]
fn different_lengths_are_distinct() {
    let a = hash_bytes(&[7u8; 32]).unwrap();
    let b = hash_bytes(&[7u8; 33]).unwrap();
    assert_ne!(a, b);
}

#[test]
fn boundary_lengths_accepted() {
    for len in [1usize, 31, 32, 62, 63, MAX_HASH_BYTES_LEN] {
        let bytes = vec![1u8; len];
        assert!(hash_bytes(&bytes).is_ok(), "len {len}");
    }
}

#[test]
fn empty_input_rejected() {
    assert_eq!(hash_bytes(&[]), Err(HasherError::EmptyInput));
}

#[test]
fn over_max_length_rejected() {
    let bytes = vec![0u8; MAX_HASH_BYTES_LEN + 1];
    assert!(matches!(
        hash_bytes(&bytes),
        Err(HasherError::InvalidInputLength(_, _))
    ));
}
