use super::{
    fixtures::{HashBytes, RULE_BROKEN},
    vectors::{native_hash, vectors},
};
use crate::harness::fixture::native;
use zk_program_sdk::{circuit, Bytes};

fn value(var: &circuit::CircuitVar) -> circuit::Field {
    circuit::value(var).expect("constant value")
}

fn check<const N: usize>(bytes: &[u8], expected: circuit::Field) {
    let bytes: [u8; N] = bytes.try_into().expect("vector width");
    assert_eq!(native_hash(&bytes), expected);
    assert_eq!(
        value(&circuit::Bytes::constant(&bytes).hash_bytes().expect("hash")),
        expected
    );
    let fixture = HashBytes {
        bytes: Bytes(bytes),
        hash: expected,
    };
    assert_eq!(native(&fixture), Ok(()));
    let wrong = circuit::Field::from(ark_bn254::Fr::from(expected) + ark_bn254::Fr::from(1u64));
    assert_eq!(
        native(&HashBytes {
            hash: wrong,
            ..fixture
        }),
        Err(RULE_BROKEN)
    );
}

#[test]
fn hardcoded_chunk_boundaries_match_native_hash_bytes_and_refuse_wrong_hashes() {
    for v in vectors() {
        let bytes = v.bytes();
        match bytes.len() {
            0 => check::<0>(&bytes, v.hash()),
            1 => check::<1>(&bytes, v.hash()),
            31 => check::<31>(&bytes, v.hash()),
            32 => check::<32>(&bytes, v.hash()),
            62 => check::<62>(&bytes, v.hash()),
            63 => check::<63>(&bytes, v.hash()),
            width => panic!("unhandled vector {} width {width}", v.name),
        }
    }
}

#[test]
fn zero_chunks_and_leading_zeros_follow_fixed_width_packing() {
    for bytes in [[0; 32], [255; 32], std::array::from_fn(|i| i as u8)] {
        check::<32>(&bytes, native_hash(&bytes));
    }
    assert_eq!(
        value(
            &circuit::Bytes::constant(&[0, 1])
                .hash_bytes()
                .expect("hash")
        ),
        value(&circuit::Bytes::constant(&[1]).hash_bytes().expect("hash"))
    );
    assert_ne!(native_hash(&[0; 31]), native_hash(&[0; 32]));
}

#[test]
fn checked_single_chunk_bytes_hash_to_their_big_endian_value() {
    check::<2>(&[1, 2], circuit::Field::from(258u64));
    check::<2>(&[1, 0], circuit::Field::from(256u64));
}
