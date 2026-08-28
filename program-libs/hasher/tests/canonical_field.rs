use num_bigint::BigUint;
use zolana_hasher::primitives::{is_canonical_bn254_scalar_be, BN254_SCALAR_MODULUS_BE};

const BN254_MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

fn modulus() -> BigUint {
    BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).unwrap()
}

fn to_be_bytes(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

#[test]
fn modulus_constant_matches_decimal_literal() {
    assert_eq!(BN254_SCALAR_MODULUS_BE, to_be_bytes(&modulus()));
}

#[test]
fn rejects_modulus_and_above() {
    assert!(!is_canonical_bn254_scalar_be(&BN254_SCALAR_MODULUS_BE));
    assert!(!is_canonical_bn254_scalar_be(&to_be_bytes(
        &(modulus() + 1u32)
    )));
    assert!(!is_canonical_bn254_scalar_be(&[0xff; 32]));
    let mut just_above_top_byte = [0u8; 32];
    just_above_top_byte[0] = 0x31;
    assert!(!is_canonical_bn254_scalar_be(&just_above_top_byte));
}

#[test]
fn accepts_values_below_modulus() {
    assert!(is_canonical_bn254_scalar_be(&[0u8; 32]));
    assert!(is_canonical_bn254_scalar_be(&to_be_bytes(
        &(modulus() - 1u32)
    )));
    let mut top_byte_below = [0xff; 32];
    top_byte_below[0] = 0x2f;
    assert!(is_canonical_bn254_scalar_be(&top_byte_below));
}
