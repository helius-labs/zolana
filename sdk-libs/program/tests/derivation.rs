use zolana_hasher::primitives::right_align;
use zolana_program::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

/// `Poseidon("TXPB", small(7), small(42))`.
const PRIVATE_TX_BLINDING_VECTOR: [u8; 32] = [
    0x19, 0x91, 0xf1, 0x66, 0x20, 0x8c, 0x44, 0x0b, 0xa5, 0xec, 0xdb, 0x0f, 0x8c, 0xcc, 0x79, 0x2e,
    0x8d, 0x27, 0x39, 0x03, 0x8a, 0xe9, 0xd9, 0x98, 0x62, 0x62, 0x1c, 0xf2, 0xc2, 0x92, 0xf6, 0x10,
];

/// `Poseidon("TXOS", small(7), small(42))`.
const OUTPUT_BLINDING_SEED_VECTOR: [u8; 32] = [
    0x06, 0xbc, 0xa3, 0x16, 0x06, 0x66, 0x30, 0x05, 0x65, 0x39, 0x77, 0x2e, 0x0d, 0x19, 0xf5, 0xd9,
    0x45, 0x33, 0x31, 0xf9, 0xdd, 0xa2, 0xf0, 0xd0, 0x8e, 0xe0, 0x63, 0x2b, 0x6b, 0x51, 0x2d, 0xe3,
];

/// `Poseidon("TXOB", small(7), small(42), 3)`.
const OUTPUT_BLINDING_VECTOR: [u8; 32] = [
    0x06, 0x26, 0x15, 0x40, 0xe8, 0x57, 0xfe, 0xbb, 0x5f, 0x8d, 0x59, 0xeb, 0x74, 0x2a, 0xd3, 0xd4,
    0xd8, 0x20, 0x0f, 0xf3, 0x8c, 0xcb, 0xf2, 0xea, 0x16, 0xcd, 0x1e, 0x0a, 0x90, 0x85, 0xe8, 0x81,
];

fn small(value: u8) -> [u8; 32] {
    right_align(&[value])
}

/// The three derivations are separated by 32-bit ASCII tags, which is what
/// keeps a disclosed output blinding seed from reaching the private
/// transaction blinding of the same root seed. Mirrors
/// `circuits/spp_transaction/shared/derivation.go`.
#[test]
fn transact_domains_are_ascii_tags() {
    assert_eq!(
        DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1.to_be_bytes(),
        *b"TXOS"
    );
    assert_eq!(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1.to_be_bytes(), *b"TXOB");
    assert_eq!(DOMAIN_PRIVATE_TX_BLINDING_V1.to_be_bytes(), *b"TXPB");
}

#[test]
fn transact_output_blinding_matches_circuit_vector() {
    let got = derive_transact_output_blinding(&small(7), &small(42), 3).unwrap();
    assert_eq!(got, OUTPUT_BLINDING_VECTOR);
}

#[test]
fn output_blinding_seed_matches_circuit_vector() {
    let got = derive_output_blinding_seed(&small(7), &small(42)).unwrap();
    assert_eq!(got, OUTPUT_BLINDING_SEED_VECTOR);
}

/// Both children of one root seed must differ, or a disclosed seed would
/// reveal the transaction-hash blinding.
#[test]
fn private_tx_blinding_matches_circuit_vector() {
    let got = derive_private_tx_blinding(&small(7), &small(42)).unwrap();
    assert_eq!(got, PRIVATE_TX_BLINDING_VECTOR);
    assert_ne!(got, OUTPUT_BLINDING_SEED_VECTOR);
}
