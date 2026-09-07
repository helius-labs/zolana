use zolana_keypair::hash::{poseidon, sha256_be};
use zolana_transaction::{
    derive_blinding,
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
        DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
        DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
    },
};

use super::utxo::fe;

/// `Poseidon("TXPB", small(7), small(42))`.
const PRIVATE_TX_BLINDING_VECTOR: [u8; 32] = [
    0x19, 0x91, 0xf1, 0x66, 0x20, 0x8c, 0x44, 0x0b, 0xa5, 0xec, 0xdb, 0x0f, 0x8c, 0xcc, 0x79, 0x2e,
    0x8d, 0x27, 0x39, 0x03, 0x8a, 0xe9, 0xd9, 0x98, 0x62, 0x62, 0x1c, 0xf2, 0xc2, 0x92, 0xf6, 0x10,
];

fn small(value: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = value;
    out
}

pub(crate) fn blindings_deterministic() {
    let seed = [5u8; 32];
    assert_eq!(derive_blinding(&seed, 0), derive_blinding(&seed, 0));
    assert_eq!(derive_blinding(&seed, 3), derive_blinding(&seed, 3));
    assert_ne!(derive_blinding(&seed, 0), derive_blinding(&seed, 1));
}

/// The three transact derivations are separated by 32-bit ASCII tags, which is
/// what keeps a disclosed output blinding seed from reaching the private
/// transaction blinding of the same secret. Mirrors
/// `circuits/spp_transaction/shared/derivation.go`.
pub(crate) fn transact_domains_are_ascii_tags() {
    assert_eq!(
        DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1.to_be_bytes(),
        *b"TXOS"
    );
    assert_eq!(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1.to_be_bytes(), *b"TXOB");
    assert_eq!(DOMAIN_PRIVATE_TX_BLINDING_V1.to_be_bytes(), *b"TXPB");
}

pub(crate) fn transact_output_blinding_matches_circuit_vector() {
    let first_nullifier = small(7);
    let seed = small(42);
    let got = derive_transact_output_blinding(&first_nullifier, &seed, 3).unwrap();
    assert_eq!(
        got,
        [
            0x06, 0x26, 0x15, 0x40, 0xe8, 0x57, 0xfe, 0xbb, 0x5f, 0x8d, 0x59, 0xeb, 0x74, 0x2a,
            0xd3, 0xd4, 0xd8, 0x20, 0x0f, 0xf3, 0x8c, 0xcb, 0xf2, 0xea, 0x16, 0xcd, 0x1e, 0x0a,
            0x90, 0x85, 0xe8, 0x81,
        ]
    );
    // Poseidon("TXOB", first_nullifier, seed, output_index).
    let expected = poseidon(&[
        &fe(*b"TXOB"),
        &first_nullifier,
        &seed,
        &fe(3u32.to_be_bytes()),
    ])
    .unwrap();
    assert_eq!(got, expected);
}

/// `output_blinding_seed = Poseidon("TXOS", first_nullifier, tx_secret)`.
pub(crate) fn output_blinding_seed_matches_circuit_vector() {
    let first_nullifier = small(7);
    let tx_secret = small(42);
    let got = derive_output_blinding_seed(&first_nullifier, &tx_secret).unwrap();
    let expected = poseidon(&[&fe(*b"TXOS"), &first_nullifier, &tx_secret]).unwrap();
    assert_eq!(got, expected);
    assert_eq!(
        got,
        [
            0x06, 0xbc, 0xa3, 0x16, 0x06, 0x66, 0x30, 0x05, 0x65, 0x39, 0x77, 0x2e, 0x0d, 0x19,
            0xf5, 0xd9, 0x45, 0x33, 0x31, 0xf9, 0xdd, 0xa2, 0xf0, 0xd0, 0x8e, 0xe0, 0x63, 0x2b,
            0x6b, 0x51, 0x2d, 0xe3,
        ]
    );
}

/// `private_tx_blinding = Poseidon("TXPB", first_nullifier, secret)`. Both
/// children of one secret must differ, or a disclosed seed would reveal the
/// transaction-hash blinding.
pub(crate) fn private_tx_blinding_matches_circuit_vector() {
    let first_nullifier = small(7);
    let tx_secret = small(42);
    let got = derive_private_tx_blinding(&first_nullifier, &tx_secret).unwrap();
    let expected = poseidon(&[&fe(*b"TXPB"), &first_nullifier, &tx_secret]).unwrap();
    assert_eq!(got, expected);
    assert_eq!(got, PRIVATE_TX_BLINDING_VECTOR);
    assert_ne!(
        got,
        derive_output_blinding_seed(&first_nullifier, &tx_secret).unwrap()
    );
}

pub(crate) fn blinding_top_byte_dropped() {
    let seed = [7u8; 32];
    let blinding = derive_blinding(&seed, 0);
    let mut preimage = [0u8; 32];
    preimage[..31].copy_from_slice(&seed[1..]);
    let digest = sha256_be(&preimage);
    assert_eq!(blinding[0], 0);
    assert_eq!(blinding[1..], digest[1..]);
}
