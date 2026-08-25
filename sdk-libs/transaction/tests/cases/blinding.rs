use zolana_keypair::hash::sha256_be;
use zolana_transaction::{derive_blinding, utxo::derive_transact_output_blinding};

pub(crate) fn blindings_deterministic() {
    let seed = [5u8; 32];
    assert_eq!(derive_blinding(&seed, 0), derive_blinding(&seed, 0));
    assert_eq!(derive_blinding(&seed, 3), derive_blinding(&seed, 3));
    assert_ne!(derive_blinding(&seed, 0), derive_blinding(&seed, 1));
}

pub(crate) fn transact_output_blinding_matches_circuit_vector() {
    let mut first_nullifier = [0u8; 32];
    first_nullifier[31] = 7;
    let mut seed = [0u8; 32];
    seed[31] = 42;
    let got = derive_transact_output_blinding(&first_nullifier, &seed, 3).unwrap();
    assert_eq!(
        got,
        [
            0x06, 0x26, 0x15, 0x40, 0xe8, 0x57, 0xfe, 0xbb, 0x5f, 0x8d, 0x59, 0xeb, 0x74, 0x2a,
            0xd3, 0xd4, 0xd8, 0x20, 0x0f, 0xf3, 0x8c, 0xcb, 0xf2, 0xea, 0x16, 0xcd, 0x1e, 0x0a,
            0x90, 0x85, 0xe8, 0x81,
        ]
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
