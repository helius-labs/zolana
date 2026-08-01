use zolana_keypair::hash::sha256_be;
use zolana_transaction::derive_blinding;

pub(crate) fn blindings_deterministic() {
    let seed = [5u8; 32];
    assert_eq!(derive_blinding(&seed, 0), derive_blinding(&seed, 0));
    assert_eq!(derive_blinding(&seed, 3), derive_blinding(&seed, 3));
    assert_ne!(derive_blinding(&seed, 0), derive_blinding(&seed, 1));
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
