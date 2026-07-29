use cucumber::then;
use zolana_keypair::hash::sha256_be;
use zolana_transaction::derive_blinding;

use crate::TransactionWorld;

#[then(expr = "output blindings are deterministic and differ by position")]
fn blindings_deterministic(_world: &mut TransactionWorld) {
    let seed = [5u8; 32];
    assert_eq!(derive_blinding(&seed, 0), derive_blinding(&seed, 0));
    assert_eq!(derive_blinding(&seed, 3), derive_blinding(&seed, 3));
    assert_ne!(derive_blinding(&seed, 0), derive_blinding(&seed, 1));
}

#[then(expr = "a blinding equals the sha256-be digest tail")]
fn blinding_top_byte_dropped(_world: &mut TransactionWorld) {
    let seed = [7u8; 32];
    let blinding = derive_blinding(&seed, 0);
    // The preimage is the seed's low 31 bytes (right-aligned semantics) plus the
    // position; the blinding is the digest's 31-byte tail, right-aligned.
    let mut preimage = [0u8; 32];
    preimage[..31].copy_from_slice(&seed[1..]);
    let digest = sha256_be(&preimage);
    assert_eq!(blinding[0], 0);
    assert_eq!(blinding[1..], digest[1..]);
}
