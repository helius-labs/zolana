use cucumber::then;
use zolana_keypair::{constants::BLINDING_LEN, hash::sha256_be};
use zolana_transaction::derive_blinding;

use crate::TransactionWorld;

#[then(expr = "output blindings are deterministic and differ by position")]
fn blindings_deterministic(_world: &mut TransactionWorld) {
    let seed = [5u8; BLINDING_LEN];
    assert_eq!(derive_blinding(&seed, 0), derive_blinding(&seed, 0));
    assert_eq!(derive_blinding(&seed, 3), derive_blinding(&seed, 3));
    assert_ne!(derive_blinding(&seed, 0), derive_blinding(&seed, 1));
}

#[then(expr = "a blinding equals the sha256-be digest tail")]
fn blinding_top_byte_dropped(_world: &mut TransactionWorld) {
    let seed = [7u8; BLINDING_LEN];
    let blinding = derive_blinding(&seed, 0);
    let mut preimage = [0u8; BLINDING_LEN + 1];
    preimage[..BLINDING_LEN].copy_from_slice(&seed);
    let digest = sha256_be(&preimage);
    assert_eq!(digest[0], 0);
    assert_eq!(blinding, digest[1..]);
}
