use cucumber::then;
use zolana_keypair::{constants::BLINDING_LEN, NullifierKey};

use crate::KeypairWorld;

#[then(expr = "the nullifier key derived from {string} is deterministic")]
fn nullifier_deterministic(world: &mut KeypairWorld, key: String) {
    let a = NullifierKey::from_signing_key(world.sig_key(&key)).unwrap();
    let b = NullifierKey::from_signing_key(world.sig_key(&key)).unwrap();
    assert_eq!(a.secret(), b.secret());
    assert_eq!(a.pubkey().unwrap(), b.pubkey().unwrap());
}

#[then(expr = "{string} and {string} derive different nullifier secrets")]
fn distinct_nullifier_secrets(world: &mut KeypairWorld, a: String, b: String) {
    let na = NullifierKey::from_signing_key(world.sig_key(&a)).unwrap();
    let nb = NullifierKey::from_signing_key(world.sig_key(&b)).unwrap();
    assert_ne!(na.secret(), nb.secret());
}

#[then("a nullifier changes with the utxo hash, the blinding, and the secret")]
fn nullifier_binds_inputs(_world: &mut KeypairWorld) {
    let nk = NullifierKey::from_secret([9u8; BLINDING_LEN]);
    let h1 = [1u8; 32];
    let h2 = [2u8; 32];
    let b1 = [3u8; BLINDING_LEN];
    let b2 = [4u8; BLINDING_LEN];
    let base = nk.nullifier(&h1, &b1).unwrap();
    assert_eq!(base, nk.nullifier(&h1, &b1).unwrap());
    assert_ne!(base, nk.nullifier(&h2, &b1).unwrap());
    assert_ne!(base, nk.nullifier(&h1, &b2).unwrap());
    let other = NullifierKey::from_secret([8u8; BLINDING_LEN]);
    assert_ne!(base, other.nullifier(&h1, &b1).unwrap());
}

#[then(expr = "the nullifier public key for secret {int} is {string}")]
fn nullifier_pubkey_golden(_world: &mut KeypairWorld, fill: u8, expected: String) {
    let nk = NullifierKey::from_secret([fill; BLINDING_LEN]);
    assert_eq!(hex::encode(nk.pubkey().unwrap()), expected);
}
