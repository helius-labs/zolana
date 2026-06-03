use cucumber::then;
use sha2::{Digest, Sha256};
use zolana_keypair::{owner_hash, pubkey_field, sha256_be};

use crate::KeypairWorld;

#[then(expr = "sha256_be of {string} has a zero first byte and matches SHA-256")]
fn sha256_be_matches(_world: &mut KeypairWorld, input: String) {
    let got = sha256_be(input.as_bytes());
    let raw: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    assert_eq!(got[0], 0);
    assert_eq!(&got[1..], &raw[1..]);
}

#[then(expr = "pubkey_field of signing key {string} is {string}")]
fn pubkey_field_golden(world: &mut KeypairWorld, name: String, expected: String) {
    let pf = pubkey_field(&world.sig_key(&name).signing_pubkey()).unwrap();
    assert_eq!(hex::encode(pf), expected);
}

#[then(expr = "pubkey_field of signing key {string} is stable")]
fn pubkey_field_stable(world: &mut KeypairWorld, name: String) {
    let pubkey = world.sig_key(&name).signing_pubkey();
    assert_eq!(
        pubkey_field(&pubkey).unwrap(),
        pubkey_field(&pubkey).unwrap()
    );
}

#[then(expr = "the owner hash of {string} is stable")]
fn owner_hash_stable(world: &mut KeypairWorld, name: String) {
    let kp = world.sk(&name);
    assert_eq!(kp.owner_hash().unwrap(), kp.owner_hash().unwrap());
}

#[then(expr = "the owner hash of {string} changes when the nullifier key changes")]
fn owner_hash_binds_nullifier(world: &mut KeypairWorld, name: String) {
    let kp = world.sk(&name);
    let signing_pubkey = kp.signing_pubkey();
    let nullifier_pubkey = kp.nullifier_pubkey().unwrap();
    let base = owner_hash(&signing_pubkey, &nullifier_pubkey).unwrap();
    let mut other = nullifier_pubkey;
    other[31] ^= 1;
    assert_ne!(base, owner_hash(&signing_pubkey, &other).unwrap());
}

#[then(expr = "{string} and {string} have different owner hashes")]
fn different_owner_hashes(world: &mut KeypairWorld, a: String, b: String) {
    assert_ne!(
        world.sk(&a).owner_hash().unwrap(),
        world.sk(&b).owner_hash().unwrap()
    );
}
