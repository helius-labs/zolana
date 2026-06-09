use cucumber::then;
use sha2::{Digest, Sha256};
use zolana_keypair::hash::{owner_hash, sha256_be};
use zolana_keypair::{PublicKey, SigningKey};

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
    let pf = world.sig_key(&name).pubkey().hash().unwrap();
    assert_eq!(hex::encode(pf), expected);
}

#[then(expr = "pubkey_field of signing key {string} is stable")]
fn pubkey_field_stable(world: &mut KeypairWorld, name: String) {
    let pubkey = world.sig_key(&name).pubkey();
    assert_eq!(pubkey.hash().unwrap(), pubkey.hash().unwrap());
}

#[then(expr = "the owner hash of {string} is stable")]
fn owner_hash_stable(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    assert_eq!(kp.owner_hash().unwrap(), kp.owner_hash().unwrap());
}

#[then(expr = "the owner hash of {string} changes when the nullifier key changes")]
fn owner_hash_binds_nullifier(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    let signing_pubkey = kp.signing_pubkey();
    let nullifier_pubkey = kp.nullifier_key.pubkey().unwrap();
    let base = owner_hash(&signing_pubkey, &nullifier_pubkey).unwrap();
    let mut other = nullifier_pubkey;
    other[31] ^= 1;
    assert_ne!(base, owner_hash(&signing_pubkey, &other).unwrap());
}

#[then(expr = "a P256 owner and an Ed25519 owner hash differently")]
fn p256_ed25519_owner_hash_differ(_world: &mut KeypairWorld) {
    let nullifier_pubkey = [9u8; 32];
    let p256 = SigningKey::new().pubkey();
    let ed25519 = PublicKey::from_ed25519(&[7u8; 32]);
    assert_ne!(
        owner_hash(&p256, &nullifier_pubkey).unwrap(),
        owner_hash(&ed25519, &nullifier_pubkey).unwrap()
    );
}
