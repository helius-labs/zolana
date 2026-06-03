use cucumber::{then, when};
use zolana_keypair::{SignatureType, SigningKey};

use crate::KeypairWorld;

#[when(expr = "{string} signs {string} as {string}")]
fn sign_message(world: &mut KeypairWorld, key: String, msg: String, dst: String) {
    let sig = world.sig_key(&key).sign(msg.as_bytes());
    world.sigs.insert(dst, sig);
}

#[then(expr = "{string} verifies {string} over {string}")]
fn verifies(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(world.sig_key(&key).verify(msg.as_bytes(), &signature));
}

#[then(expr = "{string} does not verify {string} over {string}")]
fn does_not_verify(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(!world.sig_key(&key).verify(msg.as_bytes(), &signature));
}

#[then(expr = "{string} does not verify a tampered {string} over {string}")]
fn does_not_verify_tampered(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let mut signature = *world.sigs.get(&sig).expect("signature not set");
    signature[0] ^= 0xff;
    assert!(!world.sig_key(&key).verify(msg.as_bytes(), &signature));
}

#[then(expr = "{string} signs {string} identically twice")]
fn signs_identically(world: &mut KeypairWorld, key: String, msg: String) {
    let k = world.sig_key(&key);
    assert_eq!(k.sign(msg.as_bytes()), k.sign(msg.as_bytes()));
}

#[then(expr = "signing key {string} has scheme P256")]
fn signing_scheme_p256(world: &mut KeypairWorld, key: String) {
    assert_eq!(
        world.sig_key(&key).signing_pubkey().signature_type(),
        SignatureType::P256
    );
}

#[then(expr = "signing key {string} has scheme Ed25519")]
fn signing_scheme_ed25519(world: &mut KeypairWorld, key: String) {
    assert_eq!(
        world.sig_key(&key).signing_pubkey().signature_type(),
        SignatureType::Ed25519
    );
}

#[then(expr = "signing key {string} round-trips through P256 secret bytes")]
fn p256_secret_roundtrip(world: &mut KeypairWorld, key: String) {
    let k = world.sig_key(&key);
    let bytes = k.secret_bytes();
    let restored = SigningKey::from_p256_bytes(&bytes).unwrap();
    assert_eq!(k.signing_pubkey(), restored.signing_pubkey());
    assert_eq!(*bytes, *restored.secret_bytes());
}

#[then(expr = "signing key {string} round-trips through an Ed25519 seed")]
fn ed25519_seed_roundtrip(world: &mut KeypairWorld, key: String) {
    let k = world.sig_key(&key);
    let seed = k.secret_bytes();
    let restored = SigningKey::from_ed25519_seed(&seed);
    assert_eq!(k.signing_pubkey(), restored.signing_pubkey());
}
