use spr_keypair::{hash::sha256, Curve, SigningKey};

use crate::KeypairWorld;

/// Ring authorization signs the transaction digest as an Ed25519 message.
pub(crate) fn digest(msg: &str) -> [u8; 32] {
    sha256(msg.as_bytes())
}

pub(crate) fn sign_message(world: &mut KeypairWorld, key: String, msg: String, dst: String) {
    let sig = world.sig_key(&key).sign_message(&digest(&msg)).unwrap();
    world.sigs.insert(dst, sig);
}

pub(crate) fn verifies(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(world
        .sig_key(&key)
        .pubkey()
        .verify_message(&digest(&msg), &signature));
}

pub(crate) fn does_not_verify(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(!world
        .sig_key(&key)
        .pubkey()
        .verify_message(&digest(&msg), &signature));
}

pub(crate) fn does_not_verify_tampered(
    world: &mut KeypairWorld,
    key: String,
    sig: String,
    msg: String,
) {
    let mut signature = *world.sigs.get(&sig).expect("signature not set");
    signature[0] ^= 0xff;
    assert!(!world
        .sig_key(&key)
        .pubkey()
        .verify_message(&digest(&msg), &signature));
}

pub(crate) fn signs_identically(world: &mut KeypairWorld, key: String, msg: String) {
    let k = world.sig_key(&key);
    assert_eq!(
        k.sign_message(&digest(&msg)).unwrap(),
        k.sign_message(&digest(&msg)).unwrap()
    );
}

pub(crate) fn signing_scheme_ed25519(world: &mut KeypairWorld, key: String) {
    assert_eq!(
        world.sig_key(&key).pubkey().curve().unwrap(),
        Curve::Ed25519
    );
}

pub(crate) fn secret_roundtrip(world: &mut KeypairWorld, key: String) {
    let k = world.sig_key(&key);
    let bytes = k.secret_bytes();
    let restored = SigningKey::from_ed25519_bytes(&bytes);
    assert_eq!(k.pubkey(), restored.pubkey());
    assert_eq!(*bytes, *restored.secret_bytes());
}

/// `new_ed25519` produces a genuine ed25519 key: it reports the eddsa rail,
/// signs and verifies a message (which an off-curve key could not), and its
/// confidential view tag is the raw 32-byte ed25519 public key.
pub(crate) fn new_ed25519_is_a_working_ed25519_key() {
    let key = SigningKey::new_ed25519();
    assert_eq!(key.curve(), Curve::Ed25519);

    let msg = [7u8; 32];
    let sig = key.sign_message(&msg).expect("ed25519 signing");
    assert!(key.pubkey().verify_message(&msg, &sig));

    let pubkey = key.pubkey();
    assert_eq!(pubkey.curve().unwrap(), Curve::Ed25519);
    assert_eq!(
        pubkey.confidential_view_tag().unwrap(),
        pubkey.as_ed25519().unwrap()
    );
}
