use zolana_keypair::{hash::sha256, SignatureType, SigningKey};

use crate::KeypairWorld;

/// The signing API signs a 32-byte prehash digest (the transaction
/// `message_hash`), so tests hash the fixture string to a digest first.
pub(crate) fn digest(msg: &str) -> [u8; 32] {
    sha256(msg.as_bytes())
}

pub(crate) fn sign_message(world: &mut KeypairWorld, key: String, msg: String, dst: String) {
    let sig = world.sig_key(&key).sign(&digest(&msg));
    world.sigs.insert(dst, sig);
}

pub(crate) fn verifies(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(world.sig_key(&key).verify(&digest(&msg), &signature));
}

pub(crate) fn does_not_verify(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(!world.sig_key(&key).verify(&digest(&msg), &signature));
}

pub(crate) fn does_not_verify_tampered(
    world: &mut KeypairWorld,
    key: String,
    sig: String,
    msg: String,
) {
    let mut signature = *world.sigs.get(&sig).expect("signature not set");
    signature[0] ^= 0xff;
    assert!(!world.sig_key(&key).verify(&digest(&msg), &signature));
}

pub(crate) fn signs_identically(world: &mut KeypairWorld, key: String, msg: String) {
    let k = world.sig_key(&key);
    assert_eq!(k.sign(&digest(&msg)), k.sign(&digest(&msg)));
}

pub(crate) fn signing_scheme_p256(world: &mut KeypairWorld, key: String) {
    assert_eq!(
        world.sig_key(&key).pubkey().signature_type().unwrap(),
        SignatureType::P256
    );
}

pub(crate) fn p256_secret_roundtrip(world: &mut KeypairWorld, key: String) {
    let k = world.sig_key(&key);
    let bytes = k.secret_bytes();
    let restored = SigningKey::from_bytes(&bytes).unwrap();
    assert_eq!(k.pubkey(), restored.pubkey());
    assert_eq!(*bytes, *restored.secret_bytes());
}
