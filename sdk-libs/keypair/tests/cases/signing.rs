use zolana_keypair::{hash::sha256, Curve, KeypairError, SigningKey};

use crate::KeypairWorld;

/// The proof-path signing API signs a 32-byte prehash digest (the transaction
/// `message_hash`), so tests hash the fixture string to a digest first.
pub(crate) fn digest(msg: &str) -> [u8; 32] {
    sha256(msg.as_bytes())
}

pub(crate) fn sign_hash(world: &mut KeypairWorld, key: String, msg: String, dst: String) {
    let sig = world.sig_key(&key).sign_hash(&digest(&msg)).unwrap();
    world.sigs.insert(dst, sig);
}

pub(crate) fn verifies(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(world
        .sig_key(&key)
        .pubkey()
        .verify_hash(&digest(&msg), &signature));
}

pub(crate) fn does_not_verify(world: &mut KeypairWorld, key: String, sig: String, msg: String) {
    let signature = *world.sigs.get(&sig).expect("signature not set");
    assert!(!world
        .sig_key(&key)
        .pubkey()
        .verify_hash(&digest(&msg), &signature));
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
        .verify_hash(&digest(&msg), &signature));
}

pub(crate) fn signs_identically(world: &mut KeypairWorld, key: String, msg: String) {
    let k = world.sig_key(&key);
    assert_eq!(
        k.sign_hash(&digest(&msg)).unwrap(),
        k.sign_hash(&digest(&msg)).unwrap()
    );
}

pub(crate) fn signing_scheme_p256(world: &mut KeypairWorld, key: String) {
    assert_eq!(world.sig_key(&key).pubkey().curve().unwrap(), Curve::P256);
}

pub(crate) fn p256_secret_roundtrip(world: &mut KeypairWorld, key: String) {
    let k = world.sig_key(&key);
    let bytes = k.secret_bytes();
    let restored = SigningKey::from_p256_bytes(&bytes).unwrap();
    assert_eq!(k.pubkey(), restored.pubkey());
    assert_eq!(*bytes, *restored.secret_bytes());
}

/// `new_ed25519` produces a genuine ed25519 key: it reports the ed25519 rail,
/// signs and verifies a message (which an off-curve key could not), and its
/// confidential view tag is the raw 32-byte ed25519 public key. `new_p256`
/// stays on the P256 rail.
pub(crate) fn new_ed25519_is_a_working_ed25519_key() {
    let key = SigningKey::new_ed25519();
    assert_eq!(key.curve(), Curve::Ed25519);
    assert_eq!(SigningKey::new_p256().curve(), Curve::P256);

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

pub(crate) fn p256_message_signature_is_sha256_and_low_s() {
    let key = SigningKey::new_p256();
    let message = b"registry binding";
    let raw = key.sign_message(message).expect("P256 signature");
    let signature = p256::ecdsa::Signature::from_slice(&raw).expect("compact signature");
    assert!(signature.normalize_s().is_none(), "signature must be low-S");
    assert!(key.pubkey().verify_message(message, &raw));
    assert!(key.pubkey().verify_hash(&sha256(message), &raw));
}

pub(crate) fn ed25519_cannot_sign_hash() {
    let key = SigningKey::new_ed25519();
    assert_eq!(key.sign_hash(&[7u8; 32]), Err(KeypairError::NotP256));
}

pub(crate) fn ed25519_signature_does_not_verify_as_hash() {
    let key = SigningKey::new_ed25519();
    let msg = [7u8; 32];
    let sig = key.sign_message(&msg).expect("ed25519 signing");
    assert!(!key.pubkey().verify_hash(&msg, &sig));
}
