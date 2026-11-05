use spr_keypair::{hash::sha256, Curve, PublicKey, SigningKey};

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

#[derive(serde::Deserialize)]
struct StrictVectors {
    signing_secret: String,
    public_key: String,
    message: String,
    honest_signature: String,
    cofactored_only: CofactoredOnly,
    small_order: SmallOrder,
}

#[derive(serde::Deserialize)]
struct CofactoredOnly {
    signature: String,
}

#[derive(serde::Deserialize)]
struct SmallOrder {
    public_key: String,
    signature: String,
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("hex")
        .try_into()
        .expect("vector width")
}

/// `test-vectors/ed25519_strict.json`, the cross-SDK vectors: a signature
/// whose R carries a torsion component (valid only under the cofactored
/// equation) and a small-order key that ed25519-dalek's non-strict `verify`
/// accepts. `verify_message` refuses both, as Solana and the eddsa circuits do.
pub(crate) fn verify_message_is_strict() {
    let vectors: StrictVectors =
        serde_json::from_str(include_str!("../../../../test-vectors/ed25519_strict.json"))
            .expect("ed25519_strict.json");
    let message = hex::decode(&vectors.message).expect("hex");

    let signer = SigningKey::from_ed25519_bytes(&hex_array(&vectors.signing_secret));
    let public_key = signer.pubkey();
    assert_eq!(
        public_key.as_ed25519().unwrap(),
        hex_array::<32>(&vectors.public_key)
    );
    let honest = hex_array(&vectors.honest_signature);
    assert_eq!(signer.sign_message(&message).unwrap(), honest);
    assert!(public_key.verify_message(&message, &honest));

    let cofactored_only = hex_array(&vectors.cofactored_only.signature);
    assert!(!public_key.verify_message(&message, &cofactored_only));

    let small_order_key = hex_array(&vectors.small_order.public_key);
    let small_order_signature = hex_array(&vectors.small_order.signature);
    let dalek_key = ed25519_dalek::VerifyingKey::from_bytes(&small_order_key).unwrap();
    let parsed = ed25519_dalek::Signature::from_bytes(&small_order_signature);
    assert!(
        ed25519_dalek::Verifier::verify(&dalek_key, &message, &parsed).is_ok(),
        "the non-strict equation accepts a small-order key"
    );
    assert!(
        !PublicKey::from_ed25519(&small_order_key).verify_message(&message, &small_order_signature)
    );
}
