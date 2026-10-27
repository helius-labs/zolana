use spr_keypair::{
    constants::BLINDING_LEN,
    derivation::{ed25519_derivation_message, ED25519_DERIVATION_MSG},
    KeypairError, NullifierKey, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey,
};

use crate::KeypairWorld;

fn dalek_sign(secret: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;

    ed25519_dalek::SigningKey::from_bytes(secret)
        .sign(message)
        .to_bytes()
}

fn dalek_derivation_seed(secret: &[u8; 32]) -> [u8; 64] {
    let pubkey = ed25519_dalek::SigningKey::from_bytes(secret)
        .verifying_key()
        .to_bytes();
    dalek_sign(secret, &ed25519_derivation_message(&pubkey))
}

pub(crate) fn expand_nullifier_secret(seed: &[u8], info: &[u8]) -> [u8; BLINDING_LEN] {
    let mut secret = [0u8; BLINDING_LEN];
    hkdf::Hkdf::<sha2::Sha256>::new(None, seed)
        .expand(info, &mut secret)
        .unwrap();
    secret
}

pub(crate) fn expand_viewing_pubkey(seed: &[u8], info: &[u8]) -> X25519Pubkey {
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, seed)
        .expand(info, &mut okm)
        .unwrap();
    ViewingKey::from_bytes(&okm).pubkey()
}

pub(crate) fn derivation_seed_matches_rail_primitives() {
    let ed = SigningKey::from_ed25519_bytes(&[7u8; 32]);
    assert_eq!(
        ed.derivation_seed().unwrap().as_slice(),
        dalek_derivation_seed(&[7u8; 32])
    );
    assert_ne!(
        ed.derivation_seed().unwrap().as_slice(),
        dalek_sign(&[7u8; 32], ED25519_DERIVATION_MSG)
    );
}

pub(crate) fn eddsa_rail_matches_signature_entry_point() {
    let sig = dalek_derivation_seed(&[7u8; 32]);
    let device_secret = expand_nullifier_secret(&sig, b"TSPP/nf_key/ed25519/v1");
    let software =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32])).unwrap();
    assert_eq!(device_secret, *software.nullifier_key.secret());
}

pub(crate) fn solana_keypair_matches_eddsa_rail() {
    let solana = solana_keypair::Keypair::new_from_array([7u8; 32]);
    let via_solana = ShieldedKeypair::from_keypair(&solana).unwrap();
    let via_signing =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32])).unwrap();
    assert_eq!(
        *via_solana.nullifier_key.secret(),
        *via_signing.nullifier_key.secret()
    );
    assert_eq!(
        via_solana.viewing_key.pubkey(),
        via_signing.viewing_key.pubkey()
    );
    assert_eq!(via_solana.signing_pubkey(), via_signing.signing_pubkey());
}

pub(crate) fn ed25519_keypair_derives_both_keys_from_one_signature() {
    let signing = SigningKey::from_ed25519_bytes(&[7u8; 32]);
    let sig = dalek_derivation_seed(&[7u8; 32]);
    let kp = ShieldedKeypair::from_keypair(signing).unwrap();
    assert_eq!(
        kp.viewing_key.pubkey(),
        expand_viewing_pubkey(&sig, b"TSPP/view_key/ed25519/x25519/v1")
    );
    assert_eq!(
        *kp.nullifier_key.secret(),
        expand_nullifier_secret(&sig, b"TSPP/nf_key/ed25519/v1")
    );
}

pub(crate) fn primitives_refuse_derivation_inputs() {
    let ed = SigningKey::from_ed25519_bytes(&[7u8; 32]);
    assert_eq!(
        ed.sign_message(ED25519_DERIVATION_MSG),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(
        ed.sign_message(&ed25519_derivation_message(&[7u8; 32])),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(
        ed.sign_message(b"TSPP/derive/pda/v1/x"),
        Err(KeypairError::DerivationInput)
    );
    assert!(ed.sign_message(b"benign message").is_ok());

    let vk = spr_keypair::ViewingKey::new();
    assert!(vk.ecdh(&ViewingKey::new().pubkey()).is_ok());
}

pub(crate) fn nullifier_deterministic(world: &mut KeypairWorld, key: String) {
    let a = ShieldedKeypair::from_keypair(world.sig_key(&key).clone()).unwrap();
    let b = ShieldedKeypair::from_keypair(world.sig_key(&key).clone()).unwrap();
    assert_eq!(*a.nullifier_key.secret(), *b.nullifier_key.secret());
    assert_eq!(
        a.nullifier_key.pubkey().unwrap(),
        b.nullifier_key.pubkey().unwrap()
    );
    assert_eq!(a.viewing_key.pubkey(), b.viewing_key.pubkey());
}

pub(crate) fn distinct_nullifier_secrets(world: &mut KeypairWorld, a: String, b: String) {
    let na = ShieldedKeypair::from_keypair(world.sig_key(&a).clone()).unwrap();
    let nb = ShieldedKeypair::from_keypair(world.sig_key(&b).clone()).unwrap();
    assert_ne!(*na.nullifier_key.secret(), *nb.nullifier_key.secret());
}

pub(crate) fn nullifier_binds_inputs() {
    let nk = NullifierKey::from_secret([9u8; BLINDING_LEN]);
    let h1 = [1u8; 32];
    let h2 = [2u8; 32];
    let b1 = [3u8; 32];
    let b2 = [4u8; 32];
    let base = nk.nullifier(&h1, &b1).unwrap();
    assert_eq!(base, nk.nullifier(&h1, &b1).unwrap());
    assert_ne!(base, nk.nullifier(&h2, &b1).unwrap());
    assert_ne!(base, nk.nullifier(&h1, &b2).unwrap());
    let other = NullifierKey::from_secret([8u8; BLINDING_LEN]);
    assert_ne!(base, other.nullifier(&h1, &b1).unwrap());
}

pub(crate) fn nullifier_pubkey_golden(fill: u8, expected: String) {
    let nk = NullifierKey::from_secret([fill; BLINDING_LEN]);
    assert_eq!(hex::encode(nk.pubkey().unwrap()), expected);
}
