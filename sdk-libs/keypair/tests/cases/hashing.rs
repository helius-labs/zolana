use sha2::{Digest, Sha256};
use zolana_keypair::{
    hash::{owner_hash, sha256, sha256_be},
    PublicKey, SigningKey,
};

use crate::KeypairWorld;

pub(crate) fn sha256_be_matches(_world: &mut KeypairWorld, input: String) {
    let got = sha256_be(input.as_bytes());
    let raw: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    assert_eq!(got[0], 0);
    assert_eq!(&got[1..], &raw[1..]);
}

pub(crate) fn sha256_full_matches(_world: &mut KeypairWorld, input: String) {
    let got = sha256(input.as_bytes());
    let raw: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    // Full digest, unlike sha256_be the most-significant byte is kept.
    assert_eq!(got, raw);
    assert_ne!(got[0], 0);
}

pub(crate) fn pubkey_field_golden(world: &mut KeypairWorld, name: String, expected: String) {
    let pf = world.sig_key(&name).pubkey().owner_proof_input_hash().unwrap();
    assert_eq!(hex::encode(pf), expected);
}

pub(crate) fn pubkey_field_stable(world: &mut KeypairWorld, name: String) {
    let pubkey = world.sig_key(&name).pubkey();
    assert_eq!(
        pubkey.owner_proof_input_hash().unwrap(),
        pubkey.owner_proof_input_hash().unwrap()
    );
}

pub(crate) fn owner_hash_stable(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    assert_eq!(kp.owner_hash().unwrap(), kp.owner_hash().unwrap());
}

pub(crate) fn owner_hash_binds_nullifier(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    let signing_pubkey = kp.signing_pubkey();
    let nullifier_pubkey = kp.nullifier_key.pubkey().unwrap();
    let base = owner_hash(&signing_pubkey, &nullifier_pubkey).unwrap();
    let mut other = nullifier_pubkey;
    other[31] ^= 1;
    assert_ne!(base, owner_hash(&signing_pubkey, &other).unwrap());
}

pub(crate) fn p256_ed25519_owner_hash_differ(_world: &mut KeypairWorld) {
    let nullifier_pubkey = [9u8; 32];
    let p256 = SigningKey::new().pubkey();
    let ed25519 = PublicKey::from_ed25519(&[7u8; 32]);
    assert_ne!(
        owner_hash(&p256, &nullifier_pubkey).unwrap(),
        owner_hash(&ed25519, &nullifier_pubkey).unwrap()
    );
}
