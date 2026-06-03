use cucumber::given;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};

use crate::{scalar_bytes, KeypairWorld};

#[given(expr = "a random viewing key {string}")]
fn random_viewing_key(world: &mut KeypairWorld, name: String) {
    world.viewing.insert(name, ViewingKey::new());
}

#[given(expr = "a viewing key {string} from scalar {int}")]
fn viewing_key_from_scalar(world: &mut KeypairWorld, name: String, n: u8) {
    let vk = ViewingKey::from_bytes(&scalar_bytes(n)).unwrap();
    world.viewing.insert(name, vk);
}

#[given(expr = "a random P256 signing key {string}")]
fn random_p256_signing_key(world: &mut KeypairWorld, name: String) {
    world.signing.insert(name, SigningKey::new_p256());
}

#[given(expr = "a random Ed25519 signing key {string}")]
fn random_ed25519_signing_key(world: &mut KeypairWorld, name: String) {
    world.signing.insert(name, SigningKey::new_ed25519());
}

#[given(expr = "a P256 signing key {string} from scalar {int}")]
fn p256_signing_key_from_scalar(world: &mut KeypairWorld, name: String, n: u8) {
    let secret_key = SigningKey::from_p256_bytes(&scalar_bytes(n)).unwrap();
    world.signing.insert(name, secret_key);
}

#[given(expr = "a random P256 shielded keypair {string}")]
fn random_shielded_keypair(world: &mut KeypairWorld, name: String) {
    world.shielded.insert(name, ShieldedKeypair::new().unwrap());
}

#[given(expr = "a random Ed25519 shielded keypair {string}")]
fn random_ed25519_shielded_keypair(world: &mut KeypairWorld, name: String) {
    world
        .shielded
        .insert(name, ShieldedKeypair::new_ed25519().unwrap());
}
