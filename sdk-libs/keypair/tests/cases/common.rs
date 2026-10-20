use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};

use crate::{scalar_bytes, KeypairWorld};

pub(crate) fn random_viewing_key(world: &mut KeypairWorld, name: String) {
    world.viewing.insert(name, ViewingKey::new());
}

pub(crate) fn viewing_key_from_scalar(world: &mut KeypairWorld, name: String, n: u8) {
    let vk = ViewingKey::from_bytes(&scalar_bytes(n));
    world.viewing.insert(name, vk);
}

pub(crate) fn random_signing_key(world: &mut KeypairWorld, name: String) {
    world.signing.insert(name, SigningKey::new_ed25519());
}

pub(crate) fn signing_key_from_seed(world: &mut KeypairWorld, name: String, n: u8) {
    let secret_key = SigningKey::from_ed25519_bytes(&scalar_bytes(n));
    world.signing.insert(name, secret_key);
}

pub(crate) fn random_shielded_keypair(world: &mut KeypairWorld, name: String) {
    world
        .shielded
        .insert(name, ShieldedKeypair::new_ed25519().unwrap());
}
