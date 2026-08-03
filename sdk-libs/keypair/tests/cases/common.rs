use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};

use crate::{scalar_bytes, KeypairWorld};

pub(crate) fn random_viewing_key(world: &mut KeypairWorld, name: String) {
    world.viewing.insert(name, ViewingKey::new());
}

pub(crate) fn viewing_key_from_scalar(world: &mut KeypairWorld, name: String, n: u8) {
    let vk = ViewingKey::from_bytes(&scalar_bytes(n)).unwrap();
    world.viewing.insert(name, vk);
}

pub(crate) fn random_p256_signing_key(world: &mut KeypairWorld, name: String) {
    world.signing.insert(name, SigningKey::new());
}

pub(crate) fn p256_signing_key_from_scalar(world: &mut KeypairWorld, name: String, n: u8) {
    let secret_key = SigningKey::from_bytes(&scalar_bytes(n)).unwrap();
    world.signing.insert(name, secret_key);
}

pub(crate) fn random_shielded_keypair(world: &mut KeypairWorld, name: String) {
    world.shielded.insert(name, ShieldedKeypair::new().unwrap());
}
