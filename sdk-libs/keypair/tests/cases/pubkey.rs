use spr_keypair::{constants::PUBLIC_KEY_LEN, Curve, KeypairError, PublicKey};

use crate::KeypairWorld;

pub(crate) fn tag_ed25519(world: &mut KeypairWorld, fill: u8, dst: String) {
    world
        .tagged
        .insert(dst, PublicKey::from_ed25519(&[fill; 32]));
}

pub(crate) fn scheme_is_ed25519(world: &mut KeypairWorld, name: String) {
    assert_eq!(world.tag(&name).curve().unwrap(), Curve::Ed25519);
}

pub(crate) fn last_byte_zero(world: &mut KeypairWorld, name: String) {
    assert_eq!(world.tag(&name).as_bytes()[PUBLIC_KEY_LEN - 1], 0);
}

pub(crate) fn parse_public_key_bad_prefix(world: &mut KeypairWorld, prefix: u8) {
    let mut bytes = [0u8; PUBLIC_KEY_LEN];
    bytes[0] = prefix;
    world.last_error = PublicKey::from_bytes(bytes).err();
}

pub(crate) fn parse_ed25519_nonzero_pad(world: &mut KeypairWorld) {
    let mut bytes = *PublicKey::from_ed25519(&[7u8; 32]).as_bytes();
    assert!(PublicKey::from_bytes(bytes).is_ok());
    bytes[PUBLIC_KEY_LEN - 1] = 1;
    world.last_error = PublicKey::from_bytes(bytes).err();
}

pub(crate) fn public_key_parse_fails(world: &mut KeypairWorld, expected: KeypairError) {
    assert_eq!(world.last_error, Some(expected));
}
