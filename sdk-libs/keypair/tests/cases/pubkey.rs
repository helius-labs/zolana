use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, PUBLIC_KEY_LEN},
    Curve, KeypairError, P256Pubkey, PublicKey, ViewingKey,
};

use crate::KeypairWorld;

pub(crate) fn random_p256_public_key(world: &mut KeypairWorld, name: String) {
    world.pubkeys.insert(name, ViewingKey::new().pubkey());
}

pub(crate) fn parse_p256_bytes(world: &mut KeypairWorld, name: String) {
    let bytes = *world.pubkey(&name).as_bytes();
    match P256Pubkey::from_bytes(bytes) {
        Ok(parsed) => {
            world.last_error = None;
            world.parsed_pubkey = Some(parsed);
        }
        Err(error) => world.last_error = Some(error),
    }
}

pub(crate) fn parse_p256_bad_prefix(world: &mut KeypairWorld, prefix: u8) {
    let mut bytes = [0u8; P256_PUBKEY_LEN];
    bytes[0] = prefix;
    world.last_error = P256Pubkey::from_bytes(bytes).err();
}

pub(crate) fn parse_succeeds(world: &mut KeypairWorld) {
    assert_eq!(world.last_error, None);
}

pub(crate) fn parse_fails(world: &mut KeypairWorld) {
    assert_eq!(world.last_error, Some(KeypairError::InvalidPublicKey));
}

pub(crate) fn parsed_equals(world: &mut KeypairWorld, name: String) {
    assert_eq!(
        world.parsed_pubkey.expect("parsed public key"),
        world.pubkey(&name)
    );
}

pub(crate) fn tag_p256(world: &mut KeypairWorld, src: String, dst: String) {
    let tagged = PublicKey::from_p256(&world.pubkey(&src));
    world.tagged.insert(dst, tagged);
}

pub(crate) fn tag_ed25519(world: &mut KeypairWorld, fill: u8, dst: String) {
    world
        .tagged
        .insert(dst, PublicKey::from_ed25519(&[fill; 32]));
}

pub(crate) fn scheme_is_p256(world: &mut KeypairWorld, name: String) {
    assert_eq!(world.tag(&name).curve().unwrap(), Curve::P256);
}

pub(crate) fn scheme_is_ed25519(world: &mut KeypairWorld, name: String) {
    assert_eq!(world.tag(&name).curve().unwrap(), Curve::Ed25519);
}

pub(crate) fn reads_back_as_p256(world: &mut KeypairWorld, tagged: String, expected: String) {
    assert_eq!(
        world.tag(&tagged).as_p256().unwrap(),
        world.pubkey(&expected)
    );
}

pub(crate) fn read_as_ed25519_fails(world: &mut KeypairWorld, name: String) {
    assert!(world.tag(&name).as_ed25519().is_err());
}

pub(crate) fn read_as_p256_fails(world: &mut KeypairWorld, name: String) {
    assert!(world.tag(&name).as_p256().is_err());
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
