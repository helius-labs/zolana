use cucumber::{given, then, when};
use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, PUBLIC_KEY_LEN},
    P256Pubkey, PublicKey, SignatureType, ViewingKey,
};

use crate::KeypairWorld;

#[given(expr = "a random P256 public key {string}")]
fn random_p256_public_key(world: &mut KeypairWorld, name: String) {
    world.pubkeys.insert(name, ViewingKey::new().pubkey());
}

#[when(expr = "I parse the bytes of P256 key {string}")]
fn parse_p256_bytes(world: &mut KeypairWorld, name: String) {
    let bytes = *world.pubkey(&name).as_bytes();
    match P256Pubkey::from_bytes(bytes) {
        Ok(parsed) => {
            world.last_error = false;
            world.pubkeys.insert("__parsed".to_string(), parsed);
        }
        Err(_) => world.last_error = true,
    }
}

#[when(expr = "I parse a P256 key whose first byte is {int}")]
fn parse_p256_bad_prefix(world: &mut KeypairWorld, prefix: u8) {
    let mut bytes = [0u8; P256_PUBKEY_LEN];
    bytes[0] = prefix;
    world.last_error = P256Pubkey::from_bytes(bytes).is_err();
}

#[then("the parse succeeds")]
fn parse_succeeds(world: &mut KeypairWorld) {
    assert!(!world.last_error);
}

#[then("the parse fails")]
fn parse_fails(world: &mut KeypairWorld) {
    assert!(world.last_error);
}

#[then(expr = "the parsed P256 key equals {string}")]
fn parsed_equals(world: &mut KeypairWorld, name: String) {
    assert_eq!(world.pubkey("__parsed"), world.pubkey(&name));
}

#[when(expr = "I tag P256 key {string} as {string}")]
fn tag_p256(world: &mut KeypairWorld, src: String, dst: String) {
    let tagged = PublicKey::from_p256(&world.pubkey(&src));
    world.tagged.insert(dst, tagged);
}

#[when(expr = "I tag an Ed25519 key filled with {int} as {string}")]
fn tag_ed25519(world: &mut KeypairWorld, fill: u8, dst: String) {
    world
        .tagged
        .insert(dst, PublicKey::from_ed25519(&[fill; 32]));
}

#[then(expr = "public key {string} has scheme P256")]
fn scheme_is_p256(world: &mut KeypairWorld, name: String) {
    assert_eq!(
        world.tag(&name).signature_type().unwrap(),
        SignatureType::P256
    );
}

#[then(expr = "public key {string} has scheme Ed25519")]
fn scheme_is_ed25519(world: &mut KeypairWorld, name: String) {
    assert_eq!(
        world.tag(&name).signature_type().unwrap(),
        SignatureType::Ed25519
    );
}

#[then(expr = "public key {string} reads back as P256 key {string}")]
fn reads_back_as_p256(world: &mut KeypairWorld, tagged: String, expected: String) {
    assert_eq!(
        world.tag(&tagged).as_p256().unwrap(),
        world.pubkey(&expected)
    );
}

#[then(expr = "reading public key {string} as Ed25519 fails")]
fn read_as_ed25519_fails(world: &mut KeypairWorld, name: String) {
    assert!(world.tag(&name).as_ed25519().is_err());
}

#[then(expr = "reading public key {string} as P256 fails")]
fn read_as_p256_fails(world: &mut KeypairWorld, name: String) {
    assert!(world.tag(&name).as_p256().is_err());
}

#[then(expr = "the last byte of public key {string} is zero")]
fn last_byte_zero(world: &mut KeypairWorld, name: String) {
    assert_eq!(world.tag(&name).as_bytes()[PUBLIC_KEY_LEN - 1], 0);
}

#[when(expr = "I parse a public key whose first byte is {int}")]
fn parse_public_key_bad_prefix(world: &mut KeypairWorld, prefix: u8) {
    let mut bytes = [0u8; PUBLIC_KEY_LEN];
    bytes[0] = prefix;
    world.last_error = PublicKey::from_bytes(bytes).is_err();
}

#[when(expr = "I parse an Ed25519 public key with a nonzero pad byte")]
fn parse_ed25519_nonzero_pad(world: &mut KeypairWorld) {
    let mut bytes = *PublicKey::from_ed25519(&[7u8; 32]).as_bytes();
    assert!(PublicKey::from_bytes(bytes).is_ok());
    bytes[PUBLIC_KEY_LEN - 1] = 1;
    world.last_error = PublicKey::from_bytes(bytes).is_err();
}

#[then("the public key parse fails")]
fn public_key_parse_fails(world: &mut KeypairWorld) {
    assert!(world.last_error);
}
