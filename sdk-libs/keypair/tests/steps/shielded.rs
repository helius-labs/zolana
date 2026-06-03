use cucumber::then;
use zolana_keypair::constants::{BLINDING_LEN, PUBLIC_KEY_LEN};
use zolana_keypair::{
    owner_hash, CompressedShieldedAddress, NullifierKey, ShieldedAddress, ShieldedKeypair,
    SigningKey, ViewingKey,
};

use crate::KeypairWorld;

#[then(expr = "the shielded address of {string} is consistent")]
fn address_consistent(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    let expected = ShieldedAddress {
        signing_pubkey: kp.signing_pubkey(),
        nullifier_pubkey: kp.nullifier_key.pubkey().unwrap(),
        viewing_pubkey: kp.viewing_pubkey(),
    };
    assert_eq!(kp.shielded_address().unwrap(), expected);

    let expected_owner_hash =
        owner_hash(&kp.signing_pubkey(), &kp.nullifier_key.pubkey().unwrap()).unwrap();
    assert_eq!(
        kp.compressed_address().unwrap(),
        CompressedShieldedAddress {
            owner_hash: expected_owner_hash,
            viewing_pubkey: kp.viewing_pubkey(),
        }
    );
}

#[then(expr = "a shielded keypair from {string} and {string} matches the standalone nullifier key")]
fn from_keys_derives_nullifier(world: &mut KeypairWorld, signing: String, viewing: String) {
    let expected = NullifierKey::from_signing_key(world.sig_key(&signing)).unwrap();
    let signing_clone =
        SigningKey::from_p256_bytes(&world.sig_key(&signing).secret_bytes()).unwrap();
    let viewing_clone = ViewingKey::from_bytes(&world.vk(&viewing).secret_bytes()).unwrap();
    let kp = ShieldedKeypair::from_keys(signing_clone, viewing_clone).unwrap();
    assert_eq!(kp.nullifier_key.secret(), expected.secret());
}

#[then(expr = "the facade of {string} signs and computes nullifiers consistently")]
fn facade_sign_nullifier(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    let msg = b"private_tx_hash";
    assert!(kp.signing_key.verify(msg, &kp.sign(msg)));
    let utxo_hash = [5u8; 32];
    let blinding = [6u8; BLINDING_LEN];
    assert_eq!(
        kp.nullifier(&utxo_hash, &blinding).unwrap(),
        kp.nullifier_key.nullifier(&utxo_hash, &blinding).unwrap()
    );
}

#[then(expr = "{string} and {string} derive matching shared view tags through the facade")]
fn facade_shared_tags(world: &mut KeypairWorld, sender: String, recipient: String) {
    let send = world
        .keypair(&sender)
        .get_send_shared_view_tag(&world.keypair(&recipient).viewing_pubkey(), 0)
        .unwrap();
    let recv = world
        .keypair(&recipient)
        .get_shared_view_tag(&world.keypair(&sender).viewing_pubkey(), 0)
        .unwrap();
    assert_eq!(send, recv);
}

#[then(expr = "a transfer from {string} to {string} round-trips through the facade")]
fn facade_transfer(world: &mut KeypairWorld, sender: String, recipient: String) {
    let first_nullifier = world
        .keypair(&sender)
        .nullifier(&[1u8; 32], &[2u8; BLINDING_LEN])
        .unwrap();
    let recipient_pubkey = world.keypair(&recipient).viewing_pubkey();
    let mut sender_bundle = vec![0u8; PUBLIC_KEY_LEN + 3 * 8 + BLINDING_LEN];
    sender_bundle.extend_from_slice(recipient_pubkey.as_bytes());
    let recipient_plaintext = b"owner || asset || amount || blinding".to_vec();
    let plaintexts: Vec<&[u8]> = vec![sender_bundle.as_slice(), recipient_plaintext.as_slice()];

    let enc = world
        .keypair(&sender)
        .encrypt_transaction(&first_nullifier, &plaintexts)
        .unwrap();
    let ciphertexts: Vec<&[u8]> = enc.ciphertexts.iter().map(|c| c.as_slice()).collect();
    let decrypted = world
        .keypair(&sender)
        .decrypt_transaction(&first_nullifier, &ciphertexts, enc.salt)
        .unwrap();
    assert_eq!(decrypted[1], recipient_plaintext);
}
