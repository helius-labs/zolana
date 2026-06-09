use cucumber::then;
use zolana_keypair::random_salt;

use crate::KeypairWorld;

#[then(expr = "{string} encrypts a slot to {string} and both can read it")]
fn slot_round_trips(world: &mut KeypairWorld, sender: String, recipient: String) {
    let nf = [7u8; 32];
    let tx = world.vk(&sender).get_transaction_viewing_key(&nf).unwrap();
    let salt = random_salt();
    let payload = b"recipient payload".to_vec();
    let recipient_pk = world.vk(&recipient).pubkey();
    let ct = tx.encrypt_slot(&recipient_pk, &payload, salt, 1).unwrap();

    let by_recipient = world
        .vk(&recipient)
        .decrypt_utxo(&ct, &tx.pubkey(), salt, 1)
        .unwrap();
    assert_eq!(by_recipient, payload);

    let by_sender = tx
        .decrypt_slot_ephemeral(&recipient_pk, &ct, salt, 1)
        .unwrap();
    assert_eq!(by_sender, payload);
}

#[then(
    expr = "{string} encrypts the same payload to {string} in two slots with distinct ciphertexts"
)]
fn distinct_slots(world: &mut KeypairWorld, sender: String, recipient: String) {
    let nf = [9u8; 32];
    let tx = world.vk(&sender).get_transaction_viewing_key(&nf).unwrap();
    let salt = random_salt();
    let recipient_pk = world.vk(&recipient).pubkey();
    let c0 = tx
        .encrypt_slot(&recipient_pk, b"identical", salt, 0)
        .unwrap();
    let c1 = tx
        .encrypt_slot(&recipient_pk, b"identical", salt, 1)
        .unwrap();
    assert_ne!(c0, c1);
}

#[then(expr = "{string} cannot decrypt a slot from {string} to {string}")]
fn stranger_cannot(world: &mut KeypairWorld, stranger: String, sender: String, recipient: String) {
    let nf = [7u8; 32];
    let tx = world.vk(&sender).get_transaction_viewing_key(&nf).unwrap();
    let salt = random_salt();
    let recipient_pk = world.vk(&recipient).pubkey();
    let ct = tx.encrypt_slot(&recipient_pk, b"payload", salt, 1).unwrap();
    assert!(world
        .vk(&stranger)
        .decrypt_utxo(&ct, &tx.pubkey(), salt, 1)
        .is_err());
}

#[then(expr = "a tampered slot from {string} to {string} is rejected")]
fn tampered_rejected(world: &mut KeypairWorld, sender: String, recipient: String) {
    let nf = [7u8; 32];
    let tx = world.vk(&sender).get_transaction_viewing_key(&nf).unwrap();
    let salt = random_salt();
    let recipient_pk = world.vk(&recipient).pubkey();
    let mut ct = tx.encrypt_slot(&recipient_pk, b"payload", salt, 1).unwrap();
    ct[0] ^= 0xff;
    assert!(world
        .vk(&recipient)
        .decrypt_utxo(&ct, &tx.pubkey(), salt, 1)
        .is_err());
}

#[then(expr = "{string} decrypts the golden ciphertext from {string}")]
fn golden_decrypts(world: &mut KeypairWorld, recipient: String, ephemeral: String) {
    let ciphertext =
        hex::decode("0dedf6fb1c2c64f57a31740887dbc87d6502ea3e4791598dc543358cd9").unwrap();
    let plaintext = world
        .vk(&recipient)
        .decrypt_utxo(&ciphertext, &world.vk(&ephemeral).pubkey(), [0u8; 16], 0)
        .unwrap();
    assert_eq!(plaintext, b"deterministic");
}
